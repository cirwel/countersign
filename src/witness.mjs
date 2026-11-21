// Standalone x402-paid Countersign witness HTTP service with Protocol 10 fee sponsorship for CIS-8004.setMetadata.
import crypto from 'node:crypto';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { AccountAddress } from '@concordium/web-sdk';
import {
    ANCHOR_KEY,
    TX_RE,
    WITNESS_KEY,
    assertTestnet,
    chainIsUnbroken,
    client,
    coverageGrows,
    extractWitnessState,
    getTransactionState,
    isSameAccount,
    loadAnchorsFromHistory,
    loadSignerFromFile,
    readAgentOf,
    readMetadataText,
    readRegisterData,
    readRegistryHistory,
    sendRegisterData,
    validateAndSponsorSetMetadata,
    withRpcRetry,
    witnessMatchesOnChain,
} from './chain.mjs';
import { encodeBadge, fetchAgentCard, verifyAgentCardBytes } from './cis8004.mjs';
import { REGISTRY, TESTNET_GENESIS } from './registry.mjs';
import { decodeAnchor, encodeAnchor } from './trail.mjs';
import {
    CONCORDIUM_TESTNET_CAIP2,
    HEADER_PAYMENT_REQUIRED,
    HEADER_PAYMENT_RESPONSE,
    HEADER_PAYMENT_SIGNATURE,
    PaymentLedger,
    computePaymentMemo,
    createConcordiumTransferVerifier,
    createFacilitatorVerifier,
    createPaymentRequirements,
    encodeX402Header,
} from './x402.mjs';

const U64_MAX = (1n << 64n) - 1n;
const TOKEN_ID_RE = /^(?:0|[1-9][0-9]*)$/;
const utf8Fatal = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function isPlainObject(v) {
    return v !== null && typeof v === 'object' && !Array.isArray(v);
}

class HttpError extends Error {
    constructor(statusCode, message, extraHeaders = null, bodyExtra = null) {
        super(message);
        this.statusCode = statusCode;
        this.extraHeaders = extraHeaders;
        this.bodyExtra = bodyExtra;
    }
}

function sendJson(res, statusCode, body, extraHeaders = {}) {
    if (res.headersSent || res.writableEnded) return;
    const payload = JSON.stringify(body);
    res.writeHead(statusCode, {
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'no-store',
        ...extraHeaders,
    });
    res.end(payload);
}

async function readJsonBody(req, res, maxBodyBytes) {
    const rawCt = String(req.headers['content-type'] ?? '');
    const mime = rawCt.split(';')[0].trim().toLowerCase();
    if (mime !== 'application/json') {
        sendJson(res, 415, { error: 'Content-Type must be application/json' });
        return null;
    }
    const cl = req.headers['content-length'];
    if (typeof cl === 'string' && /^\d+$/.test(cl) && Number(cl) > maxBodyBytes) {
        sendJson(res, 413, { error: `request body exceeds ${maxBodyBytes} byte limit` });
        req.destroy();
        return null;
    }

    return new Promise((resolve) => {
        const chunks = [];
        let total = 0;
        let finished = false;
        const finish = (val) => {
            if (finished) return;
            finished = true;
            resolve(val);
        };
        req.on('data', (chunk) => {
            if (finished) return;
            const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
            total += b.byteLength;
            if (total > maxBodyBytes) {
                sendJson(res, 413, { error: `request body exceeds ${maxBodyBytes} byte limit` });
                req.destroy();
                finish(null);
                return;
            }
            chunks.push(b);
        });
        req.on('end', () => {
            if (finished) return;
            let parsed;
            try {
                const text = utf8Fatal.decode(Buffer.concat(chunks, total));
                parsed = JSON.parse(text);
            } catch (err) {
                sendJson(res, 400, { error: `invalid JSON body: ${err.message}` });
                finish(null);
                return;
            }
            if (!isPlainObject(parsed)) {
                sendJson(res, 400, { error: 'JSON body must be an object' });
                finish(null);
                return;
            }
            finish(parsed);
        });
        req.on('error', (err) => {
            if (!finished && !res.headersSent) {
                sendJson(res, 400, { error: `request stream error: ${err.message}` });
            }
            finish(null);
        });
        req.on('aborted', () => finish(null));
    });
}

function validateAnchorRequestBody(body) {
    const allowed = new Set(['tokenId', 'toSeq', 'commitment', 'prevAnchorTx']);
    for (const k of Object.keys(body)) {
        if (!allowed.has(k)) throw new HttpError(400, `unexpected field in request body: ${k}`);
    }
    const { tokenId, toSeq, commitment, prevAnchorTx } = body;
    if (typeof tokenId !== 'string' || !TOKEN_ID_RE.test(tokenId) || BigInt(tokenId) > U64_MAX) {
        throw new HttpError(400, `invalid tokenId: ${tokenId}`);
    }
    if (!Number.isSafeInteger(toSeq) || toSeq <= 0) {
        throw new HttpError(400, `toSeq must be a positive safe integer, got ${toSeq}`);
    }
    if (typeof commitment !== 'string' || !TX_RE.test(commitment)) {
        throw new HttpError(400, 'commitment must be 64 lowercase hex characters');
    }
    if (prevAnchorTx !== null && (typeof prevAnchorTx !== 'string' || !TX_RE.test(prevAnchorTx))) {
        throw new HttpError(400, 'prevAnchorTx must be null or 64 lowercase hex characters');
    }
    return { tokenId, toSeq, commitment, prevAnchorTx };
}

function validateSponsorRequestBody(body) {
    const allowed = new Set(['tokenId', 'anchorTxHash', 'transactionJson']);
    for (const k of Object.keys(body)) {
        if (!allowed.has(k)) throw new HttpError(400, `unexpected field in request body: ${k}`);
    }
    const { tokenId, anchorTxHash, transactionJson } = body;
    if (typeof tokenId !== 'string' || !TOKEN_ID_RE.test(tokenId) || BigInt(tokenId) > U64_MAX) {
        throw new HttpError(400, `invalid tokenId: ${tokenId}`);
    }
    if (typeof anchorTxHash !== 'string' || !TX_RE.test(anchorTxHash)) {
        throw new HttpError(400, 'anchorTxHash must be 64 lowercase hex characters');
    }
    if (typeof transactionJson !== 'string' || transactionJson.trim().length === 0) {
        throw new HttpError(400, 'transactionJson must be a non-empty string');
    }
    return { tokenId, anchorTxHash, transactionJson };
}

/**
 * Constructs and configures the Countersign witness `node:http` server without opening the listening socket yet.
 * Enforces testnet genesis check and loads the separate witness keyfile and PaymentLedger before returning.
 */
export async function createWitnessServer(opts = {}) {
    const {
        host = '127.0.0.1',
        port = 8787,
        priceMicroCcd = '1000000',
        payTo,
        sponsorPointer = true,
        allowPrivateCard = false,
        allowPrivateFacilitator = false,
        ledgerPath,
        ledger: injectedLedger,
        witnessKeyfile,
        signer: injectedSigner,
        nodeClient,
        verifier: injectedVerifier,
        facilitatorUrl,
        fetchCard = fetchAgentCard,
        maxBodyBytes = 65536,
        requestTimeoutMs = 60000,
        maxOwnerTxs = 2000,
        log = console.log,
    } = opts;

    const signer =
        injectedSigner ??
        loadSignerFromFile(witnessKeyfile, { envVar: 'COUNTERSIGN_WITNESS_KEYFILE' });
    if (!signer || typeof signer.address !== 'string' || !signer.sender || !signer.signer) {
        throw new Error('valid witness signer is required');
    }
    if (AccountAddress.fromBase58(signer.address).address !== signer.address) {
        throw new Error(`witness signer address ${signer.address} is not in canonical Base58Check form`);
    }

    const resolvedPayTo = payTo ?? signer.address;
    if (typeof resolvedPayTo !== 'string' || AccountAddress.fromBase58(resolvedPayTo).address !== resolvedPayTo) {
        throw new Error(`payTo ${resolvedPayTo} must be a canonical Base58Check account address`);
    }

    const priceBigInt = BigInt(priceMicroCcd);
    if (priceBigInt < 0n) {
        throw new Error(`priceMicroCcd must be non-negative, got ${priceMicroCcd}`);
    }
    const priceStr = priceBigInt.toString();

    if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes <= 0) {
        throw new Error(`invalid maxBodyBytes: ${maxBodyBytes}`);
    }
    if (!Number.isSafeInteger(requestTimeoutMs) || requestTimeoutMs <= 0) {
        throw new Error(`invalid requestTimeoutMs: ${requestTimeoutMs}`);
    }

    const c = nodeClient ?? (await client());
    await assertTestnet(c);

    const resolvedLedgerPath =
        ledgerPath ?? path.join(os.homedir(), '.config', 'countersign', 'witness-ledger.json');
    const ledger = injectedLedger ?? new PaymentLedger(resolvedLedgerPath);

    let verifier = injectedVerifier;
    if (!verifier) {
        if (facilitatorUrl) {
            verifier = createFacilitatorVerifier({
                facilitatorUrl,
                allowPrivate: Boolean(allowPrivateFacilitator),
                maxBytes: maxBodyBytes,
            });
        } else {
            verifier = createConcordiumTransferVerifier({
                nodeClient: c,
                payTo: resolvedPayTo,
                minAmountMicroCcd: priceStr,
            });
        }
    }

    const tokenQueues = new Map();
    const withTokenLock = async (tokenId, fn) => {
        const prev = tokenQueues.get(tokenId) ?? Promise.resolve();
        let release;
        const next = new Promise((r) => {
            release = r;
        });
        const tail = prev.then(() => next);
        tokenQueues.set(tokenId, tail);
        await prev;
        try {
            return await fn();
        } finally {
            release();
            if (tokenQueues.get(tokenId) === tail) {
                tokenQueues.delete(tokenId);
            }
        }
    };

    const loadVerifiedTokenState = async (tokenId, { checkCard = false } = {}) => {
        const cs = await withRpcRetry(() => c.getConsensusStatus());
        const tipBlockHash = cs.lastFinalizedBlock;
        const tipBlockHeight = cs.lastFinalizedBlockHeight;

        const agent = await readAgentOf(tokenId, { blockHash: tipBlockHash, nodeClient: c });
        if (!agent) {
            throw new HttpError(404, `registry token ${tokenId} is not registered`);
        }
        if (agent.status !== 'Active') {
            throw new HttpError(403, `registry token ${tokenId} status is ${agent.status}`);
        }
        if (isSameAccount(signer.address, agent.ownerAccount)) {
            throw new HttpError(403, 'witness account cannot witness its own registry entry');
        }

        if (checkCard) {
            if (!agent.metadataHashHex || !agent.agentUri) {
                throw new HttpError(403, `registry token ${tokenId} missing on-chain agentUri or metadataHashHex`);
            }
            let cardBytes;
            try {
                cardBytes = await fetchCard(agent.agentUri, { allowPrivate: Boolean(allowPrivateCard) });
            } catch (err) {
                throw new HttpError(502, `failed to fetch Agent Card from ${agent.agentUri}: ${err.message}`);
            }
            try {
                verifyAgentCardBytes(cardBytes, {
                    badge: encodeBadge(tokenId),
                    ownerAccount: agent.ownerAccount,
                    metadataHashHex: agent.metadataHashHex,
                    registry: REGISTRY,
                    genesisPrefix: TESTNET_GENESIS.slice(0, 32),
                });
            } catch (err) {
                throw new HttpError(403, `Agent Card verification failed: ${err.message}`);
            }
        }

        const onChainWitness = await readMetadataText(tokenId, WITNESS_KEY, { blockHash: tipBlockHash, nodeClient: c });
        const currentAnchor = await readMetadataText(tokenId, ANCHOR_KEY, { blockHash: tipBlockHash, nodeClient: c });
        if (currentAnchor !== null && !TX_RE.test(currentAnchor)) {
            throw new HttpError(409, `on-chain ${ANCHOR_KEY} is not a transaction hash`);
        }

        let history;
        let witnessState;
        try {
            history = await readRegistryHistory(tokenId, {
                tipBlockHash,
                tipBlockHeight,
                agent,
                hintAnchorTxHashes: currentAnchor ? [currentAnchor] : [],
                maxOwnerTxs,
                nodeClient: c,
            });
            witnessState = extractWitnessState(history);
        } catch (err) {
            throw new HttpError(403, err.message);
        }

        if (!witnessMatchesOnChain(witnessState, onChainWitness)) {
            throw new HttpError(
                403,
                `on-chain ${WITNESS_KEY} (${onChainWitness ?? 'null'}) disagrees with reconstructed MetadataSet history (${witnessState.currentWitness ?? 'null'})`,
            );
        }
        if (witnessState.currentWitness === null || !isSameAccount(witnessState.currentWitness, signer.address)) {
            throw new HttpError(
                403,
                `token ${tokenId} active witness (${witnessState.currentWitness ?? 'none'}) does not match witness ${signer.address}`,
            );
        }

        let existing;
        try {
            existing = await loadAnchorsFromHistory(history, c, tipBlockHeight);
        } catch (err) {
            throw new HttpError(409, err.message);
        }
        if (!chainIsUnbroken(existing) || !coverageGrows(existing)) {
            throw new HttpError(409, 'existing anchor chain in history is broken or non-monotonic');
        }
        for (const a of existing) {
            if (a.tokenId !== tokenId || !isSameAccount(a.sender, a.authorizedWitness ?? agent.ownerAccount)) {
                throw new HttpError(403, `existing anchor ${a.txHash} failed authorized signer check`);
            }
        }
        const prev = existing.at(-1) ?? null;
        if (currentAnchor !== (prev?.txHash ?? null)) {
            throw new HttpError(409, 'on-chain countersign.anchor does not match latest MetadataSet history pointer');
        }

        return { tipBlockHash, tipBlockHeight, agent, onChainWitness, currentAnchor, history, existing, prev };
    };

    const handleAnchor = async (req, res, reqUrl) => {
        const rawBody = await readJsonBody(req, res, maxBodyBytes);
        if (!rawBody) return;
        const { tokenId, toSeq, commitment, prevAnchorTx } = validateAnchorRequestBody(rawBody);

        await withTokenLock(tokenId, async () => {
            const { currentAnchor, prev } = await loadVerifiedTokenState(tokenId, { checkCard: true });
            if (prevAnchorTx !== (prev?.txHash ?? null) || currentAnchor !== (prev?.txHash ?? null)) {
                throw new HttpError(
                    409,
                    `prevAnchorTx ${prevAnchorTx ?? 'null'} disagrees with current on-chain anchor ${prev?.txHash ?? 'null'}`,
                );
            }
            if (toSeq <= (prev?.toSeq ?? 0)) {
                throw new HttpError(409, `toSeq ${toSeq} must exceed latest anchored seq ${prev?.toSeq ?? 0}`);
            }

            const expectedMemoHex = computePaymentMemo({ tokenId, toSeq, commitment, prevAnchorTx });
            const resource = `http://${req.headers.host ?? `${host}:${port}`}${reqUrl.pathname}`;
            const paymentRequired = createPaymentRequirements({
                payTo: resolvedPayTo,
                amountMicroCcd: priceStr,
                resource,
                memoHex: expectedMemoHex,
                tokenId,
                toSeq,
                commitment,
                prevAnchorTx,
                witnessAccount: signer.address,
                sponsorPointer: Boolean(sponsorPointer),
            });
            const encodedPr = encodeX402Header(paymentRequired);

            const rawPaymentSig = req.headers[HEADER_PAYMENT_SIGNATURE];
            if (rawPaymentSig === undefined) {
                sendJson(res, 402, paymentRequired, { [HEADER_PAYMENT_REQUIRED]: encodedPr });
                return;
            }
            if (Array.isArray(rawPaymentSig) || typeof rawPaymentSig !== 'string') {
                sendJson(
                    res,
                    402,
                    { error: 'invalid PAYMENT-SIGNATURE header', ...paymentRequired },
                    { [HEADER_PAYMENT_REQUIRED]: encodedPr },
                );
                return;
            }

            let paymentResult;
            try {
                paymentResult = await verifier.verify({
                    header: rawPaymentSig,
                    requirements: paymentRequired.accepts[0],
                    expectedMemoHex,
                });
            } catch (err) {
                sendJson(
                    res,
                    402,
                    { error: `payment verification failed: ${err.message}`, ...paymentRequired },
                    { [HEADER_PAYMENT_REQUIRED]: encodedPr },
                );
                return;
            }

            const claim = ledger.claim(paymentResult.paymentId, {
                tokenId,
                toSeq,
                commitment,
                prevAnchorTx,
            });
            if (claim.action === 'return_cached') {
                const cached = claim.entry.result;
                const respHdr = encodeX402Header({
                    success: true,
                    transaction: cached.txHash,
                    network: CONCORDIUM_TESTNET_CAIP2,
                    payer: paymentResult.payer ?? null,
                    cached: true,
                });
                sendJson(
                    res,
                    200,
                    { ...cached, tokenId, toSeq, commitment, prevAnchorTx },
                    { [HEADER_PAYMENT_RESPONSE]: respHdr },
                );
                return;
            }

            let broadcastStarted = false;
            try {
                const latestAnchor = await readMetadataText(tokenId, ANCHOR_KEY, { nodeClient: c });
                if (latestAnchor !== (prev?.txHash ?? null)) {
                    throw new HttpError(409, 'countersign.anchor moved concurrently; refusing to anchor');
                }
                const data = encodeAnchor({
                    tokenId,
                    toSeq,
                    commitment: Buffer.from(commitment, 'hex'),
                    prevAnchorTx,
                });
                const anchorRes = await sendRegisterData(data, signer, c, {
                    onSigned: ({ txHash, expiryEpochSeconds }) => {
                        broadcastStarted = true;
                        ledger.markBroadcast(paymentResult.paymentId, { txHash, expiryEpochSeconds });
                    },
                });
                const rd = await readRegisterData(anchorRes.hash, c);
                const result = {
                    txHash: anchorRes.hash,
                    witnessAccount: signer.address,
                    blockTime: rd.blockTime,
                    blockHeight: rd.blockHeight,
                    sponsorAvailable: Boolean(sponsorPointer),
                };
                ledger.commit(paymentResult.paymentId, result);
                const respHdr = encodeX402Header({
                    success: true,
                    transaction: result.txHash,
                    network: CONCORDIUM_TESTNET_CAIP2,
                    payer: paymentResult.payer ?? null,
                });
                sendJson(
                    res,
                    200,
                    { ...result, tokenId, toSeq, commitment, prevAnchorTx },
                    { [HEADER_PAYMENT_RESPONSE]: respHdr },
                );
            } catch (err) {
                if (!broadcastStarted) {
                    ledger.releasePreBroadcast(paymentResult.paymentId);
                }
                throw err;
            }
        });
    };

    const handleSponsorPointer = async (req, res) => {
        if (!sponsorPointer) {
            sendJson(res, 403, { error: 'sponsorPointer is disabled on this witness' });
            return;
        }
        const rawBody = await readJsonBody(req, res, maxBodyBytes);
        if (!rawBody) return;
        const { tokenId, anchorTxHash, transactionJson } = validateSponsorRequestBody(rawBody);
        const requestHash = crypto.createHash('sha256').update(transactionJson, 'utf8').digest('hex');

        await withTokenLock(tokenId, async () => {
            const { tipBlockHash, agent, prev } = await loadVerifiedTokenState(tokenId, { checkCard: false });

            const existingSponsor = ledger.getSponsor(tokenId, anchorTxHash);
            if (existingSponsor?.status === 'committed') {
                if (existingSponsor.requestHash && existingSponsor.requestHash !== requestHash) {
                    throw new HttpError(409, `sponsor pointer ${tokenId}:${anchorTxHash} was already committed with a different payload`);
                }
                sendJson(res, 200, {
                    metadataTxHash: existingSponsor.metadataTxHash,
                    anchorTxHash,
                    witnessAccount: signer.address,
                });
                return;
            }
            if (existingSponsor?.status === 'broadcasted') {
                const txState = await getTransactionState(existingSponsor.metadataTxHash, c);
                if (
                    txState.state === 'finalized' &&
                    txState.summary?.transactionType !== 'failed' &&
                    !txState.summary?.rejectReason
                ) {
                    const committed = {
                        metadataTxHash: existingSponsor.metadataTxHash,
                        anchorTxHash,
                        witnessAccount: signer.address,
                    };
                    ledger.commitSponsor(tokenId, anchorTxHash, committed);
                    sendJson(res, 200, committed);
                    return;
                }
                const tipBlock = await withRpcRetry(() => c.getBlockInfo(tipBlockHash));
                const chainEpochSec = Math.floor(tipBlock.blockSlotTime.getTime() / 1000);
                const failed =
                    txState.state === 'finalized' &&
                    (txState.summary?.transactionType === 'failed' || Boolean(txState.summary?.rejectReason));
                const expired =
                    txState.state === 'absent' &&
                    existingSponsor.expiryEpochSeconds !== null &&
                    chainEpochSec > existingSponsor.expiryEpochSeconds;
                if (!failed && !expired) {
                    throw new HttpError(409, `sponsored setMetadata ${existingSponsor.metadataTxHash} is already in-flight`);
                }
                ledger.releaseExpiredOrFailedSponsor(tokenId, anchorTxHash);
            }

            let rd;
            let decoded;
            try {
                rd = await readRegisterData(anchorTxHash, c);
                decoded = decodeAnchor(rd.data);
            } catch (err) {
                throw new HttpError(400, `anchorTxHash ${anchorTxHash} is not a valid finalized registerData anchor: ${err.message}`);
            }
            if (!isSameAccount(rd.sender, signer.address)) {
                throw new HttpError(403, `anchor ${anchorTxHash} was sent by ${rd.sender}, not witness ${signer.address}`);
            }
            if (decoded.tokenId !== tokenId) {
                throw new HttpError(400, `anchor ${anchorTxHash} tokenId ${decoded.tokenId} does not match ${tokenId}`);
            }
            if (decoded.prevAnchorTx !== (prev?.txHash ?? null)) {
                throw new HttpError(
                    409,
                    `anchor ${anchorTxHash} prevAnchorTx ${decoded.prevAnchorTx ?? 'null'} disagrees with current pointer ${prev?.txHash ?? 'null'}`,
                );
            }
            if (decoded.toSeq <= (prev?.toSeq ?? 0)) {
                throw new HttpError(409, `anchor ${anchorTxHash} toSeq ${decoded.toSeq} does not advance past ${prev?.toSeq ?? 0}`);
            }

            ledger.claimSponsor(tokenId, anchorTxHash, { requestHash });
            let broadcastStarted = false;
            try {
                const resTx = await validateAndSponsorSetMetadata({
                    transactionJson,
                    expectedOwner: agent.ownerAccount,
                    expectedSponsor: signer.address,
                    expectedTokenId: tokenId,
                    expectedKey: ANCHOR_KEY,
                    expectedValueUtf8: anchorTxHash,
                    sponsorSigner: signer,
                    nodeClient: c,
                    pollOpts: {
                        onSigned: ({ txHash, expiryEpochSeconds }) => {
                            broadcastStarted = true;
                            ledger.markSponsorBroadcast(tokenId, anchorTxHash, {
                                metadataTxHash: txHash,
                                expiryEpochSeconds,
                            });
                        },
                    },
                });
                const out = {
                    metadataTxHash: resTx.txHash,
                    anchorTxHash,
                    witnessAccount: signer.address,
                };
                ledger.commitSponsor(tokenId, anchorTxHash, out);
                sendJson(res, 200, out);
            } catch (err) {
                if (!broadcastStarted) {
                    ledger.releasePreBroadcastSponsor(tokenId, anchorTxHash);
                    throw new HttpError(err.statusCode ?? 400, err.message);
                }
                throw err;
            }
        });
    };

    const server = http.createServer(async (req, res) => {
        try {
            const reqUrl = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
            if (req.method === 'GET' && reqUrl.pathname === '/health') {
                sendJson(res, 200, {
                    ok: true,
                    network: 'testnet',
                    genesis: TESTNET_GENESIS,
                    registry: { ...REGISTRY },
                    witnessAccount: signer.address,
                    payTo: resolvedPayTo,
                    priceMicroCcd: priceStr,
                    paymentScheme: 'exact',
                    sponsorPointer: Boolean(sponsorPointer),
                });
                return;
            }
            if (reqUrl.pathname === '/v1/anchor') {
                if (req.method !== 'POST') {
                    sendJson(res, 405, { error: 'method not allowed' });
                    return;
                }
                await handleAnchor(req, res, reqUrl);
                return;
            }
            if (reqUrl.pathname === '/v1/sponsor-pointer') {
                if (req.method !== 'POST') {
                    sendJson(res, 405, { error: 'method not allowed' });
                    return;
                }
                await handleSponsorPointer(req, res);
                return;
            }
            sendJson(res, 404, { error: 'not found' });
        } catch (err) {
            const status = Number.isInteger(err?.statusCode) ? err.statusCode : 500;
            if (status >= 500) {
                log?.(`witness error: ${err.message}`);
            }
            sendJson(
                res,
                status,
                { error: err.message, ...(err.bodyExtra ?? {}) },
                err.extraHeaders ?? {},
            );
        }
    });
    server.requestTimeout = requestTimeoutMs;

    let closed = false;
    const close = async () => {
        if (closed) return;
        closed = true;
        if (!server.listening) return;
        server.closeAllConnections?.();
        await new Promise((resolve) => server.close(() => resolve()));
    };

    return {
        server,
        host,
        port,
        witnessAccount: signer.address,
        payTo: resolvedPayTo,
        priceMicroCcd: priceStr,
        sponsorPointer: Boolean(sponsorPointer),
        ledger,
        close,
    };
}

/** Creates and binds the witness HTTP server to `host:port`, resolving once listening. */
export async function startWitnessServer(opts = {}) {
    const created = await createWitnessServer(opts);
    await new Promise((resolve, reject) => {
        created.server.once('error', reject);
        created.server.listen(created.port, created.host, () => {
            created.server.off('error', reject);
            resolve();
        });
    });
    const addr = created.server.address();
    const boundPort = typeof addr === 'object' && addr ? addr.port : created.port;
    const fmtHost = created.host.includes(':') && !created.host.startsWith('[') ? `[${created.host}]` : created.host;
    const url = `http://${fmtHost}:${boundPort}`;
    return {
        ...created,
        port: boundPort,
        url,
    };
}
