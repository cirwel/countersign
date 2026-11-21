// Concordium testnet access. Reading needs no keys; signing reads a key file that lives outside the repo.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
    AccountAddress,
    CcdAmount,
    ConcordiumHdWallet,
    ContractAddress,
    ContractEvent,
    DataBlob,
    Energy,
    Parameter,
    ReceiveName,
    ReturnValue,
    Transaction,
    TransactionHash,
    buildBasicAccountSigner,
} from '@concordium/web-sdk';
import { ConcordiumGRPCNodeClient, credentials } from '@concordium/web-sdk/nodejs';
import {
    decodeAgentOf,
    decodeGetMetadataUtf8,
    encodeGetMetadataParam,
    encodeSetMetadataParam,
    encodeTokenId,
    parseCis2Event,
    parseMetadataSetEvent,
} from './cis8004.mjs';
import { REGISTRY, TESTNET_GENESIS, assertRegistry } from './registry.mjs';
import { decodeAnchor } from './trail.mjs';

export { TESTNET_GENESIS };
export const EXPLORER_TX = (hash) => `https://ccdexplorer.io/testnet/transaction/${hash}`;
const DEFAULT_NODE_HOST = 'grpc.testnet.concordium.com';
const DEFAULT_NODE_PORT = 20000;
const MAX_REGISTRY_ENERGY = 100000;

let explicitConfig = null;
let cached;
let cachedKey;
let cachedPromise;
let cachedPromiseKey;
const verifiedClients = new WeakMap();

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function isTransientRpcError(err) {
    if (!err) return false;
    const code = err.code;
    if (code === 'UNAVAILABLE' || code === 'RESOURCE_EXHAUSTED' || code === 14 || code === 8 || code === 429 || code === '429') {
        return true;
    }
    if (err.status === 429 || err.statusCode === 429) return true;
    return /\b(429|UNAVAILABLE|RESOURCE_EXHAUSTED)\b/i.test(String(err.message ?? ''));
}

function isNotFoundError(err) {
    return err?.code === 'NOT_FOUND' || err?.code === 5;
}

async function withRpcRetry(fn, { maxRetries = 4, baseDelayMs = 1000, onBackoff } = {}) {
    let attempt = 0;
    while (true) {
        try {
            return await fn();
        } catch (err) {
            if (!isTransientRpcError(err) || attempt >= maxRetries) throw err;
            const delay = Math.round(baseDelayMs * 2 ** attempt * (0.85 + 0.3 * Math.random()));
            attempt += 1;
            if (onBackoff) await onBackoff(delay);
            else await sleep(delay);
        }
    }
}

/** Bounded-concurrency RPC pool with exponential backoff retry on transient HTTP 429 / gRPC UNAVAILABLE / RESOURCE_EXHAUSTED. */
export function createRpcPool(concurrency = 5, retryOpts = {}) {
    if (!Number.isInteger(concurrency) || concurrency < 1) {
        throw new Error(`invalid RPC pool concurrency: ${concurrency}`);
    }
    let active = 0;
    let cooldownUntil = 0;
    const queue = [];
    const acquire = () => {
        if (active < concurrency) {
            active += 1;
            return Promise.resolve();
        }
        return new Promise((resolve) => queue.push(resolve));
    };
    const release = () => {
        const next = queue.shift();
        if (next) next();
        else active -= 1;
    };
    const waitCooldown = async () => {
        const waitMs = cooldownUntil - Date.now();
        if (waitMs > 0) await sleep(waitMs);
    };
    const limit = async (fn) => {
        await acquire();
        try {
            await waitCooldown();
            return await fn();
        } finally {
            release();
        }
    };
    const onBackoff = async (delay) => {
        cooldownUntil = Math.max(cooldownUntil, Date.now() + delay);
        await sleep(delay);
    };
    const run = (fn) => limit(() => withRpcRetry(fn, { onBackoff, ...retryOpts }));
    run.limit = limit;
    run.run = run;
    run.map = (items, fn) => Promise.all(items.map((item, i) => run(() => fn(item, i))));
    return run;
}

export { withRpcRetry };

function parseNodeString(raw) {
    const spec = raw.trim();
    if (!spec) return null;
    if (spec.startsWith('[')) {
        const m = /^\[([^\]]+)\](?::(\d+))?$/.exec(spec);
        if (!m) throw new Error(`invalid node address: ${raw}`);
        const port = m[2] ? Number(m[2]) : DEFAULT_NODE_PORT;
        if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`invalid node port in ${raw}`);
        return { host: m[1], port, tls: true };
    }
    const parts = spec.split(':');
    if (parts.length === 1) {
        return { host: parts[0], port: DEFAULT_NODE_PORT, tls: true };
    }
    if (parts.length === 2 && parts[0].length > 0 && /^\d+$/.test(parts[1])) {
        const port = Number(parts[1]);
        if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`invalid node port in ${raw}`);
        return { host: parts[0], port, tls: true };
    }
    throw new Error(`invalid node address: ${raw}`);
}

function normalizeNodeConfig(opts) {
    if (opts === undefined || opts === null) return null;
    if (typeof opts === 'string') return parseNodeString(opts);
    if (typeof opts !== 'object') throw new TypeError('configureNode expects an options object or host[:port] string');
    const envCfg = process.env.COUNTERSIGN_NODE ? parseNodeString(process.env.COUNTERSIGN_NODE) : null;
    const host = opts.host ?? envCfg?.host ?? DEFAULT_NODE_HOST;
    const port = opts.port !== undefined ? Number(opts.port) : (envCfg?.port ?? DEFAULT_NODE_PORT);
    const tls = opts.tls ?? true;
    if (typeof host !== 'string' || host.trim().length === 0) throw new Error('node host must be a non-empty string');
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`invalid node port: ${opts.port}`);
    if (typeof tls !== 'boolean') throw new Error('node tls option must be a boolean');
    return { host: host.trim(), port, tls };
}

function effectiveNodeConfig() {
    if (explicitConfig) return explicitConfig;
    if (process.env.COUNTERSIGN_NODE) {
        const parsed = parseNodeString(process.env.COUNTERSIGN_NODE);
        if (parsed) return parsed;
    }
    return { host: DEFAULT_NODE_HOST, port: DEFAULT_NODE_PORT, tls: true };
}

/** Configures the Concordium testnet gRPC endpoint and resets any cached node client. */
export function configureNode(opts) {
    cached = undefined;
    cachedKey = undefined;
    cachedPromise = undefined;
    cachedPromiseKey = undefined;
    explicitConfig = normalizeNodeConfig(opts);
    return effectiveNodeConfig();
}

/** Confirms a node client reports Concordium testnet genesis, caching verification per client instance. */
export async function assertTestnet(nodeClient) {
    const existing = verifiedClients.get(nodeClient);
    if (existing) return existing;
    const check = (async () => {
        const status = await withRpcRetry(() => nodeClient.getConsensusStatus());
        const genesis = status.genesisBlock.toString();
        if (genesis !== TESTNET_GENESIS) {
            throw new Error(`node is not Concordium testnet (genesis ${genesis}); refusing`);
        }
    })();
    verifiedClients.set(nodeClient, check);
    try {
        await check;
    } catch (err) {
        verifiedClients.delete(nodeClient);
        throw err;
    }
}

/** Returns a node client only after confirming the node is on testnet. There is no mainnet configuration in this tool. */
export async function client() {
    const cfg = effectiveNodeConfig();
    const key = `${cfg.host}:${cfg.port}:${cfg.tls ? 'tls' : 'plain'}`;
    if (cached && cachedKey === key) return cached;
    if (cachedPromise && cachedPromiseKey === key) return cachedPromise;

    cached = undefined;
    cachedKey = undefined;
    const p = (async () => {
        const creds = cfg.tls ? credentials.createSsl() : credentials.createInsecure();
        const c = new ConcordiumGRPCNodeClient(cfg.host, cfg.port, creds);
        await assertTestnet(c);
        cached = c;
        cachedKey = key;
        return c;
    })();
    cachedPromise = p;
    cachedPromiseKey = key;
    try {
        return await p;
    } finally {
        if (cachedPromise === p) {
            cachedPromise = undefined;
            cachedPromiseKey = undefined;
        }
    }
}

function keyfilePath() {
    if (process.env.COUNTERSIGN_KEYFILE) return process.env.COUNTERSIGN_KEYFILE;
    const local = path.resolve('countersign.local.json');
    if (fs.existsSync(local)) return JSON.parse(fs.readFileSync(local, 'utf8')).keyfile.replace(/^~/, os.homedir());
    return path.join(os.homedir(), '.config/countersign/testnet-account.json');
}

/** Key file: { accountAddress, seedPhrase } (identity 0, credential 0 on identity provider 0) or { accountAddress, signKey }. */
export function loadSigner() {
    const file = keyfilePath();
    if ((fs.statSync(file).mode & 0o077) !== 0) throw new Error('key file must not be readable by group or others (chmod 600)');
    const k = JSON.parse(fs.readFileSync(file, 'utf8'));
    const signKey = k.signKey ?? ConcordiumHdWallet.fromSeedPhrase(k.seedPhrase, 'Testnet').getAccountSigningKey(0, 0, 0).toString('hex');
    return { address: k.accountAddress, sender: AccountAddress.fromBase58(k.accountAddress), signer: buildBasicAccountSigner(signKey) };
}

async function signSendWait(builder, who) {
    const c = await client();
    const { nonce } = await withRpcRetry(() => c.getNextAccountNonce(who.sender));
    const tx = builder.addMetadata({ sender: who.sender, nonce }).build();
    const signed = await Transaction.signAndFinalize(tx, who.signer);
    const hash = await c.sendTransaction(signed);
    const { summary } = await c.waitForTransactionFinalization(hash, 180000);
    if (summary.transactionType === 'failed' || summary.rejectReason) {
        throw new Error(`transaction ${hash} was rejected: ${JSON.stringify(summary.rejectReason ?? summary, bigintSafe)}`);
    }
    return { hash: hash.toString(), summary };
}

export const bigintSafe = (_k, v) => (typeof v === 'bigint' ? v.toString() : v);

export function sendRegisterData(bytes, who = loadSigner()) {
    return signSendWait(Transaction.registerData({ data: new DataBlob(Buffer.from(bytes)) }), who);
}

/**
 * Signs and submits an unsigned payload built by the Agent Registry MCP server.
 * The server is not trusted to choose what gets signed: the caller states the entrypoint it expects,
 * the contract must be the pinned registry, the energy is capped, and where the caller can build the
 * parameter itself the server's bytes must equal it.
 */
export function sendRegistryUpdate(built, who, expect) {
    assertRegistry(built.contract_address);
    if (built.network !== 'testnet') throw new Error('registry payload is not for testnet; refusing to sign');
    if (!expect?.receiveName || built.receive_name !== expect.receiveName) throw new Error(`registry payload calls ${built.receive_name}, expected ${expect?.receiveName}; refusing to sign`);
    if (expect.parameterHex !== undefined && built.parameter_hex !== expect.parameterHex) throw new Error('registry payload parameter differs from the one built locally; refusing to sign');
    const energy = Number(built.suggested_energy ?? 30000);
    if (!(energy > 0 && energy <= MAX_REGISTRY_ENERGY)) throw new Error(`registry payload asks for ${energy} energy; refusing to sign`);
    const payload = {
        amount: CcdAmount.zero(),
        address: ContractAddress.create(built.contract_address.index, built.contract_address.subindex),
        receiveName: ReceiveName.fromString(built.receive_name),
        message: Parameter.fromHexString(built.parameter_hex),
    };
    return signSendWait(Transaction.updateContract(payload, Energy.create(energy)), who);
}

function registryContractAddress() {
    return ContractAddress.create(BigInt(REGISTRY.index), BigInt(REGISTRY.subindex));
}

function isRegistryAddress(addr) {
    return addr && Number(addr.index) === REGISTRY.index && Number(addr.subindex) === REGISTRY.subindex;
}

function eventToHex(ev) {
    if (typeof ev === 'string') return ev.toLowerCase();
    if (ev?.buffer instanceof Uint8Array) return Buffer.from(ev.buffer).toString('hex');
    if (ev instanceof Uint8Array) return Buffer.from(ev).toString('hex');
    return ContractEvent.toHexString(ev);
}

/** Invokes a read-only CIS-8004 view entrypoint on the pinned testnet registry contract. */
export async function invokeRegistryView(method, paramBuf, blockHash, nodeClient) {
    const c = nodeClient ?? (await client());
    await assertTestnet(c);
    const receiveName = method.includes('.') ? method : `CIS-8004.${method}`;
    const targetBlock = blockHash ?? (await withRpcRetry(() => c.getConsensusStatus())).lastFinalizedBlock;
    const context = {
        contract: registryContractAddress(),
        method: ReceiveName.fromString(receiveName),
        parameter: paramBuf && paramBuf.length > 0 ? Parameter.fromBuffer(Buffer.from(paramBuf)) : Parameter.empty(),
    };
    const res = await withRpcRetry(() => c.invokeContract(context, targetBlock));
    if (res.tag !== 'success') {
        throw new Error(`view ${receiveName} failed: ${JSON.stringify(res.reason ?? res, bigintSafe)}`);
    }
    return Buffer.from(ReturnValue.toBuffer(res.returnValue));
}

/** Reads and decodes CIS-8004.agentOf(tokenId) directly from a Concordium node. */
export async function readAgentOf(tokenId, { blockHash, nodeClient } = {}) {
    const bytes = await invokeRegistryView('CIS-8004.agentOf', encodeTokenId(tokenId), blockHash, nodeClient);
    return decodeAgentOf(bytes);
}

/** Reads and UTF-8 decodes CIS-8004.getMetadata(tokenId, key) directly from a Concordium node. */
export async function readMetadataText(tokenId, key, { blockHash, nodeClient } = {}) {
    const bytes = await invokeRegistryView('CIS-8004.getMetadata', encodeGetMetadataParam(tokenId, key), blockHash, nodeClient);
    return decodeGetMetadataUtf8(bytes);
}

/** Builds CIS-8004.setMetadata locally, estimates energy via dry-run invokeContract, and submits it on testnet. */
export async function sendSetMetadata(tokenId, key, valueUtf8, who = loadSigner()) {
    const c = await client();
    const paramBuf = encodeSetMetadataParam(tokenId, key, valueUtf8);
    const contract = registryContractAddress();
    const receiveName = ReceiveName.fromString('CIS-8004.setMetadata');
    const dryRun = await withRpcRetry(() =>
        c.invokeContract({
            invoker: who.sender,
            contract,
            method: receiveName,
            parameter: Parameter.fromBuffer(paramBuf),
        }),
    );
    if (dryRun.tag !== 'success') {
        throw new Error(`dry-run CIS-8004.setMetadata failed: ${JSON.stringify(dryRun.reason ?? dryRun, bigintSafe)}`);
    }
    const used = Number(dryRun.usedEnergy?.value ?? dryRun.usedEnergy);
    const energy = Math.max(used + 500, Math.ceil(used * 1.25));
    if (!(energy > 0 && energy <= MAX_REGISTRY_ENERGY)) {
        throw new Error(`CIS-8004.setMetadata estimated ${energy} energy (cap ${MAX_REGISTRY_ENERGY}); refusing to sign`);
    }
    const payload = {
        amount: CcdAmount.zero(),
        address: contract,
        receiveName,
        message: Parameter.fromBuffer(paramBuf),
    };
    return signSendWait(Transaction.updateContract(payload, Energy.create(energy)), who);
}

/** Finalized register-data transaction: who sent it, what bytes it carries, timestamp, and block height. */
export async function readRegisterData(txHash, nodeClient) {
    const c = nodeClient ?? (await client());
    await assertTestnet(c);
    const status = await withRpcRetry(() => c.getBlockItemStatus(TransactionHash.fromHexString(txHash)));
    if (status.status !== 'finalized') throw new Error(`transaction ${txHash} is not finalized (${status.status})`);
    const s = status.outcome.summary;
    if (s.transactionType !== 'registerData') throw new Error(`transaction ${txHash} is ${s.transactionType}, not registerData`);
    const block = await withRpcRetry(() => c.getBlockInfo(status.outcome.blockHash));
    const data = typeof s.dataRegistered.data === 'string' ? Buffer.from(s.dataRegistered.data, 'hex') : Buffer.from(s.dataRegistered.data);
    return {
        sender: s.sender.address ?? String(s.sender),
        data,
        blockTime: block.blockSlotTime.toISOString(),
        blockHeight: Number(block.blockHeight),
    };
}

/**
 * Reconstructs the complete, unbroken CIS-8004 MetadataSet history for tokenId between registration and tip
 * directly from a Concordium node, verifying mint ownership, immutable contract module, zero initial
 * operators, and uninterrupted exclusive ownership across every owner transaction block.
 */
export async function readRegistryHistory(
    tokenId,
    { tipBlockHash, tipBlockHeight, agent, hintAnchorTxHashes = [], maxOwnerTxs = 2000, nodeClient, pool: providedPool } = {},
) {
    if (!agent || !agent.ownerAccount || typeof agent.registeredAtMs !== 'number') {
        throw new Error('readRegistryHistory requires decoded agent info with ownerAccount and registeredAtMs');
    }
    const c = nodeClient ?? (await client());
    await assertTestnet(c);
    const rpc = providedPool ?? createRpcPool(5);
    const tipH = BigInt(tipBlockHeight);
    const targetTokenId = String(tokenId);
    const owner = agent.ownerAccount;
    const ownerAddr = AccountAddress.fromBase58(owner);
    const registryAddr = registryContractAddress();

    const blockHashCache = new Map();
    const blockInfoCache = new Map();
    const nonceCache = new Map();

    const blockHashAt = (h) => {
        if (h === tipH && tipBlockHash) return Promise.resolve(tipBlockHash);
        let p = blockHashCache.get(h);
        if (!p) {
            p = rpc.run(async () => {
                const blocks = await c.getBlocksAtHeight(h);
                if (!Array.isArray(blocks) || blocks.length !== 1) {
                    throw new Error(`expected 1 finalized block at height ${h}, got ${blocks?.length ?? 0}`);
                }
                return blocks[0];
            });
            blockHashCache.set(h, p);
        }
        return p;
    };

    const blockInfoAt = (h) => {
        let p = blockInfoCache.get(h);
        if (!p) {
            p = (async () => {
                const bh = await blockHashAt(h);
                return rpc.run(() => c.getBlockInfo(bh));
            })();
            blockInfoCache.set(h, p);
        }
        return p;
    };

    const timeAt = async (h) => (await blockInfoAt(h)).blockSlotTime.getTime();

    const nonceAt = (h) => {
        let p = nonceCache.get(h);
        if (!p) {
            p = (async () => {
                const bh = await blockHashAt(h);
                const info = await rpc.run(() => c.getAccountInfo(ownerAddr, bh));
                return BigInt(info.accountNonce?.value ?? info.accountNonce);
            })();
            nonceCache.set(h, p);
        }
        return p;
    };

    const getBlockEvents = async (h) => {
        const bh = await blockHashAt(h);
        return rpc.run(async () => {
            const items = [];
            for await (const s of c.getBlockTransactionEvents(bh)) items.push(s);
            return items;
        });
    };

    // 1. Locate registration block height via 2-point linear interpolation + binary search.
    const targetMs = agent.registeredAtMs;
    const refH = tipH > 10000n ? tipH - 10000n : 0n;
    const [tipTimeMs, refTimeMs] = await Promise.all([timeAt(tipH), timeAt(refH)]);
    if (targetMs > tipTimeMs) {
        throw new Error(`registration timestamp (${targetMs}) is after pinned tip block time (${tipTimeMs})`);
    }
    let est = 0n;
    if (tipH > refH) {
        const dt = tipTimeMs - refTimeMs;
        if (dt > 0) {
            const msPerBlock = dt / Number(tipH - refH);
            const deltaBlocks = msPerBlock > 0 ? Math.round((tipTimeMs - targetMs) / msPerBlock) : 0;
            est = tipH - BigInt(deltaBlocks);
            if (est < 0n) est = 0n;
            if (est > tipH) est = tipH;
        } else {
            est = tipH / 2n;
        }
    }

    let lo = est;
    let hi = est;
    const tEst = await timeAt(est);
    let tLo = tEst;
    let tHi = tEst;
    if (tEst < targetMs) {
        let step = 256n;
        while (hi < tipH) {
            const next = hi + step < tipH ? hi + step : tipH;
            const t = await timeAt(next);
            if (t >= targetMs) {
                hi = next;
                tHi = t;
                break;
            }
            lo = next;
            tLo = t;
            hi = next;
            tHi = t;
            step *= 2n;
        }
    } else if (tEst > targetMs) {
        let step = 256n;
        while (lo > 0n) {
            const prev = lo > step ? lo - step : 0n;
            const t = await timeAt(prev);
            if (t <= targetMs) {
                lo = prev;
                tLo = t;
                break;
            }
            hi = prev;
            tHi = t;
            lo = prev;
            tLo = t;
            step *= 2n;
        }
        if (tLo > targetMs) {
            throw new Error(`registration timestamp (${targetMs}) predates genesis block`);
        }
    }
    let iter = 0;
    while (lo < hi) {
        const span = hi - lo;
        let mid = (lo + hi) / 2n;
        if (span > 4n && tHi > tLo && iter % 3 !== 2) {
            const interp = lo + BigInt(Math.round((Number(span) * (targetMs - tLo)) / (tHi - tLo)));
            if (interp > lo && interp < hi) mid = interp;
        }
        iter += 1;
        const tMid = await timeAt(mid);
        if (tMid < targetMs) {
            lo = mid + 1n;
            tLo = await timeAt(lo);
        } else {
            hi = mid;
            tHi = tMid;
        }
    }

    // 2. Find Mint event for tokenId in [regHeight-2n, regHeight+2n] and verify Mint.owner === agent.ownerAccount.
    const findMintsInBlock = (h, summaries) => {
        const hits = [];
        for (let txIdx = 0; txIdx < summaries.length; txIdx++) {
            const summary = summaries[txIdx];
            if (!Array.isArray(summary.events) || summary.rejectReason) continue;
            for (let traceIdx = 0; traceIdx < summary.events.length; traceIdx++) {
                const traceEv = summary.events[traceIdx];
                if ((traceEv.tag !== 'Updated' && traceEv.tag !== 'Interrupted') || !isRegistryAddress(traceEv.address)) continue;
                const logs = traceEv.events ?? [];
                for (let logIdx = 0; logIdx < logs.length; logIdx++) {
                    const parsed = parseCis2Event(eventToHex(logs[logIdx]));
                    if (parsed.type === 'Mint' && parsed.tokenId === targetTokenId) {
                        hits.push({
                            height: h,
                            summaries,
                            txIdx,
                            traceIdx,
                            logIdx,
                            txHash: summary.hash.toString(),
                            owner: parsed.owner,
                            amount: parsed.amount,
                        });
                    }
                }
            }
        }
        return hits;
    };

    const winLo = lo >= 2n ? lo - 2n : 0n;
    const winHi = lo + 2n <= tipH ? lo + 2n : tipH;
    // Probe the interpolated height lo first; scan neighbors only if Mint wasn't at lo.
    const loSummaries = await getBlockEvents(lo);
    let mintHits = findMintsInBlock(lo, loSummaries);
    if (mintHits.length === 0) {
        const neighbors = [];
        for (let h = winLo; h <= winHi; h += 1n) {
            if (h !== lo) neighbors.push(h);
        }
        const neighborEvents = await Promise.all(neighbors.map(getBlockEvents));
        for (let i = 0; i < neighbors.length; i++) {
            mintHits.push(...findMintsInBlock(neighbors[i], neighborEvents[i]));
        }
    }
    if (mintHits.length !== 1) {
        throw new Error(`expected 1 Mint event for token ${targetTokenId} near block ${lo}, found ${mintHits.length}`);
    }
    const mintHit = mintHits[0];
    if (mintHit.owner !== owner) {
        throw new Error(`token ${targetTokenId} was minted to ${mintHit.owner}, not current owner ${owner}`);
    }
    if (mintHit.amount !== 1n) {
        throw new Error(`token ${targetTokenId} Mint amount was ${mintHit.amount}, expected 1`);
    }

    const regHeight = mintHit.height;
    const regBlockHash = await blockHashAt(regHeight);

    // 3. Verify registry sourceModule.moduleRef did not change between registration and tip.
    const [regInst, tipInst] = await Promise.all([
        rpc.run(() => c.getInstanceInfo(registryAddr, regBlockHash)),
        rpc.run(() => c.getInstanceInfo(registryAddr, tipBlockHash)),
    ]);
    const refOf = (info) => info?.sourceModule?.moduleRef ?? String(info?.sourceModule ?? '');
    if (!refOf(regInst) || refOf(regInst) !== refOf(tipInst)) {
        throw new Error(`registry contract sourceModule changed between registration (${refOf(regInst)}) and tip (${refOf(tipInst)})`);
    }

    // 4. Verify zero initial CIS-2 operators for owner at regBlockHash.
    const ownerHex = Buffer.from(ownerAddr.decodedAddress).toString('hex');
    const opKeyHex = '0500000000000000' + ownerHex;
    let opSubmap = null;
    try {
        const raw = await rpc.run(() => c.instanceStateLookup(registryAddr, opKeyHex, regBlockHash));
        if (raw !== undefined && raw !== null) {
            opSubmap = typeof raw === 'string' ? raw.toLowerCase() : Buffer.from(raw).toString('hex');
        }
    } catch (err) {
        if (!isNotFoundError(err)) throw err;
    }
    if (opSubmap !== null) {
        if (!/^[0-9a-f]{16}$/.test(opSubmap)) {
            throw new Error(`unexpected operator submap prefix for ${owner} at block ${regHeight}`);
        }
        const hasInitialOperator = await rpc.run(async () => {
            for await (const entry of c.getInstanceState(registryAddr, regBlockHash)) {
                const k = typeof entry.key === 'string' ? entry.key.toLowerCase() : Buffer.from(entry.key).toString('hex');
                if (k.startsWith(opSubmap)) return true;
            }
            return false;
        });
        if (hasInitialOperator) {
            throw new Error(`owner ${owner} had pre-existing CIS-2 operator(s) at registration block ${regHeight}`);
        }
    }

    // 5. Follow hintAnchorTxHashes / prevAnchorTx links (cycle-protected) to get split hints.
    const seenHints = new Set();
    const hintHeightSet = new Set();
    const hintQueue = [...hintAnchorTxHashes].filter((h) => typeof h === 'string' && /^[0-9a-f]{64}$/.test(h));
    while (hintQueue.length > 0) {
        const hTx = hintQueue.shift();
        if (seenHints.has(hTx)) continue;
        seenHints.add(hTx);
        try {
            const rd = await rpc.limit(() => readRegisterData(hTx, c));
            const h = BigInt(rd.blockHeight);
            if (h > regHeight && h < tipH) hintHeightSet.add(h);
            const dec = decodeAnchor(rd.data);
            if (dec.prevAnchorTx && !seenHints.has(dec.prevAnchorTx)) hintQueue.push(dec.prevAnchorTx);
        } catch {
            // Hints are strictly advisory; exhaustive nonce scanning guarantees completeness.
        }
    }

    // 6. Check owner nonce span <= maxOwnerTxs.
    const [nStart, nEnd] = await Promise.all([nonceAt(regHeight), nonceAt(tipH)]);
    if (nEnd < nStart) {
        throw new Error(`non-monotonic owner accountNonce (${nEnd} < ${nStart})`);
    }
    if (nEnd - nStart > BigInt(maxOwnerTxs)) {
        throw new Error(`owner ${owner} executed ${nEnd - nStart} transactions between block ${regHeight} and ${tipH}, exceeding maxOwnerTxs=${maxOwnerTxs}`);
    }

    // 7. Exhaustively find every block in (regHeight, tipH] where owner's accountNonce increased.
    const binaryRange = async (rLo, rHi, nLo, nHi) => {
        if (nHi < nLo) throw new Error(`non-monotonic owner accountNonce (${nHi} < ${nLo})`);
        if (nLo === nHi || rLo >= rHi) return [];
        if (rHi === rLo + 1n) return [rHi];
        const mid = (rLo + rHi) / 2n;
        const nMid = await nonceAt(mid);
        if (nMid < nLo || nHi < nMid) throw new Error(`non-monotonic owner accountNonce across [${rLo}, ${mid}, ${rHi}]`);
        const [left, right] = await Promise.all([
            nMid > nLo ? binaryRange(rLo, mid, nLo, nMid) : [],
            nHi > nMid ? binaryRange(mid, rHi, nMid, nHi) : [],
        ]);
        return left.concat(right);
    };

    const scanRange = async (rLo, rHi, nLo, nHi) => {
        if (nHi < nLo) throw new Error(`non-monotonic owner accountNonce (${nHi} < ${nLo})`);
        if (nLo === nHi || rLo >= rHi) return [];
        if (rHi === rLo + 1n) return [rHi];
        if (rHi - rLo <= 32n) return binaryRange(rLo, rHi, nLo, nHi);

        let prev = rLo;
        let step = 8n;
        while (prev < rHi) {
            const next = prev + step < rHi ? prev + step : rHi;
            const nNext = await nonceAt(next);
            if (nNext < nLo) throw new Error(`non-monotonic owner accountNonce (${nNext} < ${nLo})`);
            if (nNext > nLo) {
                const [left, right] = await Promise.all([
                    binaryRange(prev, next, nLo, nNext),
                    nNext < nHi ? scanRange(next, rHi, nNext, nHi) : [],
                ]);
                return left.concat(right);
            }
            prev = next;
            step *= 2n;
        }
        return [];
    };

    // Split at both (h - 1) and h for each hint height so known anchor blocks resolve in 1 probe instead of binary search.
    const splitSet = new Set([regHeight, tipH]);
    for (const h of hintHeightSet) {
        if (h - 1n > regHeight) splitSet.add(h - 1n);
        splitSet.add(h);
    }
    const points = [...splitSet].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const pointNonces = await Promise.all(points.map(nonceAt));
    const intervalResults = await Promise.all(
        points.slice(0, -1).map((p, i) => scanRange(p, points[i + 1], pointNonces[i], pointNonces[i + 1])),
    );
    const discoveredHeights = [...new Set(intervalResults.flat())].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

    // 8. Stream getBlockTransactionEvents for regHeight (post-Mint) and each discovered block in ascending order.
    const discoveredEvents = await Promise.all(discoveredHeights.map(getBlockEvents));
    const collected = [];

    const processBlock = (h, summaries, startAfterMint) => {
        for (let txIdx = 0; txIdx < summaries.length; txIdx++) {
            const summary = summaries[txIdx];
            if (!Array.isArray(summary.events) || summary.rejectReason) continue;
            const txHash = summary.hash.toString();
            for (let traceIdx = 0; traceIdx < summary.events.length; traceIdx++) {
                const traceEv = summary.events[traceIdx];
                if (traceEv.tag === 'Upgraded' && isRegistryAddress(traceEv.address)) {
                    throw new Error(`registry contract upgraded at block ${h} (tx ${txHash})`);
                }
                if ((traceEv.tag !== 'Updated' && traceEv.tag !== 'Interrupted') || !isRegistryAddress(traceEv.address)) continue;
                const logs = traceEv.events ?? [];
                for (let logIdx = 0; logIdx < logs.length; logIdx++) {
                    if (startAfterMint) {
                        const beforeOrAtMint =
                            txIdx < mintHit.txIdx ||
                            (txIdx === mintHit.txIdx && (traceIdx < mintHit.traceIdx || (traceIdx === mintHit.traceIdx && logIdx <= mintHit.logIdx)));
                        if (beforeOrAtMint) continue;
                    }
                    const rawHex = eventToHex(logs[logIdx]);
                    const parsed = parseCis2Event(rawHex);
                    if (parsed.type === 'Transfer' && parsed.tokenId === targetTokenId) {
                        if (parsed.from !== owner || parsed.to !== owner) {
                            throw new Error(`token ${targetTokenId} was transferred (${parsed.from} -> ${parsed.to}) at block ${h} (tx ${txHash})`);
                        }
                    } else if (parsed.type === 'Burn' && parsed.tokenId === targetTokenId) {
                        throw new Error(`token ${targetTokenId} was burned at block ${h} (tx ${txHash})`);
                    } else if (parsed.type === 'UpdateOperator' && parsed.update === 'Add' && parsed.owner === owner) {
                        throw new Error(`owner ${owner} added CIS-2 operator ${parsed.operator} at block ${h} (tx ${txHash})`);
                    } else if (parsed.type === 'MetadataSet') {
                        const meta = parseMetadataSetEvent(rawHex, targetTokenId);
                        if (meta) {
                            collected.push({ ...meta, txHash, blockHeight: Number(h) });
                        }
                    }
                }
            }
        }
    };

    processBlock(regHeight, mintHit.summaries, true);
    for (let i = 0; i < discoveredHeights.length; i++) {
        processBlock(discoveredHeights[i], discoveredEvents[i], false);
    }

    return {
        regHeight: Number(regHeight),
        regBlockHash: regBlockHash.toString(),
        mintTxHash: mintHit.txHash,
        owner,
        scannedBlocks: discoveredHeights.length,
        events: collected,
    };
}
