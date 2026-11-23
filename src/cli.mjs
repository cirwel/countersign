#!/usr/bin/env node
// countersign: register an agent, export its trail, anchor a commitment, verify.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { AccountAddress } from '@concordium/web-sdk';
import {
    ANCHOR_KEY,
    EXPLORER_TX,
    TESTNET_GENESIS,
    TX_RE,
    UUID_KEY,
    WITNESS_KEY,
    applyNodeOptions,
    assertTestnet,
    buildSignedSponsoredSetMetadata,
    chainIsUnbroken,
    client,
    coverageGrows,
    extractWitnessState,
    isSameAccount,
    loadAnchorsFromHistory,
    loadSigner,
    loadSignerFromFile,
    readAgentOf,
    readMetadataText,
    readRegisterData,
    readRegistryHistory,
    sendRegisterData,
    sendRegistryUpdate,
    sendSetMetadata,
    sendTransferWithMemo,
    verifyExistingAnchors,
    withRpcRetry,
    witnessMatchesOnChain,
} from './chain.mjs';
import { UUID_RE, fetchCheckpointsAfter } from './checkpoints.mjs';
import { decodeBadge, encodeBadge, fetchAgentCard, verifyAgentCardBytes } from './cis8004.mjs';
import { NETWORK, REGISTRY, mcp } from './registry.mjs';
import { SCHEMA, commitments, decodeAnchor, encodeAnchor, readTrail, serializeTrail } from './trail.mjs';
import { startWitnessServer } from './witness.mjs';
import {
    canonicalStatePath,
    canonicalTrailPath,
    legacySidecarPath,
    preparePointerUpdateAtTip,
    runAnchorWorker,
    tokenLockPath,
    trailFileMode,
    trailLockPath,
    verifyWitnessAnchorOnChain,
    withFileLock,
    writeFileAtomic,
} from './worker.mjs';
import {
    X402_VERSION,
    encodeX402Header,
    fetchWitnessHealth,
    requestSponsoredPointer,
    requestWitnessAnchor,
} from './x402.mjs';

const hex = (s) => Buffer.from(s, 'utf8').toString('hex');
const sha256hex = (b) => crypto.createHash('sha256').update(b).digest('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function parseOptionalPositiveInt(val, flagName) {
    if (val === undefined || val === null) return null;
    if (typeof val === 'number') {
        if (!Number.isSafeInteger(val) || val <= 0) throw new Error(`${flagName} must be a positive safe integer`);
        return val;
    }
    const s = String(val).trim();
    if (!/^[0-9]+$/.test(s)) throw new Error(`${flagName} must be a positive integer`);
    const n = Number(s);
    if (!Number.isSafeInteger(n) || n <= 0) throw new Error(`${flagName} must be a positive safe integer`);
    return n;
}

function parseOptionalPositiveNumber(val, flagName, defaultVal = null) {
    if (val === undefined || val === null) return defaultVal;
    const s = typeof val === 'number' ? String(val) : String(val).trim();
    if (s.length === 0) throw new Error(`${flagName} must be a positive number`);
    const n = Number(s);
    if (!Number.isFinite(n) || n <= 0) throw new Error(`${flagName} must be a positive finite number`);
    return n;
}

function parseOptionalPort(val, flagName) {
    if (val === undefined || val === null) return null;
    const s = typeof val === 'number' ? String(val) : String(val).trim();
    if (!/^[0-9]+$/.test(s)) throw new Error(`${flagName} must be an integer between 0 and 65535`);
    const n = Number(s);
    if (!Number.isInteger(n) || n < 0 || n > 65535) throw new Error(`${flagName} must be between 0 and 65535`);
    return n;
}

function parseOptionalNonNegativeBigIntStr(val, flagName, defaultVal) {
    if (val === undefined || val === null) return defaultVal;
    const s = typeof val === 'bigint' || typeof val === 'number' ? String(val) : String(val).trim();
    if (!/^(?:0|[1-9][0-9]*)$/.test(s)) throw new Error(`${flagName} must be a non-negative integer`);
    return s;
}

function resolveSponsorPointerOpt(opts, defaultVal = true) {
    const hasDisable = Boolean(opts.noSponsorPointer ?? opts['no-sponsor-pointer']);
    const explicitEnable = opts.sponsorPointer ?? opts['sponsor-pointer'];
    if (hasDisable && explicitEnable === true) {
        throw new Error('cannot combine --sponsor-pointer and --no-sponsor-pointer');
    }
    if (hasDisable) return false;
    if (explicitEnable !== undefined) return Boolean(explicitEnable);
    return defaultVal;
}

function resolveTrailStateContext(trail, explicitState) {
    const targetTrail = canonicalTrailPath(trail);
    const resolvedStatePath = canonicalStatePath(targetTrail, explicitState);
    const legacyStatePath =
        explicitState === undefined || explicitState === null
            ? legacySidecarPath(trail, resolvedStatePath)
            : null;
    const trailLock = trailLockPath(targetTrail);
    if (
        resolvedStatePath === targetTrail ||
        resolvedStatePath === trailLock ||
        (legacyStatePath && (legacyStatePath === targetTrail || legacyStatePath === trailLock))
    ) {
        throw new Error(`statePath (${resolvedStatePath}) must not collide with trailPath or lockPath`);
    }
    const stateCandidates = legacyStatePath ? [resolvedStatePath, legacyStatePath] : [resolvedStatePath];
    return { targetTrail, resolvedStatePath, legacyStatePath, trailLock, stateCandidates };
}

function assertNoPendingStateFiles(
    stateCandidates,
    { legacyStatePath = null, resolvedStatePath = null, trail = null, callerCommand = 'anchor', checkPending = true } = {},
) {
    if (legacyStatePath && fs.existsSync(legacyStatePath) && fs.existsSync(resolvedStatePath)) {
        const stLegacy = fs.statSync(legacyStatePath);
        const stCanon = fs.statSync(resolvedStatePath);
        if (
            (stLegacy.dev !== stCanon.dev || stLegacy.ino !== stCanon.ino) &&
            Buffer.compare(fs.readFileSync(legacyStatePath), fs.readFileSync(resolvedStatePath)) !== 0
        ) {
            throw new Error(
                `conflicting anchor state files exist at both legacy path (${legacyStatePath}) and canonical path (${resolvedStatePath}); resolve manually`,
            );
        }
    }
    if (!checkPending) return;
    for (const stateFile of stateCandidates) {
        if (!fs.existsSync(stateFile)) continue;
        let parsedState;
        try {
            parsedState = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
        } catch (err) {
            throw new Error(`corrupt anchor state file ${stateFile}: ${err.message}`);
        }
        if (parsedState?.pendingAnchor) {
            const hint = trail
                ? `finish it with "countersign anchor --trail ${trail} --tx ${parsedState.pendingAnchor.txHash}" or "countersign watch --once"`
                : `finish or clear it with "countersign watch --once"`;
            throw new Error(
                `pending anchor ${parsedState.pendingAnchor.txHash} exists in ${stateFile}; ${hint} before running "countersign ${callerCommand}"`,
            );
        }
        if (parsedState?.pendingPayment) {
            throw new Error(
                `pending payment ${parsedState.pendingPayment.paymentTxHash} exists in ${stateFile}; finish it with "countersign watch --once --witness-url ${parsedState.pendingPayment.witnessUrl ?? '<witness-url>'}" before running "countersign ${callerCommand}"`,
            );
        }
    }
}

export const commands = {
    /** Mint a registry entry whose on-chain metadata names the agent's UNITARES UUID. */
    async register({ uuid }) {
        if (!UUID_RE.test(uuid ?? '')) throw new Error('--uuid <agent uuid> is required');
        const who = loadSigner();
        const before = new Set(((await mcp('agents_by_owner', { owner_account: who.address }))?.agents ?? []).map((a) => String(a.token_id)));
        const built = await mcp('build_register', { sender: who.address, initial_metadata: [{ key: UUID_KEY, value_hex: hex(uuid) }] });
        const { hash } = await sendRegistryUpdate(built, who, { receiveName: 'CIS-8004.register' });
        console.log('registered:', EXPLORER_TX(hash));
        for (let i = 0; i < 20; i++) {
            const mine = ((await mcp('agents_by_owner', { owner_account: who.address }))?.agents ?? []).map((a) => String(a.token_id));
            const fresh = mine.filter((t) => !before.has(t));
            if (fresh.length === 1) {
                console.log('token_id:', fresh[0], 'badge:', encodeBadge(fresh[0]));
                return;
            }
            if (fresh.length > 1) throw new Error(`several new entries appeared (${fresh.join(', ')}); find yours by transaction ${hash}`);
            await sleep(3000);
        }
        console.log('registered, but the indexer has not listed the new token yet; look it up with agents_by_owner');
    },

    /** Build the Agent Card through the registry server and write the exact bytes to host. */
    async card({ token, name, description, url, out, uuid }) {
        const who = loadSigner();
        const r = await mcp('build_agent_card', {
            name,
            description,
            agent_uri: url,
            owner_account: who.address,
            token_id: String(token),
            documentation_url: 'https://github.com/cirwel/countersign',
            skills: [
                { id: 'countersigned-trail', name: 'Countersigned trail', description: `Check-in record anchored on Concordium testnet; UNITARES agent ${uuid}.`, tags: ['audit', 'unitares'] },
            ],
        });
        const local = sha256hex(Buffer.from(r.agent_card_json));
        if (local !== r.metadata_hash_hex) throw new Error('the registry server reported a different hash for the card it returned');
        fs.writeFileSync(out, r.agent_card_json);
        console.log('wrote', out, 'sha256', local);
    },

    /** Pin the hosted card's URL and hash on chain. Run after the card is publicly served. */
    async 'pin-card'({ token, url, file, ...opts }) {
        const who = loadSigner();
        const allowPrivate = Boolean(opts.allowPrivateCard ?? opts['allow-private-card']);
        const local = sha256hex(fs.readFileSync(file));
        const served = sha256hex(await fetchAgentCard(url, { allowPrivate }));
        if (local !== served) throw new Error(`the bytes served at ${url} differ from ${file}; host the file verbatim first`);
        const built = await mcp('build_set_agent_uri', { token_id: String(token), agent_uri: url, metadata_hash_hex: local, sender: who.address });
        const { hash } = await sendRegistryUpdate(built, who, { receiveName: 'CIS-8004.setAgentURI' });
        console.log('card pinned:', EXPLORER_TX(hash));
    },

    /** Operator side: read an agent's checkpoints from the UNITARES database (read-only) into a canonical trail file. */
    async export({ uuid, token, out, psql, execFile, ...opts }) {
        if (!UUID_RE.test(uuid ?? '')) throw new Error('--uuid is required');
        if (!/^[0-9]+$/.test(token ?? '')) throw new Error('--token <id> is required');
        if (!out) throw new Error('--out <path> is required');
        const timeoutMs = parseOptionalPositiveInt(opts.psqlTimeoutMs ?? opts['psql-timeout-ms'] ?? opts['psql-timeout'], '--psql-timeout');
        const batchSize = parseOptionalPositiveInt(opts.batchSize ?? opts['psql-batch-size'], '--psql-batch-size');
        const targetOut = canonicalTrailPath(out);
        return withFileLock(trailLockPath(targetOut), async () => {
            const rows = await fetchCheckpointsAfter({
                uuid,
                afterSeq: 0,
                psql,
                ...(timeoutMs ? { timeoutMs } : {}),
                ...(batchSize ? { batchSize } : {}),
                ...(execFile ? { execFile } : {}),
            });
            const header = { schema: SCHEMA, source: 'unitares core.checkpoints', agent_uuid: uuid, token_id: String(token), registry: { network: NETWORK, ...REGISTRY } };
            writeFileAtomic(targetOut, serializeTrail(header, rows), { mode: trailFileMode(targetOut) });
            const { last, count } = commitments(header, rows);
            console.log(`exported ${count} records to ${out}; commitment ${last.toString('hex')}`);
        });
    },

    /** Write the trail's current commitment to testnet and point the registry entry at it. */
    async anchor({ trail, tx, node, nodeClient, who: providedWho, ...opts }) {
        if (!trail) throw new Error('--trail <path> is required');
        const explicitState = opts.state ?? opts.statePath;
        const { targetTrail, resolvedStatePath, legacyStatePath, trailLock, stateCandidates } = resolveTrailStateContext(
            trail,
            explicitState,
        );
        return withFileLock(trailLock, async () => {
            const nodeInsecure = Boolean(opts.nodeInsecure ?? opts['node-insecure']);
            applyNodeOptions(node, nodeInsecure);
            const who = providedWho ?? loadSigner();
            const { header, records } = readTrail(targetTrail);
            const tokenId = header.token_id;
            return withFileLock(tokenLockPath(tokenId, { tokenLockDir: opts.tokenLockDir }), async () => {
                assertNoPendingStateFiles(stateCandidates, {
                    legacyStatePath,
                    resolvedStatePath,
                    trail,
                    callerCommand: 'anchor',
                    checkPending: !tx,
                });

                const c = nodeClient ?? (await client());
                await assertTestnet(c);
                const cs = await withRpcRetry(() => c.getConsensusStatus());
                const tipBlockHash = cs.lastFinalizedBlock;
                const tipBlockHeight = cs.lastFinalizedBlockHeight;

                const agent = await readAgentOf(tokenId, { blockHash: tipBlockHash, nodeClient: c });
                if (!agent) throw new Error(`registry token ${tokenId} is not registered`);
                if (agent.status !== undefined && agent.status !== 'Active') {
                    throw new Error(`registry token ${tokenId} status is ${agent.status}`);
                }
                if (who.address !== agent.ownerAccount) {
                    throw new Error(
                        `signer ${who.address} must exactly match registered owner ${agent.ownerAccount} (CIS-8004.setMetadata rejects account aliases)`,
                    );
                }
                const current = await readMetadataText(tokenId, ANCHOR_KEY, { blockHash: tipBlockHash, nodeClient: c });
                if (current !== null && !TX_RE.test(current)) throw new Error(`metadata ${ANCHOR_KEY} is not a transaction hash`);

                const history = await readRegistryHistory(tokenId, {
                    tipBlockHash,
                    tipBlockHeight,
                    agent,
                    hintAnchorTxHashes: current ? [current] : [],
                    nodeClient: c,
                });
                const existing = await loadAnchorsFromHistory(history, c, tipBlockHeight);
                const { last, count, at } = commitments(header, records, new Set(existing.map((a) => a.toSeq)));
                // Never extend a chain this trail no longer agrees with: a new anchor over a drifted record would break every earlier one.
                const prev = verifyExistingAnchors(existing, {
                    tokenId,
                    ownerAccount: agent.ownerAccount,
                    commitmentAt: at,
                    currentPointer: current,
                });
                if (prev && prev.toSeq >= count) throw new Error(`the latest anchor already covers seq ${prev.toSeq}; nothing new to anchor`);

                const onChainWitness = await readMetadataText(tokenId, WITNESS_KEY, {
                    blockHash: tipBlockHash,
                    nodeClient: c,
                });
                const witnessState = extractWitnessState(history);
                if (!witnessMatchesOnChain(witnessState, onChainWitness)) {
                    throw new Error(
                        `on-chain ${WITNESS_KEY} (${onChainWitness ?? 'null'}) disagrees with MetadataSet history (${witnessState.currentWitness ?? 'null'})`,
                    );
                }
                const activeWitness = witnessState.currentWitness;

                const acc = await withRpcRetry(() => c.getAccountInfo(who.sender, tipBlockHash));
                const expectedAnchorNonce = BigInt(acc.accountNonce.value);

                const witnessUrl = opts.witnessUrl ?? opts['witness-url'] ?? null;
                const sponsorPointerOpt = resolveSponsorPointerOpt(opts, true);
                const maxPriceMicroCcd = parseOptionalNonNegativeBigIntStr(
                    opts.maxPriceMicroCcd ?? opts['max-price-micro-ccd'],
                    '--max-price-micro-ccd',
                    null,
                );
                const paymentSignature = opts.paymentSignature ?? opts['payment-signature'] ?? null;
                const payerKeyfile =
                    opts.payerKeyfile ?? opts['payer-keyfile'] ?? opts.paymentKeyfile ?? opts['payment-keyfile'] ?? null;
                const allowPrivateWitness = Boolean(opts.allowPrivateWitness ?? opts['allow-private-witness']);
                const fetchHealthFn = opts.fetchWitnessHealthFn ?? fetchWitnessHealth;
                const reqWitnessAnchorFn = opts.requestWitnessAnchorFn ?? requestWitnessAnchor;
                const reqSponsoredPointerFn = opts.requestSponsoredPointerFn ?? requestSponsoredPointer;

                if (!tx && activeWitness !== null && !witnessUrl) {
                    throw new Error(
                        `token ${tokenId} has active ${WITNESS_KEY} (${activeWitness}); --witness-url is required and owner self-anchoring is disabled`,
                    );
                }

                let witnessHealth = null;
                if (witnessUrl) {
                    witnessHealth = await fetchHealthFn({ witnessUrl, allowPrivate: allowPrivateWitness });
                    if (activeWitness === null || !isSameAccount(activeWitness, witnessHealth.witnessAccount)) {
                        throw new Error(
                            `on-chain ${WITNESS_KEY} (${onChainWitness ?? 'not set'}) does not match witness ${witnessHealth.witnessAccount}`,
                        );
                    }
                    if (isSameAccount(witnessHealth.witnessAccount, agent.ownerAccount)) {
                        throw new Error(`witness account ${witnessHealth.witnessAccount} cannot equal owner ${agent.ownerAccount}`);
                    }
                }

                let hash = tx; // --tx <hash>: an anchor that was sent but whose pointer update did not land
                if (hash) {
                    if (!TX_RE.test(hash)) throw new Error('--tx must be a transaction hash');
                    const sent = await readRegisterData(hash, c);
                    const d = decodeAnchor(sent.data);
                    const authorizedSender = activeWitness ?? agent.ownerAccount;
                    const ok =
                        isSameAccount(sent.sender, authorizedSender) &&
                        d.tokenId === tokenId &&
                        d.toSeq === count &&
                        d.commitment === last.toString('hex') &&
                        d.prevAnchorTx === (prev?.txHash ?? null);
                    if (!ok) throw new Error('--tx is not the next anchor for this trail');
                } else {
                    const latestBeforeAnchor = await readMetadataText(tokenId, ANCHOR_KEY, { nodeClient: c });
                    if (latestBeforeAnchor !== (prev?.txHash ?? null)) {
                        throw new Error('countersign.anchor moved concurrently; refusing to overwrite pointer');
                    }
                    if (witnessUrl) {
                        let finalizedPaymentSig = null;
                        let finalizedPaymentHash = null;
                        const payFn = paymentSignature
                            ? null
                            : async (requirements) => {
                                  const amount = BigInt(requirements.amount);
                                  if (amount > 0n) {
                                      if (maxPriceMicroCcd === null) {
                                          throw new Error(
                                              `refusing to auto-pay ${amount} microCCD without explicit --max-price-micro-ccd`,
                                          );
                                      }
                                      if (amount > BigInt(maxPriceMicroCcd)) {
                                          throw new Error(
                                              `witness price ${amount} microCCD exceeds --max-price-micro-ccd ${maxPriceMicroCcd}`,
                                          );
                                      }
                                      if (
                                          witnessHealth?.priceMicroCcd === undefined ||
                                          witnessHealth?.priceMicroCcd === null
                                      ) {
                                          throw new Error(
                                              'witness /health did not advertise priceMicroCcd; refusing non-zero auto-payment',
                                          );
                                      }
                                      if (amount > BigInt(witnessHealth.priceMicroCcd)) {
                                          throw new Error(
                                              `witness 402 amount ${amount} exceeds /health priceMicroCcd ${witnessHealth.priceMicroCcd}`,
                                          );
                                      }
                                  }
                                  const pWho = opts.payerSigner ?? (payerKeyfile ? loadSignerFromFile(payerKeyfile) : who);
                                  const nextPayerNonce = await withRpcRetry(() => c.getNextAccountNonce(pWho.sender));
                                  if (!nextPayerNonce?.allFinal) {
                                      throw new Error(
                                          `payer account ${pWho.address} has non-finalized transactions; refusing witness payment`,
                                      );
                                  }
                                  const memoBytes = Buffer.from(requirements.extra.memoHex, 'hex');
                                  const payTx = await sendTransferWithMemo({
                                      to: requirements.payTo,
                                      microCcd: amount,
                                      memoBytes,
                                      who: pWho,
                                      nodeClient: c,
                                      expectedNonce: BigInt(nextPayerNonce.nonce.value),
                                      onSigned: ({ txHash: pHash }) => {
                                          console.log(`submitting witness payment ${requirements.amount} microCCD: ${EXPLORER_TX(pHash)}`);
                                      },
                                  });
                                  const envelope = {
                                      x402Version: X402_VERSION,
                                      accepted: requirements,
                                      payload: { txHash: payTx.hash },
                                  };
                                  finalizedPaymentSig = encodeX402Header(envelope);
                                  finalizedPaymentHash = payTx.hash;
                                  console.log(`paid witness fee ${requirements.amount} microCCD: ${EXPLORER_TX(payTx.hash)}`);
                                  return envelope;
                              };
                        let wRes;
                        try {
                            wRes = await reqWitnessAnchorFn({
                                witnessUrl,
                                tokenId,
                                toSeq: count,
                                commitment: last.toString('hex'),
                                prevAnchorTx: prev?.txHash ?? null,
                                paymentSignature,
                                payFn,
                                expectedPayTo: witnessHealth.payTo,
                                maxPriceMicroCcd,
                                expectedWitnessAccount: witnessHealth.witnessAccount,
                                allowPrivate: allowPrivateWitness,
                            });
                            await verifyWitnessAnchorOnChain({
                                nodeClient: c,
                                txHash: wRes.txHash,
                                activeWitness,
                                tokenId,
                                toSeq: count,
                                commitmentHex: last.toString('hex'),
                                prevAnchorTx: prev?.txHash ?? null,
                            });
                        } catch (err) {
                            if (finalizedPaymentSig) {
                                console.error(
                                    `witness request failed after payment ${finalizedPaymentHash} finalized; retry with --payment-signature ${finalizedPaymentSig}`,
                                );
                            }
                            throw err;
                        }
                        hash = wRes.txHash;
                        console.log(`witnessed seq 1..${count}: ${EXPLORER_TX(hash)}`);
                    } else {
                        const data = encodeAnchor({ tokenId, toSeq: count, commitment: last, prevAnchorTx: prev?.txHash ?? null });
                        ({ hash } = await sendRegisterData(data, who, c, { expectedNonce: expectedAnchorNonce }));
                        console.log(`anchored seq 1..${count}: ${EXPLORER_TX(hash)}`);
                    }
                }

                const preparedSet = await preparePointerUpdateAtTip({
                    nodeClient: c,
                    tokenId,
                    signerSender: who.sender,
                    expectedPrevTx: prev?.txHash ?? null,
                    expectedOwnerAccount: agent.ownerAccount,
                    expectedActiveWitness: activeWitness,
                });
                const expectedSetNonce =
                    witnessUrl || tx ? preparedSet.expectedSetNonce : expectedAnchorNonce + 1n;
                if (witnessUrl && sponsorPointerOpt && witnessHealth?.sponsorPointer) {
                    const built = await buildSignedSponsoredSetMetadata({
                        tokenId,
                        key: ANCHOR_KEY,
                        valueUtf8: hash,
                        who,
                        sponsorAddress: witnessHealth.witnessAccount,
                        expectedNonce: expectedSetNonce,
                        nodeClient: c,
                    });
                    const sp = await reqSponsoredPointerFn({
                        witnessUrl,
                        tokenId,
                        anchorTxHash: hash,
                        transactionJson: built.transactionJson,
                        allowPrivate: allowPrivateWitness,
                    });
                    console.log('registry entry now points at the anchor (sponsored):', EXPLORER_TX(sp.metadataTxHash));
                } else {
                    const set = await sendSetMetadata(tokenId, ANCHOR_KEY, hash, who, c, { expectedNonce: expectedSetNonce });
                    console.log('registry entry now points at the anchor:', EXPLORER_TX(set.hash));
                }
            });
        });
    },

    /** Authorize or clear a separate witness account (`countersign.witness`) for a registry token. */
    async 'set-witness'({ token, tokenId, witness, clear, trail, node, nodeClient, who: providedWho, ...opts }) {
        const resolvedToken = token ?? tokenId;
        if (!/^(?:0|[1-9][0-9]*)$/.test(resolvedToken !== undefined && resolvedToken !== null ? String(resolvedToken) : '')) {
            throw new Error('--token <id> is required');
        }
        const tokenStr = String(resolvedToken);
        const doClear = Boolean(clear);
        const hasWitness = witness !== undefined && witness !== null;
        if (doClear === hasWitness) {
            throw new Error('pass either --witness <account> or --clear');
        }
        let valueUtf8 = '';
        if (hasWitness) {
            if (typeof witness !== 'string' || witness.length === 0) {
                throw new Error('--witness must be a non-empty Concordium account address');
            }
            const parsed = AccountAddress.fromBase58(witness);
            if (parsed.address !== witness) {
                throw new Error(`--witness ${witness} is not in canonical Base58Check form`);
            }
            valueUtf8 = witness;
        }

        const explicitState = opts.state ?? opts.statePath ?? null;
        const runSetWitness = async () => {
            const nodeInsecure = Boolean(opts.nodeInsecure ?? opts['node-insecure']);
            applyNodeOptions(node, nodeInsecure);
            const who = providedWho ?? loadSigner();
            const c = nodeClient ?? (await client());
            await assertTestnet(c);

            const cs = await withRpcRetry(() => c.getConsensusStatus());
            const tipBlockHash = cs.lastFinalizedBlock;
            const agent = await readAgentOf(tokenStr, { blockHash: tipBlockHash, nodeClient: c });
            if (!agent) throw new Error(`registry token ${tokenStr} is not registered`);
            if (agent.status !== 'Active') {
                throw new Error(`registry token ${tokenStr} status is ${agent.status}`);
            }
            if (who.address !== agent.ownerAccount) {
                throw new Error(
                    `signer ${who.address} must exactly match registered owner ${agent.ownerAccount} (CIS-8004.setMetadata rejects account aliases)`,
                );
            }
            if (!doClear && isSameAccount(valueUtf8, agent.ownerAccount)) {
                throw new Error(`witness account ${valueUtf8} cannot be the same as token owner ${agent.ownerAccount}`);
            }

            const next = await withRpcRetry(() => c.getNextAccountNonce(who.sender));
            if (next.allFinal !== true) {
                throw new Error(`owner ${who.address} has unfinalized transactions (allFinal=${next.allFinal}); retry after finalization`);
            }
            const expectedNonce = BigInt(next.nonce?.value ?? next.nonce);
            const res = await sendSetMetadata(tokenStr, WITNESS_KEY, valueUtf8, who, c, { expectedNonce });
            console.log(
                doClear ? `cleared ${WITNESS_KEY}:` : `set ${WITNESS_KEY} to ${valueUtf8}:`,
                EXPLORER_TX(res.hash),
            );
            return { hash: res.hash, witness: doClear ? null : valueUtf8 };
        };

        if (trail) {
            const { targetTrail, resolvedStatePath, legacyStatePath, trailLock, stateCandidates } =
                resolveTrailStateContext(trail, explicitState);
            return withFileLock(trailLock, async () => {
                if (fs.existsSync(targetTrail)) {
                    const { header } = readTrail(targetTrail);
                    if (String(header.token_id) !== tokenStr) {
                        throw new Error(`trail ${trail} belongs to token ${header.token_id}, not ${tokenStr}`);
                    }
                }
                return withFileLock(tokenLockPath(tokenStr, { tokenLockDir: opts.tokenLockDir }), async () => {
                    assertNoPendingStateFiles(stateCandidates, {
                        legacyStatePath,
                        resolvedStatePath,
                        trail,
                        callerCommand: 'set-witness',
                    });
                    return await runSetWitness();
                });
            });
        }

        return withFileLock(tokenLockPath(tokenStr, { tokenLockDir: opts.tokenLockDir }), async () => {
            if (explicitState !== null) {
                assertNoPendingStateFiles([canonicalTrailPath(explicitState)], { callerCommand: 'set-witness' });
            }
            return await runSetWitness();
        });
    },

    /** Run the standalone x402-paid Countersign witness HTTP service. */
    async witness({ node, nodeClient, ...opts }) {
        const nodeInsecure = Boolean(opts.nodeInsecure ?? opts['node-insecure']);
        applyNodeOptions(node, nodeInsecure);
        const witnessKeyfile = opts.witnessKeyfile ?? opts['witness-keyfile'];
        const ledgerPath = opts.ledger ?? opts.ledgerPath;
        const host = opts.host ?? '127.0.0.1';
        const port = parseOptionalPort(opts.port, '--port') ?? 8787;
        const priceMicroCcd = parseOptionalNonNegativeBigIntStr(
            opts.priceMicroCcd ?? opts['price-micro-ccd'],
            '--price-micro-ccd',
            '1000000',
        );
        const payTo = opts.payTo ?? opts['pay-to'];
        const facilitatorUrl = opts.facilitatorUrl ?? opts['facilitator-url'];
        const sponsorPointer = resolveSponsorPointerOpt(opts, true);
        const allowPrivateCard = Boolean(opts.allowPrivateCard ?? opts['allow-private-card']);
        const allowPrivateFacilitator = Boolean(
            opts.allowPrivateFacilitator ?? opts['allow-private-facilitator'],
        );
        const publicBaseUrl = opts.publicBaseUrl ?? opts['public-base-url'] ?? null;
        const maxQueuedPerToken =
            parseOptionalPositiveInt(
                opts.maxQueuedPerToken ?? opts['max-queued-per-token'],
                '--max-queued-per-token',
            ) ?? 8;

        const handle = await startWitnessServer({
            host,
            port,
            ...(publicBaseUrl ? { publicBaseUrl } : {}),
            maxQueuedPerToken,
            priceMicroCcd,
            payTo,
            sponsorPointer,
            allowPrivateCard,
            allowPrivateFacilitator,
            ledgerPath,
            witnessKeyfile,
            signer: opts.signer,
            nodeClient,
            verifier: opts.verifier,
            facilitatorUrl,
            fetchCard: opts.fetchCard,
            log: opts.log,
        });

        console.log(
            `witness listening on ${handle.url} (account=${handle.witnessAccount}, payTo=${handle.payTo}, price=${handle.priceMicroCcd} microCCD, sponsorPointer=${handle.sponsorPointer})`,
        );

        let closing = false;
        const shutdown = async () => {
            if (closing) return;
            closing = true;
            process.off('SIGINT', onSig);
            process.off('SIGTERM', onSig);
            await handle.close();
        };
        const onSig = () => {
            shutdown().catch((e) => {
                console.error('error closing witness:', e.message);
                process.exit(1);
            });
        };
        process.on('SIGINT', onSig);
        process.on('SIGTERM', onSig);

        const origClose = handle.close;
        handle.close = async () => {
            process.off('SIGINT', onSig);
            process.off('SIGTERM', onSig);
            await origClose();
        };
        return handle;
    },

    /** Anyone: check a badge and a trail file directly against a Concordium testnet node. Needs no keys. */
    async verify({ badge, trail, card, node, nodeClient, fetchCard = fetchAgentCard, ...opts }) {
        process.exitCode = 1; // only a completed, fully passing run resets this
        const nodeInsecure = Boolean(opts.nodeInsecure ?? opts['node-insecure']);
        const allowPrivate = Boolean(opts.allowPrivateCard ?? opts['allow-private-card']);
        const requireWitness = Boolean(opts.requireWitness ?? opts['require-witness']);
        const expectedWitness = opts.witness !== undefined && opts.witness !== null ? String(opts.witness) : null;
        applyNodeOptions(node, nodeInsecure);
        const checks = [];
        let covered = 0;
        const check = (name, ok, detail = '') => {
            checks.push(ok);
            console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  ' + detail : ''}`);
            return ok;
        };

        if (expectedWitness !== null) {
            try {
                const parsedWitness = AccountAddress.fromBase58(expectedWitness);
                if (parsedWitness.address !== expectedWitness) {
                    throw new Error('not in canonical Base58Check form');
                }
            } catch (e) {
                check('witness flag is a canonical Concordium account address', false, e.message);
                return finish(checks);
            }
        }

        let header, records;
        try {
            ({ header, records } = readTrail(trail));
        } catch (e) {
            check('trail file is in canonical form', false, e.message);
            return finish(checks);
        }

        let parsed;
        try {
            parsed = decodeBadge(badge);
        } catch (e) {
            check('badge resolves to the trusted testnet registry', false, e.message);
            return finish(checks);
        }
        const tokenId = parsed.tokenId;
        const onTrustedRegistry = parsed.contract.index === REGISTRY.index && parsed.contract.subindex === REGISTRY.subindex;
        if (!check('badge resolves to the trusted testnet registry', onTrustedRegistry, `<${parsed.contract.index},${parsed.contract.subindex}> token ${tokenId}`)) return finish(checks);

        const c = nodeClient ?? (await client());
        await assertTestnet(c);
        const cs = await withRpcRetry(() => c.getConsensusStatus());
        const tipBlockHash = cs.lastFinalizedBlock;
        const tipBlockHeight = cs.lastFinalizedBlockHeight;

        const agent = await readAgentOf(tokenId, { blockHash: tipBlockHash, nodeClient: c });
        if (!agent) {
            check('badge check (registered, active, card matches on-chain hash)', false, `token ${tokenId} is not registered`);
            return finish(checks);
        }

        let badgeOk = false;
        let badgeDetail = '';
        try {
            if (agent.status !== 'Active') throw new Error(`agent status is ${agent.status}`);
            if (!agent.metadataHashHex) throw new Error('on-chain metadata_hash is not set');
            let cardBytes;
            let sourceLabel;
            if (card) {
                cardBytes = fs.readFileSync(card);
                sourceLabel = card;
            } else {
                if (!agent.agentUri) throw new Error('on-chain agent_uri is not set');
                cardBytes = await fetchCard(agent.agentUri, { allowPrivate });
                sourceLabel = agent.agentUri;
            }
            verifyAgentCardBytes(cardBytes, {
                badge,
                ownerAccount: agent.ownerAccount,
                metadataHashHex: agent.metadataHashHex,
                registry: REGISTRY,
                genesisPrefix: TESTNET_GENESIS.slice(0, 32),
            });
            badgeOk = true;
            badgeDetail = `Active, card verified (${sourceLabel})`;
        } catch (e) {
            badgeDetail = e.message;
        }
        check('badge check (registered, active, card matches on-chain hash)', badgeOk, badgeDetail);

        const owner = agent.ownerAccount;
        const r = header.registry ?? {};
        check('trail header names this registry token', header.token_id === tokenId && r.network === NETWORK && r.index === REGISTRY.index && r.subindex === REGISTRY.subindex);

        const onChainUuid = await readMetadataText(tokenId, UUID_KEY, { blockHash: tipBlockHash, nodeClient: c });
        check('on-chain metadata names the same UNITARES agent as the trail', UUID_RE.test(onChainUuid ?? '') && onChainUuid === header.agent_uuid, onChainUuid ?? 'not set');

        const current = await readMetadataText(tokenId, ANCHOR_KEY, { blockHash: tipBlockHash, nodeClient: c });
        if (current !== null && !TX_RE.test(current)) {
            check('registry entry points at an anchor', false, `metadata ${ANCHOR_KEY} is not a transaction hash`);
            return finish(checks);
        }
        if (!check('registry entry points at an anchor', Boolean(current))) return finish(checks);

        // Check every anchor the entry has ever pointed at, reconstructed directly from the node's block events.
        // Otherwise the owner could repoint the entry at a fresh anchor over an edited trail.
        let history;
        try {
            history = await readRegistryHistory(tokenId, {
                tipBlockHash,
                tipBlockHeight,
                agent,
                hintAnchorTxHashes: [current],
                nodeClient: c,
            });
        } catch (e) {
            check('on-chain ownership and event history are intact since registration', false, e.message);
            return finish(checks);
        }
        check('on-chain ownership and event history are intact since registration', true, `reg block ${history.regHeight}, ${history.scannedBlocks} owner tx block(s)`);

        const onChainWitness = await readMetadataText(tokenId, WITNESS_KEY, { blockHash: tipBlockHash, nodeClient: c });
        let witnessState;
        try {
            witnessState = extractWitnessState(history);
        } catch (e) {
            check('on-chain witness metadata matches reconstructed witness history', false, e.message);
            return finish(checks);
        }
        if (!witnessMatchesOnChain(witnessState, onChainWitness)) {
            check(
                'on-chain witness metadata matches reconstructed witness history',
                false,
                `on-chain ${onChainWitness ?? 'null'} !== history ${witnessState.currentWitness ?? 'null'}`,
            );
            return finish(checks);
        }
        if (witnessState.sawWitnessEvent) {
            check('on-chain witness metadata matches reconstructed witness history', true, onChainWitness ?? 'cleared');
        }

        let anchors;
        try {
            anchors = await loadAnchorsFromHistory(history, c, tipBlockHeight);
        } catch (e) {
            check('every pointer the entry has held is an anchor transaction', false, e.message);
            return finish(checks);
        }
        check('the current pointer is the last one in the registry event history', anchors.at(-1)?.txHash === current, `${anchors.length} pointer updates`);
        const senderLabel = witnessState.sawWitnessEvent
            ? 'every anchor was sent by the authorized signer (owner or active witness)'
            : 'every anchor was sent by the registry entry owner';
        check(
            senderLabel,
            Boolean(owner) && anchors.every((a) => isSameAccount(a.sender, a.authorizedWitness ?? owner)),
            witnessState.currentWitness ? `owner ${owner}, witness ${witnessState.currentWitness}` : owner,
        );
        if (requireWitness) {
            const latest = anchors.at(-1);
            const ok =
                witnessState.currentWitness !== null &&
                Boolean(latest?.authorizedWitness) &&
                isSameAccount(latest.sender, witnessState.currentWitness);
            check('latest anchor was countersigned by active witness', ok, witnessState.currentWitness ?? 'none');
        }
        if (expectedWitness !== null) {
            const latest = anchors.at(-1);
            const ok =
                witnessState.currentWitness !== null &&
                isSameAccount(witnessState.currentWitness, expectedWitness) &&
                Boolean(latest?.authorizedWitness) &&
                isSameAccount(latest.sender, expectedWitness);
            check(`latest anchor was countersigned by witness ${expectedWitness}`, ok, witnessState.currentWitness ?? 'none');
        }
        check('every anchor names this registry token', anchors.every((a) => a.tokenId === tokenId));
        check('anchors form one unbroken chain (each names the one before it, none was skipped or replaced)', chainIsUnbroken(anchors));
        check('each anchor covers more records than the one before', coverageGrows(anchors));

        let computed;
        try {
            computed = commitments(header, records, new Set(anchors.map((a) => a.toSeq)));
        } catch (e) {
            check('trail is well formed', false, e.message);
            return finish(checks);
        }
        for (const a of anchors) {
            const got = computed.at.get(a.toSeq)?.toString('hex');
            check(`records 1..${a.toSeq} match the commitment anchored ${a.blockTime}`, got === a.commitment, got ? EXPLORER_TX(a.txHash) : `trail has only ${computed.count} records`);
        }
        covered = anchors.at(-1)?.toSeq ?? 0;
        if (computed.count > covered) console.log(`note  records ${covered + 1}..${computed.count} are newer than the latest anchor and are not covered by it`);
        return finish(checks, covered);
    },

    /** Operator side: stream core.checkpoint_outbox checkpoints into a trail and anchor automatically on threshold. */
    async watch({ uuid, token, tokenId, trail, trailPath, state, statePath, psql, node, nodeClient, ...opts }) {
        const resolvedUuid = uuid;
        const resolvedToken = token ?? tokenId;
        const resolvedTrail = trail ?? trailPath;
        if (!UUID_RE.test(resolvedUuid ?? '')) throw new Error('--uuid <agent uuid> is required');
        if (!/^[0-9]+$/.test(resolvedToken !== undefined && resolvedToken !== null ? String(resolvedToken) : '')) {
            throw new Error('--token <id> is required');
        }
        if (!resolvedTrail) throw new Error('--trail <path> is required');

        const everyRecords = parseOptionalPositiveInt(opts.everyRecords ?? opts['every-records'], '--every-records');
        const everySeconds = parseOptionalPositiveNumber(opts.everySeconds ?? opts['every-seconds'], '--every-seconds', null);
        const pollSeconds = parseOptionalPositiveNumber(opts.pollSeconds ?? opts['poll-seconds'], '--poll-seconds', 15);
        const maxBackoffSeconds = parseOptionalPositiveNumber(
            opts.maxBackoffSeconds ?? opts['max-backoff-seconds'],
            '--max-backoff-seconds',
            300,
        );
        const psqlTimeoutMs = parseOptionalPositiveInt(
            opts.psqlTimeoutMs ?? opts['psql-timeout-ms'] ?? opts['psql-timeout'],
            '--psql-timeout',
        );
        const psqlBatchSize = parseOptionalPositiveInt(opts.batchSize ?? opts['psql-batch-size'], '--psql-batch-size');
        const once = Boolean(opts.once);
        const dryRun = Boolean(opts.dryRun ?? opts['dry-run']);
        const nodeInsecure = Boolean(opts.nodeInsecure ?? opts['node-insecure']);
        const witnessUrl = opts.witnessUrl ?? opts['witness-url'] ?? null;
        const allowPrivateWitness = Boolean(opts.allowPrivateWitness ?? opts['allow-private-witness']);
        const sponsorPointer = resolveSponsorPointerOpt(opts, true);
        const maxPriceMicroCcd = parseOptionalNonNegativeBigIntStr(
            opts.maxPriceMicroCcd ?? opts['max-price-micro-ccd'],
            '--max-price-micro-ccd',
            null,
        );
        const paymentSignature = opts.paymentSignature ?? opts['payment-signature'] ?? null;
        const payerKeyfile =
            opts.payerKeyfile ?? opts['payer-keyfile'] ?? opts.paymentKeyfile ?? opts['payment-keyfile'] ?? null;

        const ac = new AbortController();
        const externalSignal = opts.signal;
        const onExternalAbort = () => ac.abort();
        if (externalSignal) {
            if (externalSignal.aborted) ac.abort();
            else externalSignal.addEventListener('abort', onExternalAbort, { once: true });
        }
        let sigCount = 0;
        const onSignal = (sig) => {
            sigCount += 1;
            if (sigCount === 1) {
                ac.abort();
                return;
            }
            process.exit(sig === 'SIGTERM' ? 143 : 130);
        };
        process.on('SIGINT', onSignal);
        process.on('SIGTERM', onSignal);

        try {
            return await runAnchorWorker({
                uuid: resolvedUuid,
                tokenId: String(resolvedToken),
                trailPath: resolvedTrail,
                statePath: state ?? statePath,
                ...(opts.tokenLockDir ? { tokenLockDir: opts.tokenLockDir } : {}),
                psql,
                ...(psqlTimeoutMs ? { psqlTimeoutMs } : {}),
                ...(psqlBatchSize ? { psqlBatchSize } : {}),
                everyRecords,
                everySeconds,
                pollSeconds,
                maxBackoffSeconds,
                once,
                dryRun,
                node,
                nodeInsecure,
                nodeClient,
                signer: opts.signer ?? opts.who ?? null,
                ...(opts.loadSignerFn ? { loadSignerFn: opts.loadSignerFn } : {}),
                witnessUrl,
                allowPrivateWitness,
                sponsorPointer,
                ...(maxPriceMicroCcd !== null ? { maxPriceMicroCcd } : {}),
                paymentSignature,
                payerKeyfile,
                ...(opts.payFn ? { payFn: opts.payFn } : {}),
                ...(opts.payerSigner ? { payerSigner: opts.payerSigner } : {}),
                ...(opts.fetchWitnessHealthFn ? { fetchWitnessHealthFn: opts.fetchWitnessHealthFn } : {}),
                ...(opts.requestWitnessAnchorFn ? { requestWitnessAnchorFn: opts.requestWitnessAnchorFn } : {}),
                ...(opts.requestSponsoredPointerFn ? { requestSponsoredPointerFn: opts.requestSponsoredPointerFn } : {}),
                ...(opts.buildSponsoredSetMetadataFn ? { buildSponsoredSetMetadataFn: opts.buildSponsoredSetMetadataFn } : {}),
                source: opts.source,
                submitAnchor: opts.submitAnchor,
                setMetadata: opts.setMetadata,
                now: opts.now,
                wallClock: opts.wallClock,
                sleep: opts.sleep,
                ...(opts.random ? { random: opts.random } : {}),
                log: opts.log,
                signal: ac.signal,
            });
        } finally {
            process.off('SIGINT', onSignal);
            process.off('SIGTERM', onSignal);
            if (externalSignal) externalSignal.removeEventListener('abort', onExternalAbort);
        }
    },
};

function finish(checks, covered = 0) {
    const ok = checks.length > 0 && checks.every(Boolean) && covered > 0;
    console.log(ok ? `\nVERIFIED: records 1..${covered} match what was anchored.` : '\nNOT VERIFIED.');
    process.exitCode = ok ? 0 : 1;
    return ok;
}

function isMainEntry() {
    if (!process.argv[1]) return false;
    try {
        return fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url));
    } catch {
        return false;
    }
}

if (isMainEntry()) {
    const [name, ...rest] = process.argv.slice(2);
    if (!commands[name]) {
        console.log(`usage: countersign <${Object.keys(commands).join(' | ')}> [--options]`);
        process.exit(name ? 2 : 0);
    }
    const stringOpts = [
        'uuid',
        'token',
        'name',
        'description',
        'url',
        'out',
        'file',
        'trail',
        'state',
        'badge',
        'psql',
        'tx',
        'node',
        'card',
        'witness',
        'witness-keyfile',
        'witness-url',
        'ledger',
        'host',
        'port',
        'price-micro-ccd',
        'max-price-micro-ccd',
        'pay-to',
        'public-base-url',
        'max-queued-per-token',
        'facilitator-url',
        'payment-signature',
        'payer-keyfile',
        'payment-keyfile',
        'every-records',
        'every-seconds',
        'poll-seconds',
        'max-backoff-seconds',
        'psql-timeout',
        'psql-batch-size',
    ];
    const boolOpts = [
        'node-insecure',
        'allow-private-card',
        'allow-private-witness',
        'allow-private-facilitator',
        'once',
        'dry-run',
        'clear',
        'require-witness',
        'sponsor-pointer',
        'no-sponsor-pointer',
    ];
    const { values } = parseArgs({
        args: rest,
        options: {
            ...Object.fromEntries(stringOpts.map((k) => [k, { type: 'string' }])),
            ...Object.fromEntries(boolOpts.map((k) => [k, { type: 'boolean' }])),
        },
    });
    commands[name](values).catch((e) => {
        console.error('error:', e.message);
        process.exit(1);
    });
}
