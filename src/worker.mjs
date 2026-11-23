// Crash-safe, stream-driven automatic anchoring worker for Countersign.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
    ANCHOR_KEY,
    EXPLORER_TX,
    TX_RE,
    UUID_KEY,
    WITNESS_KEY,
    applyNodeOptions,
    assertTestnet,
    buildSignedSponsoredSetMetadata,
    client,
    extractWitnessState,
    getTransactionState,
    isSameAccount,
    loadAnchorsFromHistory,
    loadSigner,
    loadSignerFromFile,
    readAgentOf,
    readMetadataText,
    readRegisterData,
    readRegistryHistory,
    sendRegisterData,
    sendSetMetadata,
    sendTransferWithMemo,
    verifyExistingAnchors,
    waitForFinalizedPolling,
    withRpcRetry,
    witnessMatchesOnChain,
    writeFileAtomic,
} from './chain.mjs';
import { UUID_RE, fetchCheckpointsAfter } from './checkpoints.mjs';
import { NETWORK, REGISTRY } from './registry.mjs';
import {
    SCHEMA,
    canonical,
    checkHeader,
    checkRecord,
    commitments,
    decodeAnchor,
    encodeAnchor,
    genesisHash,
    parseTrailBuffer,
    readTrail,
    serializeTrail,
    stepHash,
} from './trail.mjs';
import {
    X402_VERSION,
    encodeX402Header,
    fetchWitnessHealth,
    requestSponsoredPointer,
    requestWitnessAnchor,
} from './x402.mjs';

export { writeFileAtomic };

function isPidAlive(pid) {
    try {
        process.kill(pid, 0);
        return true;
    } catch (err) {
        if (err && err.code === 'EPERM') return true;
        if (err && err.code === 'ESRCH') return false;
        throw err;
    }
}

/** Resolves the canonical filesystem path for a trail file even before the file or leaf directories exist. */
export function canonicalTrailPath(trailPath) {
    const abs = path.resolve(trailPath);
    let cur = abs;
    const suffix = [];
    while (!fs.existsSync(cur)) {
        const parent = path.dirname(cur);
        if (parent === cur) break;
        suffix.unshift(path.basename(cur));
        cur = parent;
    }
    const realBase = fs.existsSync(cur) ? fs.realpathSync(cur) : cur;
    return suffix.length > 0 ? path.join(realBase, ...suffix) : realBase;
}

/** Returns the canonical exclusive lockfile path derived from the canonical trail file path. */
export function trailLockPath(trailPath) {
    return `${canonicalTrailPath(trailPath)}.lock`;
}

/** Resolves the canonical anchor-state path for a trail file and optional override. */
export function canonicalStatePath(trailPath, statePath) {
    const canonicalTrail = canonicalTrailPath(trailPath);
    return statePath ? canonicalTrailPath(statePath) : `${canonicalTrail}.anchor-state.json`;
}

/** Returns the per-token exclusive lockfile path under COUNTERSIGN_LOCK_DIR or ~/.config/countersign/locks. */
export function tokenLockPath(tokenId, opts = {}) {
    const tokenStr = tokenId === undefined || tokenId === null ? '' : String(tokenId);
    if (!/^[0-9]+$/.test(tokenStr)) {
        throw new Error(`invalid tokenId for tokenLockPath: ${tokenId}`);
    }
    const lockDir = opts.tokenLockDir ?? process.env.COUNTERSIGN_LOCK_DIR ?? path.join(os.homedir(), '.config', 'countersign', 'locks');
    fs.mkdirSync(lockDir, { mode: 0o700, recursive: true });
    return path.join(canonicalTrailPath(lockDir), `token-${REGISTRY.index}-${REGISTRY.subindex}-${tokenStr}.lock`);
}

/** Resolves parent directories canonically while preserving the leaf filename (safe for leaf symlinks). */
export function canonicalParentFilePath(filePath) {
    const abs = path.resolve(filePath);
    return path.join(canonicalTrailPath(path.dirname(abs)), path.basename(abs));
}

/** Resolves any legacy non-canonical sidecar path beside a symlinked trail when statePath is omitted. */
export function legacySidecarPath(trailPath, resolvedCanonicalStatePath) {
    const absTrail = path.resolve(trailPath);
    const cand = canonicalParentFilePath(`${absTrail}.anchor-state.json`);
    return cand !== canonicalParentFilePath(resolvedCanonicalStatePath) ? cand : null;
}

/** Returns the existing file mode for a trail file, or 0o600 for a newly created trail. */
export function trailFileMode(filePath) {
    try {
        return fs.statSync(filePath).mode & 0o777;
    } catch (err) {
        if (err?.code === 'ENOENT') return 0o600;
        throw err;
    }
}

function assertDistinctPaths(entries) {
    for (let i = 0; i < entries.length; i += 1) {
        for (let j = i + 1; j < entries.length; j += 1) {
            const [labelA, pathA] = entries[i];
            const [labelB, pathB] = entries[j];
            if (pathA === pathB) {
                throw new Error(`${labelA} (${pathA}) must not collide with ${labelB}`);
            }
            if (fs.existsSync(pathA) && fs.existsSync(pathB)) {
                const stA = fs.statSync(pathA);
                const stB = fs.statSync(pathB);
                if (stA.dev === stB.dev && stA.ino === stB.ino) {
                    throw new Error(`${labelA} (${pathA}) and ${labelB} (${pathB}) resolve to the same file inode`);
                }
            }
        }
    }
}

function acquireTakeoverDir(takeoverDir, staleMs) {
    try {
        fs.mkdirSync(takeoverDir);
        return;
    } catch (err) {
        if (err?.code !== 'EEXIST') throw err;
    }
    let st;
    try {
        st = fs.statSync(takeoverDir);
    } catch (err) {
        if (err?.code === 'ENOENT') {
            fs.mkdirSync(takeoverDir);
            return;
        }
        throw err;
    }
    if (Date.now() - st.mtimeMs > staleMs) {
        try {
            fs.rmdirSync(takeoverDir);
        } catch (rmErr) {
            if (rmErr?.code !== 'ENOENT') throw rmErr;
        }
        fs.mkdirSync(takeoverDir);
        return;
    }
    throw new Error(`stale lock takeover already in progress (${takeoverDir})`);
}

function writeLockTempFile(lockPath, lockBody) {
    const dir = path.dirname(lockPath);
    const tmpPath = path.join(dir, `.${path.basename(lockPath)}.tmp.${process.pid}.${crypto.randomUUID()}`);
    const fd = fs.openSync(tmpPath, 'w', 0o600);
    try {
        const buf = Buffer.from(lockBody, 'utf8');
        let offset = 0;
        while (offset < buf.length) {
            offset += fs.writeSync(fd, buf, offset, buf.length - offset);
        }
        fs.fchmodSync(fd, 0o600);
        fs.fsyncSync(fd);
    } catch (err) {
        try {
            fs.closeSync(fd);
        } catch {}
        try {
            fs.unlinkSync(tmpPath);
        } catch {}
        throw err;
    }
    fs.closeSync(fd);
    return tmpPath;
}

/**
 * Acquires an exclusive lockfile via fsynced temp file + atomic linkSync publish and mutually
 * exclusive stale-PID takeover, returning an idempotent async release function.
 */
export async function acquireFileLock(
    lockPath,
    { wallClock = () => new Date(), hostname = os.hostname(), takeoverStaleMs = 10_000 } = {},
) {
    fs.mkdirSync(path.dirname(lockPath), { recursive: true });
    const lockBody =
        JSON.stringify({
            pid: process.pid,
            host: hostname,
            startedAt: wallClock().toISOString(),
            token: crypto.randomUUID(),
        }) + '\n';

    const tmpPath = writeLockTempFile(lockPath, lockBody);

    const tryPublish = () => {
        fs.linkSync(tmpPath, lockPath);
    };

    const acquire = () => {
        try {
            tryPublish();
            return lockBody;
        } catch (err) {
            if (err?.code !== 'EEXIST') throw err;
        }

        let raw;
        try {
            raw = fs.readFileSync(lockPath, 'utf8');
        } catch (err) {
            if (err?.code === 'ENOENT') {
                try {
                    tryPublish();
                    return lockBody;
                } catch (retryErr) {
                    if (retryErr?.code === 'EEXIST') {
                        throw new Error(`lockfile ${lockPath} is held by another worker`);
                    }
                    throw retryErr;
                }
            }
            throw err;
        }

        let existing;
        try {
            existing = JSON.parse(raw);
        } catch {
            throw new Error(`corrupt lockfile ${lockPath}; remove manually if no worker is running`);
        }
        const pid = existing?.pid;
        if (!Number.isInteger(pid) || pid <= 0) {
            throw new Error(`invalid pid in lockfile ${lockPath}`);
        }
        if (existing.host && existing.host !== hostname) {
            throw new Error(`lockfile ${lockPath} is held by host ${existing.host} (pid ${pid})`);
        }
        if (isPidAlive(pid)) {
            throw new Error(`lockfile ${lockPath} is already held by active process ${pid}`);
        }

        const takeoverDir = `${lockPath}.takeover`;
        acquireTakeoverDir(takeoverDir, takeoverStaleMs);
        try {
            let currentRaw;
            try {
                currentRaw = fs.readFileSync(lockPath, 'utf8');
            } catch (err) {
                if (err?.code === 'ENOENT') {
                    try {
                        tryPublish();
                    } catch (linkErr) {
                        if (linkErr?.code === 'EEXIST') {
                            throw new Error(`lockfile ${lockPath} was claimed concurrently`);
                        }
                        throw linkErr;
                    }
                    if (fs.readFileSync(lockPath, 'utf8') !== lockBody) {
                        throw new Error(`lockfile ${lockPath} was claimed concurrently`);
                    }
                    return lockBody;
                }
                throw err;
            }
            if (currentRaw !== raw) {
                throw new Error(`lockfile ${lockPath} changed during stale takeover`);
            }
            if (isPidAlive(pid)) {
                throw new Error(`lockfile ${lockPath} is already held by active process ${pid}`);
            }
            try {
                fs.unlinkSync(lockPath);
            } catch (err) {
                if (err?.code !== 'ENOENT') throw err;
            }
            try {
                tryPublish();
            } catch (err) {
                if (err?.code === 'EEXIST') {
                    throw new Error(`lockfile ${lockPath} is held by another worker`);
                }
                throw err;
            }
            if (fs.readFileSync(lockPath, 'utf8') !== lockBody) {
                throw new Error(`lockfile ${lockPath} was claimed concurrently`);
            }
            return lockBody;
        } finally {
            try {
                fs.rmdirSync(takeoverDir);
            } catch (err) {
                if (err?.code !== 'ENOENT') throw err;
            }
        }
    };

    let acquired;
    try {
        acquired = acquire();
    } finally {
        try {
            fs.unlinkSync(tmpPath);
        } catch (err) {
            if (err?.code !== 'ENOENT') throw err;
        }
    }

    let released = false;
    return async () => {
        if (released) return;
        released = true;
        try {
            if (fs.readFileSync(lockPath, 'utf8') === acquired) {
                fs.unlinkSync(lockPath);
            }
        } catch (err) {
            if (err?.code !== 'ENOENT') throw err;
        }
    };
}

/**
 * Acquires an exclusive lockfile via `acquireFileLock`, running `fn` and releasing in `finally`.
 */
export async function withFileLock(
    lockPath,
    fn,
    opts = {},
) {
    const release = await acquireFileLock(lockPath, opts);
    try {
        return await fn();
    } finally {
        await release();
    }
}

/**
 * Returns true if `sender` was authorized at some block in `[max(regHeight, prevBlockHeight), rdBlockHeight]`,
 * preventing later witness appointments from validating earlier transactions while still recognizing in-flight
 * transactions finalized shortly after revocation.
 */
function wasSignerAuthorizedInWindow({
    sender,
    rdBlockHeight,
    ownerAccount,
    regHeight,
    transitions = [],
}) {
    const rdH = BigInt(rdBlockHeight);
    const minH = BigInt(regHeight);
    if (rdH < minH) return false;
    let active = null;
    for (const t of transitions) {
        if (BigInt(t.blockHeight) <= minH) {
            active = t.witness;
        }
    }
    const authorized = [active ?? ownerAccount];
    for (const t of transitions) {
        const th = BigInt(t.blockHeight);
        if (th > minH && th <= rdH) {
            active = t.witness;
            authorized.push(active ?? ownerAccount);
        }
    }
    return authorized.some((acct) => isSameAccount(sender, acct));
}

/** Pure policy predicate determining whether unanchored records meet record-count or monotonic time thresholds. */
export function shouldAnchor({ localSeq, anchoredSeq, lastAnchorMs, nowMs, everyRecords, everySeconds }) {
    if (localSeq <= anchoredSeq) return false;
    if (everyRecords !== null && everyRecords !== undefined && localSeq - anchoredSeq >= everyRecords) {
        return true;
    }
    if (everySeconds !== null && everySeconds !== undefined) {
        if (lastAnchorMs === null || lastAnchorMs === undefined) return true;
        if (nowMs - lastAnchorMs >= everySeconds * 1000) return true;
    }
    return false;
}

function defaultSubmitAnchor({ data, signer, nodeClient, onSigned, expectedNonce }) {
    const pollOpts = {};
    if (onSigned) pollOpts.onSigned = onSigned;
    if (expectedNonce !== undefined) pollOpts.expectedNonce = expectedNonce;
    return sendRegisterData(data, signer, nodeClient, Object.keys(pollOpts).length > 0 ? pollOpts : undefined).then((res) => ({
        txHash: res.hash,
        sender: signer.address,
    }));
}

function validateEveryRecords(val) {
    if (val === undefined || val === null) return null;
    if (!Number.isSafeInteger(val) || val <= 0) {
        throw new Error(`everyRecords must be a positive safe integer or null, got ${val}`);
    }
    return val;
}

function validatePositiveNumber(val, name, allowNull = false) {
    if (allowNull && (val === undefined || val === null)) return null;
    if (typeof val !== 'number' || !Number.isFinite(val) || val <= 0) {
        throw new Error(`${name} must be a positive finite number, got ${val}`);
    }
    return val;
}

function isTxRefObj(v) {
    if (v === null || typeof v !== 'object' || Array.isArray(v)) return false;
    if (v.mode === 'sponsored') {
        return (
            typeof v.sponsorUrl === 'string' &&
            v.sponsorUrl.length > 0 &&
            (v.txHash === null || TX_RE.test(v.txHash ?? '')) &&
            typeof v.expiryEpochSeconds === 'number' &&
            Number.isFinite(v.expiryEpochSeconds) &&
            v.expiryEpochSeconds >= 0 &&
            (v.nonce === undefined || (Number.isSafeInteger(v.nonce) && v.nonce >= 0))
        );
    }
    if (v.mode !== undefined && v.mode !== 'direct') return false;
    return (
        TX_RE.test(v.txHash ?? '') &&
        (v.expiryEpochSeconds === undefined ||
            v.expiryEpochSeconds === null ||
            (typeof v.expiryEpochSeconds === 'number' && Number.isFinite(v.expiryEpochSeconds) && v.expiryEpochSeconds >= 0))
    );
}

/**
 * Verifies a witness-submitted `registerData` transaction directly on-chain before committing
 * local pendingAnchor state or updating `countersign.anchor`.
 */
export async function verifyWitnessAnchorOnChain({
    nodeClient,
    txHash,
    activeWitness,
    tokenId,
    toSeq,
    commitmentHex,
    prevAnchorTx,
}) {
    if (!TX_RE.test(txHash ?? '')) {
        throw new Error(`witness returned invalid txHash: ${txHash}`);
    }
    const rd = await readRegisterData(txHash, nodeClient);
    if (!isSameAccount(rd.sender, activeWitness)) {
        throw new Error(
            `witness registerData tx ${txHash} sender ${rd.sender} does not match active countersign.witness ${activeWitness}`,
        );
    }
    const decoded = decodeAnchor(rd.data);
    if (
        decoded.tokenId !== String(tokenId) ||
        decoded.toSeq !== toSeq ||
        decoded.commitment !== commitmentHex ||
        decoded.prevAnchorTx !== prevAnchorTx
    ) {
        throw new Error(
            `witness registerData tx ${txHash} payload (${JSON.stringify(decoded)}) does not match expected anchor (tokenId=${tokenId}, toSeq=${toSeq}, commitment=${commitmentHex}, prevAnchorTx=${prevAnchorTx})`,
        );
    }
    return { rd, decoded };
}

/**
 * Pins one finalized block (`setTipHash`), re-verifies token active status, unchanged owner,
 * `countersign.anchor === expectedPrevTx`, and `countersign.witness` alignment, then derives
 * `expectedSetNonce` for `signerSender` from that same finalized block.
 */
export async function preparePointerUpdateAtTip({
    nodeClient,
    tokenId,
    signerSender,
    expectedPrevTx,
    expectedOwnerAccount,
    expectedActiveWitness = null,
}) {
    const cs = await withRpcRetry(() => nodeClient.getConsensusStatus());
    const setTipHash = cs.lastFinalizedBlock;
    const setAgent = await readAgentOf(tokenId, { blockHash: setTipHash, nodeClient });
    if (!setAgent) {
        throw new Error(`registry token ${tokenId} is not registered`);
    }
    if (setAgent.status !== 'Active') {
        throw new Error(
            `registry token ${tokenId} status is ${setAgent.status ?? 'unknown'}; refusing pointer update`,
        );
    }
    if (setAgent.ownerAccount !== expectedOwnerAccount) {
        throw new Error(
            `registry token ${tokenId} owner changed from ${expectedOwnerAccount} to ${setAgent.ownerAccount}; refusing pointer update`,
        );
    }
    const latestBeforeSet = await readMetadataText(tokenId, ANCHOR_KEY, {
        blockHash: setTipHash,
        nodeClient,
    });
    if (latestBeforeSet !== expectedPrevTx) {
        throw new Error('countersign.anchor moved concurrently; refusing to overwrite pointer');
    }
    const onChainWitnessAtSet = await readMetadataText(tokenId, WITNESS_KEY, {
        blockHash: setTipHash,
        nodeClient,
    });
    if (!witnessMatchesOnChain({ currentWitness: expectedActiveWitness }, onChainWitnessAtSet)) {
        throw new Error(
            `countersign.witness changed concurrently (expected ${expectedActiveWitness ?? 'none'}, got ${onChainWitnessAtSet ?? 'none'}); refusing pointer update`,
        );
    }
    const accForSet = await withRpcRetry(() => nodeClient.getAccountInfo(signerSender, setTipHash));
    return {
        setTipHash,
        agent: setAgent,
        onChainWitness: onChainWitnessAtSet,
        expectedSetNonce: BigInt(accForSet.accountNonce.value),
    };
}

function normalizeWitnessBaseUrl(urlStr) {
    return String(urlStr).trim().replace(/\/+$/, '');
}

/**
 * Stream-driven worker that incrementally syncs UNITARES checkpoints into a canonical trail file
 * and submits crash-recoverable Concordium testnet anchors when configured thresholds are reached.
 */
export class AnchorWorker {
    constructor(opts = {}) {
        const {
            uuid,
            tokenId,
            trailPath,
            statePath,
            lockPath,
            tokenLockDir,
            psql,
            psqlTimeoutMs = 30000,
            psqlBatchSize = 5000,
            everyRecords = null,
            everySeconds = null,
            pollSeconds = 15,
            maxBackoffSeconds = 300,
            dryRun = false,
            once = false,
            node,
            nodeInsecure = false,
            nodeClient = null,
            signer = null,
            loadSignerFn = loadSigner,
            source,
            submitAnchor = defaultSubmitAnchor,
            setMetadata = sendSetMetadata,
            witnessUrl = null,
            allowPrivateWitness = false,
            sponsorPointer,
            maxPriceMicroCcd = null,
            paymentSignature = null,
            payFn = null,
            payerSigner = null,
            payerKeyfile = null,
            fetchWitnessHealthFn = fetchWitnessHealth,
            requestWitnessAnchorFn = requestWitnessAnchor,
            requestSponsoredPointerFn = requestSponsoredPointer,
            buildSponsoredSetMetadataFn = buildSignedSponsoredSetMetadata,
            now = () => performance.now(),
            wallClock = () => new Date(),
            sleep,
            random = Math.random,
            log = console.log,
            signal,
        } = opts;

        if (typeof uuid !== 'string' || !UUID_RE.test(uuid)) {
            throw new Error(`invalid agent UUID: ${uuid}`);
        }
        const tokenStr = tokenId === undefined || tokenId === null ? '' : String(tokenId);
        if (!/^[0-9]+$/.test(tokenStr) || BigInt(tokenStr) > 0xffffffffffffffffn) {
            throw new Error(`invalid tokenId: ${tokenId}`);
        }
        if (typeof trailPath !== 'string' || trailPath.trim().length === 0) {
            throw new Error('trailPath must be a non-empty string');
        }

        this.uuid = uuid;
        this.tokenId = tokenStr;
        const canonicalTrail = canonicalTrailPath(trailPath);
        this.trailPath = canonicalTrail;
        this.statePath = canonicalStatePath(canonicalTrail, statePath);
        this.legacyStatePath = null;
        if (statePath === undefined || statePath === null) {
            this.legacyStatePath = legacySidecarPath(trailPath, this.statePath);
        }
        this.lockPath = lockPath ? canonicalTrailPath(lockPath) : trailLockPath(canonicalTrail);
        this.tokenLockPath = tokenLockPath(this.tokenId, { tokenLockDir });
        assertDistinctPaths([
            ['trailPath', this.trailPath],
            ['statePath', this.statePath],
            ['lockPath', this.lockPath],
            ['tokenLockPath', this.tokenLockPath],
        ]);
        if (this.legacyStatePath) {
            assertDistinctPaths([
                ['trailPath', this.trailPath],
                ['legacyStatePath', this.legacyStatePath],
                ['lockPath', this.lockPath],
                ['tokenLockPath', this.tokenLockPath],
            ]);
        }

        this.psql = psql;
        this.psqlTimeoutMs = psqlTimeoutMs;
        this.psqlBatchSize = psqlBatchSize;
        this.everyRecords = validateEveryRecords(everyRecords);
        this.everySeconds = validatePositiveNumber(everySeconds, 'everySeconds', true);
        this.once = Boolean(once);
        if (!this.once && this.everyRecords === null && this.everySeconds === null) {
            throw new Error('at least one of everyRecords or everySeconds must be set unless once is true');
        }
        this.pollSeconds = validatePositiveNumber(pollSeconds, 'pollSeconds', false);
        this.maxBackoffSeconds = validatePositiveNumber(maxBackoffSeconds, 'maxBackoffSeconds', false);
        this.dryRun = Boolean(dryRun);
        this.nodeClient = nodeClient;
        if (!this.nodeClient && (node || nodeInsecure)) {
            applyNodeOptions(node, Boolean(nodeInsecure));
        }
        this.signer = signer;
        this._loadSigner = loadSignerFn;
        this.source =
            source ??
            ((afterSeq) =>
                fetchCheckpointsAfter({
                    uuid: this.uuid,
                    afterSeq,
                    psql: this.psql,
                    timeoutMs: this.psqlTimeoutMs,
                    batchSize: this.psqlBatchSize,
                }));
        this.submitAnchor = submitAnchor;
        this.hasCustomSubmitAnchor = opts.submitAnchor !== undefined;
        this.setMetadata = setMetadata;
        if (witnessUrl !== null && witnessUrl !== undefined && (typeof witnessUrl !== 'string' || witnessUrl.trim().length === 0)) {
            throw new Error('witnessUrl must be a non-empty URL string');
        }
        this.witnessUrl = witnessUrl ? witnessUrl.trim() : null;
        this.allowPrivateWitness = Boolean(allowPrivateWitness);
        if (sponsorPointer !== undefined && typeof sponsorPointer !== 'boolean') {
            throw new TypeError('sponsorPointer must be a boolean');
        }
        this.sponsorPointer = sponsorPointer === undefined ? true : sponsorPointer;
        if (maxPriceMicroCcd !== null && maxPriceMicroCcd !== undefined) {
            const mpStr =
                typeof maxPriceMicroCcd === 'bigint' ? maxPriceMicroCcd.toString() : String(maxPriceMicroCcd).trim();
            if (!/^(?:0|[1-9][0-9]*)$/.test(mpStr)) {
                throw new Error(`maxPriceMicroCcd must be a non-negative integer, got ${maxPriceMicroCcd}`);
            }
            this.maxPriceMicroCcd = mpStr;
        } else {
            this.maxPriceMicroCcd = null;
        }
        this.paymentSignature = paymentSignature ?? null;
        this.payFn = payFn ?? null;
        this.payerSigner = payerSigner ?? null;
        this.payerKeyfile = payerKeyfile ?? null;
        this.fetchWitnessHealthFn = fetchWitnessHealthFn;
        this.requestWitnessAnchorFn = requestWitnessAnchorFn;
        this.requestSponsoredPointerFn = requestSponsoredPointerFn;
        this.buildSponsoredSetMetadataFn = buildSponsoredSetMetadataFn;
        this.now = now;
        this.wallClock = wallClock;
        this.customSleep = sleep ?? null;
        this.random = random;
        this.log = log;
        this.signal = signal ?? null;

        this.trail = null;
        this.lastAnchorMs = null;
        this._lastSeenAnchorTxHash = null;
        this._verifiedTip = null;
        this._activeCall = null;
    }

    _resolveSigner() {
        if (!this.signer) this.signer = this._loadSigner();
        return this.signer;
    }

    _seedLastAnchorMs(blockTimeIso) {
        if (!blockTimeIso) return;
        const blockMs = Date.parse(blockTimeIso);
        if (!Number.isFinite(blockMs)) return;
        const elapsedMs = Math.max(0, this.wallClock().getTime() - blockMs);
        this.lastAnchorMs = this.now() - elapsedMs;
    }

    _reconcileLegacyState() {
        if (!this.legacyStatePath) return this.statePath;
        const legacyExists = fs.existsSync(this.legacyStatePath);
        const canonExists = fs.existsSync(this.statePath);
        if (legacyExists && canonExists) {
            const stLegacy = fs.statSync(this.legacyStatePath);
            const stCanon = fs.statSync(this.statePath);
            const sameInode = stLegacy.dev === stCanon.dev && stLegacy.ino === stCanon.ino;
            const canonRaw = fs.readFileSync(this.statePath);
            if (!sameInode) {
                const legacyRaw = fs.readFileSync(this.legacyStatePath);
                if (Buffer.compare(legacyRaw, canonRaw) !== 0) {
                    throw new Error(
                        `conflicting state files exist at both legacy path (${this.legacyStatePath}) and canonical path (${this.statePath}); resolve manually`,
                    );
                }
            }
            if (!this.dryRun) {
                const canonIsSymlink = fs.lstatSync(this.statePath).isSymbolicLink();
                if ((stCanon.mode & 0o777) !== 0o600 || (sameInode && canonIsSymlink)) {
                    writeFileAtomic(this.statePath, canonRaw, { mode: 0o600 });
                }
                fs.unlinkSync(this.legacyStatePath);
                this.log(`removed already-migrated legacy state file ${this.legacyStatePath}`);
            }
            return this.statePath;
        }
        if (legacyExists && !canonExists) {
            if (this.dryRun) {
                return this.legacyStatePath;
            }
            const raw = fs.readFileSync(this.legacyStatePath);
            writeFileAtomic(this.statePath, raw, { mode: 0o600 });
            fs.unlinkSync(this.legacyStatePath);
            this.log(`migrated legacy state file ${this.legacyStatePath} -> ${this.statePath}`);
        }
        return this.statePath;
    }

    _readState() {
        const targetStatePath = this._reconcileLegacyState();
        if (!fs.existsSync(targetStatePath)) return null;
        let parsed;
        try {
            parsed = JSON.parse(fs.readFileSync(targetStatePath, 'utf8'));
        } catch (err) {
            throw new Error(`corrupt anchor state file ${targetStatePath}: ${err.message}`);
        }
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            throw new Error(`invalid anchor state file ${targetStatePath}: expected JSON object`);
        }
        if (parsed.agentUuid !== undefined && parsed.agentUuid !== this.uuid) {
            throw new Error(`state file ${targetStatePath} agentUuid ${parsed.agentUuid} does not match ${this.uuid}`);
        }
        if (parsed.tokenId !== undefined && String(parsed.tokenId) !== this.tokenId) {
            throw new Error(`state file ${targetStatePath} tokenId ${parsed.tokenId} does not match ${this.tokenId}`);
        }
        if (parsed.pendingAnchor !== undefined && parsed.pendingAnchor !== null) {
            const p = parsed.pendingAnchor;
            if (
                typeof p !== 'object' ||
                Array.isArray(p) ||
                !TX_RE.test(p.txHash ?? '') ||
                !Number.isSafeInteger(p.toSeq) ||
                p.toSeq <= 0 ||
                !TX_RE.test(p.commitment ?? '') ||
                (p.prevAnchorTx !== null && !TX_RE.test(p.prevAnchorTx ?? ''))
            ) {
                throw new Error(`corrupt pendingAnchor in ${targetStatePath}`);
            }
            if (p.tokenId !== undefined && String(p.tokenId) !== this.tokenId) {
                throw new Error(`pendingAnchor tokenId ${p.tokenId} does not match ${this.tokenId}`);
            }
            if (p.metadataTx !== undefined && p.metadataTx !== null && !isTxRefObj(p.metadataTx)) {
                throw new Error(`corrupt pendingAnchor.metadataTx in ${targetStatePath}`);
            }
        }
        if (parsed.pendingPayment !== undefined && parsed.pendingPayment !== null) {
            const pp = parsed.pendingPayment;
            if (
                typeof pp !== 'object' ||
                Array.isArray(pp) ||
                typeof pp.witnessUrl !== 'string' ||
                pp.witnessUrl.trim().length === 0 ||
                (pp.tokenId !== undefined && String(pp.tokenId) !== this.tokenId) ||
                !Number.isSafeInteger(pp.toSeq) ||
                pp.toSeq <= 0 ||
                !TX_RE.test(pp.commitment ?? '') ||
                (pp.prevAnchorTx !== null && !TX_RE.test(pp.prevAnchorTx ?? '')) ||
                !TX_RE.test(pp.memoHex ?? '') ||
                !TX_RE.test(pp.paymentTxHash ?? '') ||
                (pp.expiryEpochSeconds !== undefined &&
                    pp.expiryEpochSeconds !== null &&
                    (!Number.isFinite(pp.expiryEpochSeconds) || pp.expiryEpochSeconds < 0)) ||
                typeof pp.paymentSignature !== 'string' ||
                pp.paymentSignature.length === 0 ||
                (pp.payer !== undefined && pp.payer !== null && typeof pp.payer !== 'string') ||
                (pp.amountMicroCcd !== undefined &&
                    pp.amountMicroCcd !== null &&
                    !/^(?:0|[1-9][0-9]*)$/.test(String(pp.amountMicroCcd))) ||
                (pp.status !== 'signed' && pp.status !== 'finalized')
            ) {
                throw new Error(`corrupt pendingPayment in ${targetStatePath}`);
            }
        }
        if (parsed.trailAppend !== undefined && parsed.trailAppend !== null) {
            const ta = parsed.trailAppend;
            if (
                typeof ta !== 'object' ||
                Array.isArray(ta) ||
                !Number.isSafeInteger(ta.baseSize) ||
                ta.baseSize <= 0 ||
                !Number.isSafeInteger(ta.targetSeq) ||
                ta.targetSeq <= 0
            ) {
                throw new Error(`corrupt trailAppend in ${targetStatePath}`);
            }
        }
        return parsed;
    }

    _updateState(patch) {
        const current = this._readState() ?? {};
        const payload = {
            version: 1,
            agentUuid: this.uuid,
            tokenId: this.tokenId,
            lastAnchoredSeq: 0,
            lastAnchoredTxHash: null,
            lastAnchoredCommitment: null,
            lastAnchoredAt: null,
            pendingAnchor: null,
            pendingPayment: null,
            trailAppend: null,
            ...current,
            ...patch,
            updatedAt: this.wallClock().toISOString(),
        };
        writeFileAtomic(this.statePath, JSON.stringify(payload, null, 2) + '\n', { mode: 0o600 });
        return payload;
    }

    _assertHeaderMatchesConfig(header) {
        const r = header.registry ?? {};
        if (
            header.agent_uuid !== this.uuid ||
            header.token_id !== this.tokenId ||
            r.network !== NETWORK ||
            r.index !== REGISTRY.index ||
            r.subindex !== REGISTRY.subindex
        ) {
            throw new Error(
                `trail header (${header.agent_uuid}, token ${header.token_id}, ${r.network} <${r.index},${r.subindex}>) does not match worker config`,
            );
        }
    }

    _loadOrRecoverExistingTrail() {
        const readAndValidate = () => {
            const { header, records } = readTrail(this.trailPath);
            this._assertHeaderMatchesConfig(header);
            const wanted = new Set(records.map((_, i) => i + 1));
            const { last, count, at } = commitments(header, records, wanted);
            return {
                header,
                records,
                lastSeq: count,
                lastCheckpointId: records.at(-1)?.checkpoint_id ?? null,
                commitment: last,
                commitmentsBySeq: at,
            };
        };

        let loaded;
        let trailReadErr = null;
        try {
            loaded = readAndValidate();
        } catch (readErr) {
            trailReadErr = readErr;
        }

        if (!trailReadErr) {
            const existingState = this._readState();
            if (existingState?.trailAppend && !this.dryRun) {
                this._updateState({ trailAppend: null });
            }
            return loaded;
        }

        const existingState = this._readState();
        const ta = existingState?.trailAppend;
        if (!ta) throw trailReadErr;

        const curSize = fs.statSync(this.trailPath).size;
        if (curSize <= ta.baseSize) throw trailReadErr;

        const prefixBuf = Buffer.alloc(ta.baseSize);
        const fd = fs.openSync(this.trailPath, 'r');
        try {
            let totalRead = 0;
            while (totalRead < ta.baseSize) {
                const n = fs.readSync(fd, prefixBuf, totalRead, ta.baseSize - totalRead, totalRead);
                if (n === 0) break;
                totalRead += n;
            }
            if (totalRead !== ta.baseSize) throw trailReadErr;
        } finally {
            fs.closeSync(fd);
        }

        const parsedPrefix = parseTrailBuffer(prefixBuf);
        this._assertHeaderMatchesConfig(parsedPrefix.header);
        commitments(parsedPrefix.header, parsedPrefix.records);

        this.log(`recovering interrupted trail append: truncating ${this.trailPath} from ${curSize} to ${ta.baseSize} bytes`);
        const truncFd = fs.openSync(this.trailPath, 'r+');
        try {
            fs.ftruncateSync(truncFd, ta.baseSize);
            fs.fsyncSync(truncFd);
        } finally {
            fs.closeSync(truncFd);
        }
        if (!this.dryRun) {
            this._updateState({ trailAppend: null });
        }
        return readAndValidate();
    }

    /** Initializes or reads/verifies the trail file, then fetches and durably appends any new checkpoints. */
    async syncTrail() {
        this._reconcileLegacyState();
        let baseTrail;
        if (!fs.existsSync(this.trailPath)) {
            const header = checkHeader({
                schema: SCHEMA,
                source: 'unitares core.checkpoints',
                agent_uuid: this.uuid,
                token_id: this.tokenId,
                registry: { network: NETWORK, ...REGISTRY },
            });
            writeFileAtomic(this.trailPath, canonical(header) + '\n', { mode: 0o600 });
            baseTrail = {
                header,
                records: [],
                lastSeq: 0,
                lastCheckpointId: null,
                commitment: genesisHash(header),
                commitmentsBySeq: new Map(),
            };
        } else {
            baseTrail = this._loadOrRecoverExistingTrail();
        }

        this.trail = {
            header: baseTrail.header,
            lastSeq: baseTrail.lastSeq,
            lastCheckpointId: baseTrail.lastCheckpointId,
            commitment: baseTrail.commitment,
            commitmentsBySeq: baseTrail.commitmentsBySeq,
        };
        const rows = await this.source(baseTrail.lastSeq);
        if (!Array.isArray(rows)) {
            throw new Error('checkpoint source must return an array');
        }
        if (rows.length === 0) {
            return { ...this.trail, added: 0 };
        }

        let nextSeq = baseTrail.lastSeq;
        let nextCheckpointId = baseTrail.lastCheckpointId;
        let nextCommitment = baseTrail.commitment;
        const nextCommitments = new Map(baseTrail.commitmentsBySeq);
        const lines = [];

        for (const row of rows) {
            nextSeq += 1;
            checkRecord(row, nextSeq, nextCheckpointId);
            nextCommitment = stepHash(nextCommitment, row);
            nextCheckpointId = row.checkpoint_id;
            nextCommitments.set(nextSeq, nextCommitment);
            lines.push(canonical(row) + '\n');
        }

        try {
            if (this.dryRun) {
                const fullText = serializeTrail(baseTrail.header, [...baseTrail.records, ...rows]);
                writeFileAtomic(this.trailPath, fullText, { mode: trailFileMode(this.trailPath) });
            } else {
                const payload = Buffer.from(lines.join(''), 'utf8');
                const originalSize = fs.statSync(this.trailPath).size;
                this._updateState({ trailAppend: { baseSize: originalSize, targetSeq: nextSeq } });
                const fd = fs.openSync(this.trailPath, 'a');
                try {
                    let offset = 0;
                    while (offset < payload.length) {
                        offset += fs.writeSync(fd, payload, offset, payload.length - offset);
                    }
                    fs.fsyncSync(fd);
                } catch (err) {
                    try {
                        fs.ftruncateSync(fd, originalSize);
                    } catch {}
                    throw err;
                } finally {
                    fs.closeSync(fd);
                }
                this._updateState({ trailAppend: null });
            }
            this.trail = {
                header: baseTrail.header,
                lastSeq: nextSeq,
                lastCheckpointId: nextCheckpointId,
                commitment: nextCommitment,
                commitmentsBySeq: nextCommitments,
            };
            return { ...this.trail, added: rows.length };
        } catch (err) {
            this.trail = {
                header: baseTrail.header,
                lastSeq: baseTrail.lastSeq,
                lastCheckpointId: baseTrail.lastCheckpointId,
                commitment: baseTrail.commitment,
                commitmentsBySeq: baseTrail.commitmentsBySeq,
            };
            throw err;
        }
    }

    _syncTipFromAnchor(anchorRecord, agentOwnerAccount, witnessStateOrAccount = null) {
        const witnessState =
            witnessStateOrAccount && typeof witnessStateOrAccount === 'object'
                ? {
                      currentWitness: witnessStateOrAccount.currentWitness ?? null,
                      sawWitnessEvent: Boolean(witnessStateOrAccount.sawWitnessEvent),
                  }
                : {
                      currentWitness: witnessStateOrAccount ?? null,
                      sawWitnessEvent: witnessStateOrAccount !== null && witnessStateOrAccount !== undefined,
                  };
        this._verifiedTip = {
            pointer: anchorRecord?.txHash ?? null,
            ownerAccount: agentOwnerAccount,
            witnessAccount: witnessState.currentWitness,
            sawWitnessEvent: witnessState.sawWitnessEvent,
            anchoredSeq: anchorRecord?.toSeq ?? 0,
            anchoredCommitment: anchorRecord?.commitment ?? null,
        };
        if (anchorRecord?.txHash) {
            this._lastSeenAnchorTxHash = anchorRecord.txHash;
        }
    }

    async _verifyWitnessAlignment({ c, tipBlockHash, agent, history, onChainWitness }) {
        const health = await this.fetchWitnessHealthFn({
            witnessUrl: this.witnessUrl,
            allowPrivate: this.allowPrivateWitness,
        });
        const actualWitness =
            onChainWitness !== undefined
                ? onChainWitness
                : await readMetadataText(this.tokenId, WITNESS_KEY, {
                      blockHash: tipBlockHash,
                      nodeClient: c,
                  });
        const witnessState = extractWitnessState(history);
        if (!witnessMatchesOnChain(witnessState, actualWitness)) {
            throw new Error(
                `on-chain ${WITNESS_KEY} (${actualWitness ?? 'null'}) disagrees with MetadataSet history (${witnessState.currentWitness ?? 'null'})`,
            );
        }
        const activeWitness = witnessState.currentWitness;
        if (activeWitness === null || !isSameAccount(activeWitness, health.witnessAccount)) {
            throw new Error(
                `on-chain ${WITNESS_KEY} (${actualWitness ?? 'not set'}) does not match witness ${health.witnessAccount}`,
            );
        }
        if (isSameAccount(health.witnessAccount, agent.ownerAccount)) {
            throw new Error(`witness account ${health.witnessAccount} cannot equal token owner ${agent.ownerAccount}`);
        }
        return {
            health,
            onChainWitness: actualWitness,
            witnessState,
            activeWitness,
            useSponsoredPointer: this.sponsorPointer && Boolean(health.sponsorPointer),
        };
    }

    _buildWitnessPayFn(c, ownerSigner, witnessCtx, paymentMeta, resolvedPayer = null) {
        if (this.payFn) return this.payFn;
        if (this.paymentSignature) return null;
        return async (requirements) => {
            const amount = BigInt(requirements.amount);
            if (amount > 0n) {
                if (this.maxPriceMicroCcd === null) {
                    throw new Error(`refusing to auto-pay ${amount} microCCD without explicit maxPriceMicroCcd`);
                }
                if (amount > BigInt(this.maxPriceMicroCcd)) {
                    throw new Error(
                        `witness price ${amount} microCCD exceeds maxPriceMicroCcd ${this.maxPriceMicroCcd}`,
                    );
                }
                if (
                    witnessCtx?.health?.priceMicroCcd === undefined ||
                    witnessCtx?.health?.priceMicroCcd === null
                ) {
                    throw new Error('witness /health did not advertise priceMicroCcd; refusing non-zero auto-payment');
                }
                if (amount > BigInt(witnessCtx.health.priceMicroCcd)) {
                    throw new Error(
                        `witness 402 amount ${amount} exceeds /health priceMicroCcd ${witnessCtx.health.priceMicroCcd}`,
                    );
                }
            }

            const pWho =
                resolvedPayer ??
                this.payerSigner ??
                (this.payerKeyfile ? loadSignerFromFile(this.payerKeyfile) : ownerSigner);
            const nextNonce = await withRpcRetry(() => c.getNextAccountNonce(pWho.sender));
            if (!nextNonce?.allFinal) {
                throw new Error(`payer account ${pWho.address} has non-finalized transactions; refusing witness payment`);
            }
            const expectedPayerNonce = BigInt(nextNonce.nonce.value);
            const memoBytes = Buffer.from(requirements.extra.memoHex, 'hex');
            let savedPendingPayment = null;

            let txRes;
            try {
                txRes = await sendTransferWithMemo({
                    to: requirements.payTo,
                    microCcd: amount,
                    memoBytes,
                    who: pWho,
                    nodeClient: c,
                    expectedNonce: expectedPayerNonce,
                    onSigned: ({ txHash: paymentTxHash, expiryEpochSeconds }) => {
                        const envelope = {
                            x402Version: X402_VERSION,
                            accepted: requirements,
                            payload: { txHash: paymentTxHash },
                        };
                        savedPendingPayment = {
                            witnessUrl: normalizeWitnessBaseUrl(this.witnessUrl),
                            tokenId: this.tokenId,
                            toSeq: paymentMeta.toSeq,
                            commitment: paymentMeta.commitment,
                            prevAnchorTx: paymentMeta.prevAnchorTx,
                            memoHex: requirements.extra.memoHex,
                            paymentTxHash,
                            expiryEpochSeconds,
                            paymentSignature: encodeX402Header(envelope),
                            payer: pWho.address,
                            amountMicroCcd: String(requirements.amount),
                            status: 'signed',
                        };
                        this._updateState({ pendingPayment: savedPendingPayment });
                    },
                });
            } catch (err) {
                if (/was rejected:/.test(err.message)) {
                    this._updateState({ pendingPayment: null });
                }
                throw err;
            }
            if (savedPendingPayment) {
                this._updateState({
                    pendingPayment: { ...savedPendingPayment, status: 'finalized' },
                });
            }
            this.log(`paid witness fee ${requirements.amount} microCCD: ${EXPLORER_TX(txRes.hash)}`);
            return {
                x402Version: X402_VERSION,
                accepted: requirements,
                payload: { txHash: txRes.hash },
            };
        };
    }

    async _submitPointerUpdate({
        c,
        signer,
        anchorTxHash,
        expectedPrevTx,
        expectedOwnerAccount,
        expectedActiveWitness,
        expectedSetNonce = null,
        witnessCtx,
        getPending,
        setPending,
    }) {
        const prepared = await preparePointerUpdateAtTip({
            nodeClient: c,
            tokenId: this.tokenId,
            signerSender: signer.sender,
            expectedPrevTx,
            expectedOwnerAccount,
            expectedActiveWitness,
        });
        const resolvedSetNonce =
            expectedSetNonce !== null && expectedSetNonce !== undefined
                ? expectedSetNonce
                : prepared.expectedSetNonce;

        if (witnessCtx?.useSponsoredPointer) {
            const built = await this.buildSponsoredSetMetadataFn({
                tokenId: this.tokenId,
                key: ANCHOR_KEY,
                valueUtf8: anchorTxHash,
                who: signer,
                sponsorAddress: witnessCtx.health.witnessAccount,
                expectedNonce: resolvedSetNonce,
                nodeClient: c,
            });
            const preSponsorPending = {
                ...getPending(),
                status: 'finalized',
                metadataTx: {
                    mode: 'sponsored',
                    sponsorUrl: this.witnessUrl,
                    txHash: null,
                    expiryEpochSeconds: built.expiryEpochSeconds,
                    nonce: built.nonce,
                },
            };
            setPending(preSponsorPending);
            this._updateState({ pendingAnchor: preSponsorPending });

            const sp = await this.requestSponsoredPointerFn({
                witnessUrl: this.witnessUrl,
                tokenId: this.tokenId,
                anchorTxHash,
                transactionJson: built.transactionJson,
                allowPrivate: this.allowPrivateWitness,
            });
            const postSponsorPending = {
                ...getPending(),
                status: 'finalized',
                metadataTx: {
                    mode: 'sponsored',
                    sponsorUrl: this.witnessUrl,
                    txHash: sp.metadataTxHash,
                    expiryEpochSeconds: built.expiryEpochSeconds,
                    nonce: built.nonce,
                },
            };
            setPending(postSponsorPending);
            this._updateState({ pendingAnchor: postSponsorPending });
            return { hash: sp.metadataTxHash, sponsored: true };
        }

        const onMetadataSigned = ({ txHash: metaTxHash, expiryEpochSeconds: metaExpiry }) => {
            const nextPending = {
                ...getPending(),
                status: 'finalized',
                metadataTx: { txHash: metaTxHash, expiryEpochSeconds: metaExpiry },
            };
            setPending(nextPending);
            this._updateState({ pendingAnchor: nextPending });
        };
        const res = await this.setMetadata(this.tokenId, ANCHOR_KEY, anchorTxHash, signer, c, {
            onSigned: onMetadataSigned,
            expectedNonce: resolvedSetNonce,
        });
        return { hash: res?.hash ?? null, sponsored: false };
    }

    /** Syncs trail, reconciles chain history and pending anchors, and anchors if threshold is met. */
    async reconcileAndAnchor() {
        const syncResult = await this.syncTrail();
        const state = this._readState();

        const c = this.nodeClient ?? (await client());
        await assertTestnet(c);

        const loadFinalizedSnapshot = async () => {
            const freshCs = await withRpcRetry(() => c.getConsensusStatus());
            const freshBh = freshCs.lastFinalizedBlock;
            const freshHeight = freshCs.lastFinalizedBlockHeight;
            const freshAgent = await readAgentOf(this.tokenId, { blockHash: freshBh, nodeClient: c });
            if (!freshAgent) throw new Error(`registry token ${this.tokenId} is not registered`);
            if (freshAgent.status !== 'Active') {
                throw new Error(`registry token ${this.tokenId} status is ${freshAgent.status ?? 'unknown'}; refusing to anchor`);
            }
            const freshUuid = await readMetadataText(this.tokenId, UUID_KEY, { blockHash: freshBh, nodeClient: c });
            if (freshUuid !== this.uuid) {
                throw new Error(`on-chain ${UUID_KEY} (${freshUuid ?? 'not set'}) does not match worker uuid ${this.uuid}`);
            }
            const freshCurrent = await readMetadataText(this.tokenId, ANCHOR_KEY, { blockHash: freshBh, nodeClient: c });
            if (freshCurrent !== null && !TX_RE.test(freshCurrent)) {
                throw new Error(`metadata ${ANCHOR_KEY} is not a transaction hash`);
            }
            const freshWitness = await readMetadataText(this.tokenId, WITNESS_KEY, { blockHash: freshBh, nodeClient: c });
            const freshHistory = await readRegistryHistory(this.tokenId, {
                tipBlockHash: freshBh,
                tipBlockHeight: freshHeight,
                agent: freshAgent,
                hintAnchorTxHashes: freshCurrent ? [freshCurrent] : [],
                nodeClient: c,
            });
            const freshWitnessState = extractWitnessState(freshHistory);
            if (!witnessMatchesOnChain(freshWitnessState, freshWitness)) {
                throw new Error(
                    `on-chain ${WITNESS_KEY} (${freshWitness ?? 'null'}) disagrees with MetadataSet history (${freshWitnessState.currentWitness ?? 'null'})`,
                );
            }
            const freshExisting = await loadAnchorsFromHistory(freshHistory, c, freshHeight);
            const freshPrev = verifyExistingAnchors(freshExisting, {
                tokenId: this.tokenId,
                ownerAccount: freshAgent.ownerAccount,
                commitmentAt: this.trail.commitmentsBySeq,
                currentPointer: freshCurrent,
            });
            return {
                tipBlockHash: freshBh,
                tipBlockHeight: freshHeight,
                agent: freshAgent,
                current: freshCurrent,
                onChainWitness: freshWitness,
                witnessState: freshWitnessState,
                history: freshHistory,
                existing: freshExisting,
                prev: freshPrev,
                remainingOwnerBudget: freshHistory.maxOwnerTxs - freshHistory.ownerNonceSpan,
            };
        };

        const cs = await withRpcRetry(() => c.getConsensusStatus());
        let tipBlockHash = cs.lastFinalizedBlock;
        let tipBlockHeight = cs.lastFinalizedBlockHeight;

        let agent = await readAgentOf(this.tokenId, { blockHash: tipBlockHash, nodeClient: c });
        if (!agent) throw new Error(`registry token ${this.tokenId} is not registered`);
        if (agent.status !== 'Active') {
            throw new Error(`registry token ${this.tokenId} status is ${agent.status ?? 'unknown'}; refusing to anchor`);
        }

        const onChainUuid = await readMetadataText(this.tokenId, UUID_KEY, { blockHash: tipBlockHash, nodeClient: c });
        if (onChainUuid !== this.uuid) {
            throw new Error(`on-chain ${UUID_KEY} (${onChainUuid ?? 'not set'}) does not match worker uuid ${this.uuid}`);
        }

        let current = await readMetadataText(this.tokenId, ANCHOR_KEY, { blockHash: tipBlockHash, nodeClient: c });
        if (current !== null && !TX_RE.test(current)) {
            throw new Error(`metadata ${ANCHOR_KEY} is not a transaction hash`);
        }

        const localSeq = this.trail.lastSeq;
        const noThresholds = this.everyRecords === null && this.everySeconds === null;

        // Idle-poll fast path: verify cached pointer, owner, witness (always), commitment, and !due before skipping history scans.
        if (
            this._verifiedTip !== null &&
            !state?.pendingAnchor &&
            !state?.pendingPayment &&
            current === this._verifiedTip.pointer &&
            agent.ownerAccount === this._verifiedTip.ownerAccount &&
            localSeq >= this._verifiedTip.anchoredSeq
        ) {
            const currentWitness = await readMetadataText(this.tokenId, WITNESS_KEY, {
                blockHash: tipBlockHash,
                nodeClient: c,
            });
            const idleWitnessMatches = witnessMatchesOnChain(
                {
                    currentWitness: this._verifiedTip.witnessAccount,
                    sawWitnessEvent: this._verifiedTip.sawWitnessEvent,
                },
                currentWitness,
            );
            const cachedAnchoredSeq = this._verifiedTip.anchoredSeq;
            const cachedCommitmentMatches =
                cachedAnchoredSeq === 0
                    ? this._verifiedTip.anchoredCommitment === null
                    : this.trail.commitmentsBySeq.get(cachedAnchoredSeq)?.toString('hex') === this._verifiedTip.anchoredCommitment;
            if (idleWitnessMatches && cachedCommitmentMatches) {
                const dueFast =
                    shouldAnchor({
                        localSeq,
                        anchoredSeq: cachedAnchoredSeq,
                        lastAnchorMs: this.lastAnchorMs,
                        nowMs: this.now(),
                        everyRecords: this.everyRecords,
                        everySeconds: this.everySeconds,
                    }) ||
                    (this.once && noThresholds && localSeq > cachedAnchoredSeq);
                if (!dueFast) {
                    return {
                        synced: syncResult.added,
                        localSeq,
                        anchoredSeq: cachedAnchoredSeq,
                        anchored: false,
                        dryRun: this.dryRun,
                    };
                }
            }
        }

        let onChainWitness = await readMetadataText(this.tokenId, WITNESS_KEY, {
            blockHash: tipBlockHash,
            nodeClient: c,
        });
        let history = await readRegistryHistory(this.tokenId, {
            tipBlockHash,
            tipBlockHeight,
            agent,
            hintAnchorTxHashes: current ? [current] : [],
            nodeClient: c,
        });
        let witnessStateAtTip = extractWitnessState(history);
        if (!witnessMatchesOnChain(witnessStateAtTip, onChainWitness)) {
            throw new Error(
                `on-chain ${WITNESS_KEY} (${onChainWitness ?? 'null'}) disagrees with MetadataSet history (${witnessStateAtTip.currentWitness ?? 'null'})`,
            );
        }
        let existing = await loadAnchorsFromHistory(history, c, tipBlockHeight);
        let prev = verifyExistingAnchors(existing, {
            tokenId: this.tokenId,
            ownerAccount: agent.ownerAccount,
            commitmentAt: this.trail.commitmentsBySeq,
            currentPointer: current,
        });
        if (prev && prev.txHash !== this._lastSeenAnchorTxHash) {
            this._seedLastAnchorMs(prev.blockTime);
            this._lastSeenAnchorTxHash = prev.txHash;
        }
        this._syncTipFromAnchor(prev, agent.ownerAccount, witnessStateAtTip);

        let remainingOwnerBudget = history.maxOwnerTxs - history.ownerNonceSpan;
        let resumedPendingOnThisTick = false;

        const applyRefreshedSnapshot = async ({ preserveTimerForTxHash = null } = {}) => {
            const snap = await loadFinalizedSnapshot();
            tipBlockHash = snap.tipBlockHash;
            tipBlockHeight = snap.tipBlockHeight;
            agent = snap.agent;
            current = snap.current;
            onChainWitness = snap.onChainWitness;
            witnessStateAtTip = snap.witnessState;
            history = snap.history;
            existing = snap.existing;
            prev = snap.prev;
            remainingOwnerBudget = snap.remainingOwnerBudget;
            if (prev) {
                if (prev.txHash === preserveTimerForTxHash) {
                    this._lastSeenAnchorTxHash = prev.txHash;
                } else if (prev.txHash !== this._lastSeenAnchorTxHash) {
                    this._seedLastAnchorMs(prev.blockTime);
                    this._lastSeenAnchorTxHash = prev.txHash;
                }
            }
            this._syncTipFromAnchor(prev, agent.ownerAccount, witnessStateAtTip);
        };

        if (state?.pendingAnchor) {
            let pending = state.pendingAnchor;
            const clearPending = (extraPatch = {}) => {
                if (!this.dryRun) {
                    this._updateState({ pendingAnchor: null, ...extraPatch });
                }
            };
            const tipBlock = await withRpcRetry(() => c.getBlockInfo(tipBlockHash));
            const finalizedChainEpochSec = Math.floor(tipBlock.blockSlotTime.getTime() / 1000);

            if (current === pending.txHash) {
                if (
                    !prev ||
                    prev.toSeq !== pending.toSeq ||
                    prev.commitment !== pending.commitment ||
                    prev.prevAnchorTx !== pending.prevAnchorTx
                ) {
                    throw new Error(`pending anchor ${pending.txHash} disagrees with on-chain anchor record`);
                }
                this._seedLastAnchorMs(prev.blockTime ?? this.wallClock().toISOString());
                this._lastSeenAnchorTxHash = prev.txHash;
                this.log(`pending anchor ${pending.txHash} (seq 1..${prev.toSeq}) already landed on chain; clearing pending state`);
                clearPending({
                    lastAnchoredSeq: prev.toSeq,
                    lastAnchoredTxHash: prev.txHash,
                    lastAnchoredCommitment: prev.commitment,
                    lastAnchoredAt: prev.blockTime ?? this.wallClock().toISOString(),
                });
            } else if (existing.some((a) => a.txHash === pending.txHash)) {
                this.log(`pending anchor ${pending.txHash} is already in on-chain history; clearing pending state`);
                clearPending({
                    lastAnchoredSeq: prev?.toSeq ?? 0,
                    lastAnchoredTxHash: prev?.txHash ?? null,
                    lastAnchoredCommitment: prev?.commitment ?? null,
                    lastAnchoredAt: prev?.blockTime ?? null,
                });
            } else {
                let metadataHandled = false;
                if (pending.metadataTx) {
                    const metaTx = pending.metadataTx;
                    const finishLandedMetadata = async () => {
                        const anchoredAt = this.wallClock().toISOString();
                        clearPending({
                            lastAnchoredSeq: pending.toSeq,
                            lastAnchoredTxHash: pending.txHash,
                            lastAnchoredCommitment: pending.commitment,
                            lastAnchoredAt: anchoredAt,
                        });
                        this.lastAnchorMs = this.now();
                        this.log(`resumed pending metadata tx ${metaTx.txHash ?? 'sponsored'} for anchor ${pending.txHash}`);
                        metadataHandled = true;
                        resumedPendingOnThisTick = true;
                        await applyRefreshedSnapshot({ preserveTimerForTxHash: pending.txHash });
                    };

                    if (metaTx.mode === 'sponsored' && !metaTx.txHash) {
                        let latestCurrent = await readMetadataText(this.tokenId, ANCHOR_KEY, { nodeClient: c });
                        if (latestCurrent === pending.txHash) {
                            await finishLandedMetadata();
                        } else if (latestCurrent !== (prev?.txHash ?? null)) {
                            this.log(`pending sponsored metadata landed and pointer moved concurrently; clearing pending state`);
                            clearPending();
                            return {
                                synced: syncResult.added,
                                localSeq,
                                anchoredSeq: prev?.toSeq ?? 0,
                                anchored: false,
                                dryRun: this.dryRun,
                            };
                        } else if (finalizedChainEpochSec <= (metaTx.expiryEpochSeconds ?? Infinity)) {
                            throw new Error(
                                `pending sponsored metadata tx (nonce ${metaTx.nonce ?? 'unknown'}) in-flight/ambiguous until finalized chain time passes expiry ${metaTx.expiryEpochSeconds} (chain=${finalizedChainEpochSec})`,
                            );
                        } else {
                            latestCurrent = await readMetadataText(this.tokenId, ANCHOR_KEY, { nodeClient: c });
                            if (latestCurrent === pending.txHash) {
                                await finishLandedMetadata();
                            } else if (latestCurrent !== (prev?.txHash ?? null)) {
                                this.log(`pending sponsored metadata landed and pointer moved concurrently; clearing pending state`);
                                clearPending();
                                return {
                                    synced: syncResult.added,
                                    localSeq,
                                    anchoredSeq: prev?.toSeq ?? 0,
                                    anchored: false,
                                    dryRun: this.dryRun,
                                };
                            } else {
                                this.log(`pending sponsored metadata tx expired at chain time ${finalizedChainEpochSec}; clearing metadataTx`);
                                pending = { ...pending, metadataTx: null };
                                if (!this.dryRun) this._updateState({ pendingAnchor: pending });
                            }
                        }
                    } else {
                        let metaStatus = await getTransactionState(metaTx.txHash, c);

                        if (metaStatus.state === 'absent') {
                            if (finalizedChainEpochSec <= (metaTx.expiryEpochSeconds ?? Infinity)) {
                                throw new Error(
                                    `pending metadata tx ${metaTx.txHash} in-flight/ambiguous until finalized chain time passes expiry ${metaTx.expiryEpochSeconds} (chain=${finalizedChainEpochSec})`,
                                );
                            }
                            metaStatus = await getTransactionState(metaTx.txHash, c);
                            if (metaStatus.state === 'absent') {
                                this.log(`pending metadata tx ${metaTx.txHash} expired at chain time ${finalizedChainEpochSec}; clearing metadataTx`);
                                pending = { ...pending, metadataTx: null };
                                if (!this.dryRun) this._updateState({ pendingAnchor: pending });
                            }
                        }

                        if (metaStatus.state === 'pending' || metaStatus.state === 'committed') {
                            if (this.dryRun) {
                                const plan = {
                                    action: 'wait_metadata_finalization',
                                    tokenId: this.tokenId,
                                    txHash: pending.txHash,
                                    metadataTxHash: metaTx.txHash,
                                    toSeq: pending.toSeq,
                                };
                                this.log(`[dry-run] pending metadata recovery plan ${JSON.stringify(plan)}`);
                                return {
                                    synced: syncResult.added,
                                    localSeq,
                                    anchoredSeq: prev?.toSeq ?? 0,
                                    anchored: false,
                                    dryRun: true,
                                    plan,
                                };
                            }
                            let waitSucceeded = false;
                            try {
                                await waitForFinalizedPolling(c, metaTx.txHash);
                                waitSucceeded = true;
                            } catch (waitErr) {
                                if (/was rejected:/.test(waitErr.message)) {
                                    this.log(`pending metadata tx ${metaTx.txHash} rejected; clearing metadataTx`);
                                    pending = { ...pending, metadataTx: null };
                                    this._updateState({ pendingAnchor: pending });
                                } else {
                                    throw waitErr;
                                }
                            }
                            if (waitSucceeded) {
                                const latestCurrent = await readMetadataText(this.tokenId, ANCHOR_KEY, { nodeClient: c });
                                if (latestCurrent === pending.txHash) {
                                    await finishLandedMetadata();
                                } else if (latestCurrent !== (prev?.txHash ?? null)) {
                                    this.log(`pending metadata tx ${metaTx.txHash} landed and pointer moved concurrently; clearing pending state`);
                                    clearPending();
                                    return {
                                        synced: syncResult.added,
                                        localSeq,
                                        anchoredSeq: prev?.toSeq ?? 0,
                                        anchored: false,
                                        dryRun: this.dryRun,
                                    };
                                }
                            }
                        } else if (metaStatus.state === 'finalized') {
                            const failed = metaStatus.summary?.transactionType === 'failed' || Boolean(metaStatus.summary?.rejectReason);
                            if (failed) {
                                this.log(`pending metadata tx ${metaTx.txHash} failed on chain; clearing metadataTx`);
                                pending = { ...pending, metadataTx: null };
                                if (!this.dryRun) this._updateState({ pendingAnchor: pending });
                            } else {
                                const latestCurrent = await readMetadataText(this.tokenId, ANCHOR_KEY, { nodeClient: c });
                                if (latestCurrent === pending.txHash) {
                                    await finishLandedMetadata();
                                } else if (latestCurrent !== (prev?.txHash ?? null)) {
                                    this.log(`pending metadata tx ${metaTx.txHash} landed and pointer moved concurrently; clearing pending state`);
                                    clearPending();
                                    return {
                                        synced: syncResult.added,
                                        localSeq,
                                        anchoredSeq: prev?.toSeq ?? 0,
                                        anchored: false,
                                        dryRun: this.dryRun,
                                    };
                                }
                            }
                        }
                    }
                }

                if (!metadataHandled) {
                    let rdStatus = await getTransactionState(pending.txHash, c);
                    let pendingCleared = false;
                    let waitedForPendingRd = false;

                    if (rdStatus.state === 'absent') {
                        if (finalizedChainEpochSec <= (pending.expiryEpochSeconds ?? Infinity)) {
                            throw new Error(
                                `pending registerData tx ${pending.txHash} ambiguous until finalized chain time passes expiry ${pending.expiryEpochSeconds ?? 'unknown'} (chain=${finalizedChainEpochSec})`,
                            );
                        }
                        rdStatus = await getTransactionState(pending.txHash, c);
                        if (rdStatus.state === 'absent') {
                            this.log(`pending registerData tx ${pending.txHash} expired at chain time ${finalizedChainEpochSec}; clearing pending state`);
                            clearPending();
                            pendingCleared = true;
                        }
                    }

                    if (!pendingCleared && (rdStatus.state === 'pending' || rdStatus.state === 'committed')) {
                        if (this.dryRun) {
                            const plan = {
                                action: 'wait_anchor_finalization',
                                tokenId: this.tokenId,
                                txHash: pending.txHash,
                                toSeq: pending.toSeq,
                            };
                            this.log(`[dry-run] pending anchor recovery plan ${JSON.stringify(plan)}`);
                            return {
                                synced: syncResult.added,
                                localSeq,
                                anchoredSeq: prev?.toSeq ?? 0,
                                anchored: false,
                                dryRun: true,
                                plan,
                            };
                        }
                        try {
                            await waitForFinalizedPolling(c, pending.txHash);
                            waitedForPendingRd = true;
                        } catch (waitErr) {
                            if (/was rejected:/.test(waitErr.message)) {
                                this.log(`pending registerData tx ${pending.txHash} rejected; clearing pending state`);
                                clearPending();
                                pendingCleared = true;
                            } else {
                                throw waitErr;
                            }
                        }
                    } else if (!pendingCleared && rdStatus.state === 'finalized') {
                        const failed = rdStatus.summary?.transactionType === 'failed' || Boolean(rdStatus.summary?.rejectReason);
                        if (failed) {
                            this.log(`pending registerData tx ${pending.txHash} failed on chain; clearing pending state`);
                            clearPending();
                            pendingCleared = true;
                        }
                    }

                    if (!pendingCleared) {
                        const rd = await readRegisterData(pending.txHash, c);
                        if (waitedForPendingRd || rd.blockHeight > Number(tipBlockHeight)) {
                            await applyRefreshedSnapshot();
                        }
                        const d = decodeAnchor(rd.data);
                        const expectedPrevTx = prev?.txHash ?? null;
                        const expectedCommitment = this.trail.commitmentsBySeq.get(d.toSeq)?.toString('hex');
                        const activeWitness = witnessStateAtTip.currentWitness;
                        const expectedAnchorSender = activeWitness ?? agent.ownerAccount;
                        const senderAuthorizedNow = isSameAccount(rd.sender, expectedAnchorSender);
                        const wasHistoricallyAuthorizedSigner = wasSignerAuthorizedInWindow({
                            sender: rd.sender,
                            rdBlockHeight: rd.blockHeight,
                            ownerAccount: agent.ownerAccount,
                            regHeight: history.regHeight,
                            transitions: witnessStateAtTip.transitions,
                        });
                        const integrityOk =
                            d.tokenId === this.tokenId &&
                            d.toSeq === pending.toSeq &&
                            d.toSeq <= localSeq &&
                            Boolean(expectedCommitment) &&
                            d.commitment === expectedCommitment &&
                            d.commitment === pending.commitment &&
                            wasHistoricallyAuthorizedSigner &&
                            (!pending.sender || isSameAccount(rd.sender, pending.sender));
                        if (!integrityOk) {
                            throw new Error(
                                `pending anchor ${pending.txHash} disagrees with current trail/owner state; refusing to resume`,
                            );
                        }

                        const superseded =
                            pending.prevAnchorTx !== expectedPrevTx ||
                            d.prevAnchorTx !== expectedPrevTx ||
                            d.toSeq <= (prev?.toSeq ?? 0);
                        if (superseded) {
                            this.log(
                                `orphaned pending anchor ${pending.txHash} (seq 1..${d.toSeq}) superseded by chain pointer ${expectedPrevTx ?? 'none'} (seq ${prev?.toSeq ?? 0}); clearing pending state`,
                            );
                            clearPending({
                                lastAnchoredSeq: prev?.toSeq ?? 0,
                                lastAnchoredTxHash: prev?.txHash ?? null,
                                lastAnchoredCommitment: prev?.commitment ?? null,
                                lastAnchoredAt: prev?.blockTime ?? null,
                            });
                        } else if (!senderAuthorizedNow) {
                            if (this.dryRun) {
                                const plan = {
                                    action: 'clear_orphaned_pending_anchor',
                                    reason: 'witness_changed',
                                    tokenId: this.tokenId,
                                    txHash: pending.txHash,
                                    toSeq: d.toSeq,
                                    sender: rd.sender,
                                    expectedSender: expectedAnchorSender,
                                };
                                this.log(`[dry-run] pending anchor recovery plan ${JSON.stringify(plan)}`);
                                return {
                                    synced: syncResult.added,
                                    localSeq,
                                    anchoredSeq: prev?.toSeq ?? 0,
                                    anchored: false,
                                    dryRun: true,
                                    plan,
                                };
                            }
                            this.log(
                                `orphaned pending anchor ${pending.txHash} (seq 1..${d.toSeq}) signed by ${rd.sender} is no longer authorized under current signer ${expectedAnchorSender}; clearing pending state`,
                            );
                            clearPending({
                                lastAnchoredSeq: prev?.toSeq ?? 0,
                                lastAnchoredTxHash: prev?.txHash ?? null,
                                lastAnchoredCommitment: prev?.commitment ?? null,
                                lastAnchoredAt: prev?.blockTime ?? null,
                            });
                        } else if (this.dryRun) {
                            const plan = {
                                action: 'resume_set_metadata',
                                tokenId: this.tokenId,
                                txHash: pending.txHash,
                                toSeq: d.toSeq,
                                commitment: d.commitment,
                                prevAnchorTx: expectedPrevTx,
                            };
                            this.log(`[dry-run] pending anchor recovery plan ${JSON.stringify(plan)}`);
                            return {
                                synced: syncResult.added,
                                localSeq,
                                anchoredSeq: prev?.toSeq ?? 0,
                                anchored: false,
                                dryRun: true,
                                plan,
                            };
                        } else {
                            if (remainingOwnerBudget < 1) {
                                throw new Error(
                                    `owner nonce span ${history.ownerNonceSpan} + 1 exceeds maxOwnerTxs=${history.maxOwnerTxs}; refusing to resume setMetadata`,
                                );
                            }
                            const signer = this._resolveSigner();
                            if (signer.address !== agent.ownerAccount) {
                                throw new Error(
                                    `signer ${signer.address} must exactly match registered owner ${agent.ownerAccount} (CIS-8004.setMetadata rejects account aliases)`,
                                );
                            }
                            if (!isSameAccount(rd.sender, expectedAnchorSender)) {
                                throw new Error(
                                    `pending anchor ${pending.txHash} sender ${rd.sender} does not match authorized signer ${expectedAnchorSender}`,
                                );
                            }

                            const witnessCtx = this.witnessUrl
                                ? await this._verifyWitnessAlignment({
                                      c,
                                      tipBlockHash,
                                      agent,
                                      history,
                                      onChainWitness,
                                  })
                                : null;

                            await this._submitPointerUpdate({
                                c,
                                signer,
                                anchorTxHash: pending.txHash,
                                expectedPrevTx,
                                expectedOwnerAccount: agent.ownerAccount,
                                expectedActiveWitness: activeWitness,
                                expectedSetNonce: null,
                                witnessCtx,
                                getPending: () => pending,
                                setPending: (nextP) => {
                                    pending = nextP;
                                },
                            });
                            resumedPendingOnThisTick = true;
                            const anchoredAt = this.wallClock().toISOString();
                            clearPending({
                                lastAnchoredSeq: d.toSeq,
                                lastAnchoredTxHash: pending.txHash,
                                lastAnchoredCommitment: d.commitment,
                                lastAnchoredAt: anchoredAt,
                            });
                            this.lastAnchorMs = this.now();
                            this.log(`resumed pending anchor seq 1..${d.toSeq}: ${EXPLORER_TX(pending.txHash)}`);
                            await applyRefreshedSnapshot({ preserveTimerForTxHash: pending.txHash });
                        }
                    }
                }
            }
        }

        let pendingPayment = this._readState()?.pendingPayment ?? null;
        let resumedWitnessPaymentTxHash = null;
        if (pendingPayment) {
            const currentPrevTx = prev?.txHash ?? null;
            const currentAnchoredSeq = prev?.toSeq ?? 0;
            if (currentPrevTx !== pendingPayment.prevAnchorTx || currentAnchoredSeq >= pendingPayment.toSeq) {
                this.log(
                    `orphaned pending payment ${pendingPayment.paymentTxHash} (seq 1..${pendingPayment.toSeq}) superseded by chain pointer ${currentPrevTx ?? 'none'} (seq ${currentAnchoredSeq}); clearing pendingPayment`,
                );
                if (!this.dryRun) this._updateState({ pendingPayment: null });
                pendingPayment = null;
            } else {
                const expectedPayCommitment = this.trail.commitmentsBySeq.get(pendingPayment.toSeq)?.toString('hex');
                if (pendingPayment.toSeq > localSeq || expectedPayCommitment !== pendingPayment.commitment) {
                    throw new Error(
                        `pending payment ${pendingPayment.paymentTxHash} disagrees with current trail state; refusing to resume`,
                    );
                }
                let ppStatus = await getTransactionState(pendingPayment.paymentTxHash, c);
                if (ppStatus.state === 'absent') {
                    const tipBlock = await withRpcRetry(() => c.getBlockInfo(tipBlockHash));
                    const finalizedChainEpochSec = Math.floor(tipBlock.blockSlotTime.getTime() / 1000);
                    if (finalizedChainEpochSec <= (pendingPayment.expiryEpochSeconds ?? Infinity)) {
                        throw new Error(
                            `pending payment tx ${pendingPayment.paymentTxHash} in-flight/ambiguous until finalized chain time passes expiry ${pendingPayment.expiryEpochSeconds ?? 'unknown'} (chain=${finalizedChainEpochSec})`,
                        );
                    }
                    ppStatus = await getTransactionState(pendingPayment.paymentTxHash, c);
                    if (ppStatus.state === 'absent') {
                        this.log(
                            `pending payment tx ${pendingPayment.paymentTxHash} expired at chain time ${finalizedChainEpochSec}; clearing pendingPayment`,
                        );
                        if (!this.dryRun) this._updateState({ pendingPayment: null });
                        pendingPayment = null;
                    }
                }
                if (pendingPayment && (ppStatus.state === 'pending' || ppStatus.state === 'committed')) {
                    if (this.dryRun) {
                        const plan = {
                            action: 'wait_payment_finalization',
                            tokenId: this.tokenId,
                            paymentTxHash: pendingPayment.paymentTxHash,
                            toSeq: pendingPayment.toSeq,
                        };
                        this.log(`[dry-run] pending payment recovery plan ${JSON.stringify(plan)}`);
                        return {
                            synced: syncResult.added,
                            localSeq,
                            anchoredSeq: prev?.toSeq ?? 0,
                            anchored: false,
                            dryRun: true,
                            plan,
                        };
                    }
                    try {
                        await waitForFinalizedPolling(c, pendingPayment.paymentTxHash);
                        pendingPayment = { ...pendingPayment, status: 'finalized' };
                        this._updateState({ pendingPayment });
                    } catch (waitErr) {
                        if (/was rejected:/.test(waitErr.message)) {
                            this.log(`pending payment tx ${pendingPayment.paymentTxHash} rejected; clearing pendingPayment`);
                            this._updateState({ pendingPayment: null });
                            pendingPayment = null;
                        } else {
                            throw waitErr;
                        }
                    }
                } else if (pendingPayment && ppStatus.state === 'finalized') {
                    const failed =
                        ppStatus.summary?.transactionType === 'failed' || Boolean(ppStatus.summary?.rejectReason);
                    if (failed) {
                        this.log(`pending payment tx ${pendingPayment.paymentTxHash} failed on chain; clearing pendingPayment`);
                        if (!this.dryRun) this._updateState({ pendingPayment: null });
                        pendingPayment = null;
                    } else if (pendingPayment.status !== 'finalized' && !this.dryRun) {
                        pendingPayment = { ...pendingPayment, status: 'finalized' };
                        this._updateState({ pendingPayment });
                    }
                }
            }

            if (pendingPayment) {
                if (!this.witnessUrl) {
                    throw new Error(
                        `pending payment ${pendingPayment.paymentTxHash} targets witness ${pendingPayment.witnessUrl}; --witness-url is required to resume`,
                    );
                }
                if (normalizeWitnessBaseUrl(this.witnessUrl) !== normalizeWitnessBaseUrl(pendingPayment.witnessUrl)) {
                    throw new Error(
                        `pending payment ${pendingPayment.paymentTxHash} targets witness ${pendingPayment.witnessUrl}, not ${this.witnessUrl}`,
                    );
                }
                if (this.dryRun) {
                    const plan = {
                        action: 'resume_witness_payment',
                        tokenId: this.tokenId,
                        paymentTxHash: pendingPayment.paymentTxHash,
                        toSeq: pendingPayment.toSeq,
                        commitment: pendingPayment.commitment,
                        prevAnchorTx: pendingPayment.prevAnchorTx,
                    };
                    this.log(`[dry-run] pending payment recovery plan ${JSON.stringify(plan)}`);
                    return {
                        synced: syncResult.added,
                        localSeq,
                        anchoredSeq: prev?.toSeq ?? 0,
                        anchored: false,
                        dryRun: true,
                        plan,
                    };
                }
                const signer = this._resolveSigner();
                if (signer.address !== agent.ownerAccount) {
                    throw new Error(
                        `signer ${signer.address} must exactly match registered owner ${agent.ownerAccount} (CIS-8004.setMetadata rejects account aliases)`,
                    );
                }
                if (remainingOwnerBudget < 1) {
                    throw new Error(
                        `owner nonce span ${history.ownerNonceSpan} + 1 exceeds maxOwnerTxs=${history.maxOwnerTxs}; refusing to resume pending witness payment`,
                    );
                }
                const witnessCtx = await this._verifyWitnessAlignment({
                    c,
                    tipBlockHash,
                    agent,
                    history,
                    onChainWitness,
                });
                const latestBeforeAnchor = await readMetadataText(this.tokenId, ANCHOR_KEY, { nodeClient: c });
                if (latestBeforeAnchor !== pendingPayment.prevAnchorTx) {
                    throw new Error('countersign.anchor moved concurrently; refusing to resume pending witness payment');
                }
                const witnessRes = await this.requestWitnessAnchorFn({
                    witnessUrl: this.witnessUrl,
                    tokenId: this.tokenId,
                    toSeq: pendingPayment.toSeq,
                    commitment: pendingPayment.commitment,
                    prevAnchorTx: pendingPayment.prevAnchorTx,
                    paymentSignature: pendingPayment.paymentSignature,
                    payFn: null,
                    expectedPayTo: witnessCtx.health.payTo,
                    maxPriceMicroCcd: this.maxPriceMicroCcd,
                    expectedWitnessAccount: witnessCtx.health.witnessAccount,
                    allowPrivate: this.allowPrivateWitness,
                });
                const { rd } = await verifyWitnessAnchorOnChain({
                    nodeClient: c,
                    txHash: witnessRes.txHash,
                    activeWitness: witnessCtx.activeWitness,
                    tokenId: this.tokenId,
                    toSeq: pendingPayment.toSeq,
                    commitmentHex: pendingPayment.commitment,
                    prevAnchorTx: pendingPayment.prevAnchorTx,
                });
                let currentPending = {
                    txHash: witnessRes.txHash,
                    status: 'finalized',
                    expiryEpochSeconds: null,
                    tokenId: this.tokenId,
                    toSeq: pendingPayment.toSeq,
                    commitment: pendingPayment.commitment,
                    prevAnchorTx: pendingPayment.prevAnchorTx,
                    sender: rd.sender,
                    submittedAt: this.wallClock().toISOString(),
                    metadataTx: null,
                };
                this._updateState({
                    lastAnchoredSeq: prev?.toSeq ?? 0,
                    lastAnchoredTxHash: pendingPayment.prevAnchorTx,
                    lastAnchoredCommitment: prev?.commitment ?? null,
                    lastAnchoredAt: prev?.blockTime ?? null,
                    pendingPayment: null,
                    pendingAnchor: currentPending,
                });
                pendingPayment = null;
                this.log(`anchored seq 1..${currentPending.toSeq}: ${EXPLORER_TX(witnessRes.txHash)}`);
                await this._submitPointerUpdate({
                    c,
                    signer,
                    anchorTxHash: witnessRes.txHash,
                    expectedPrevTx: currentPending.prevAnchorTx,
                    expectedOwnerAccount: agent.ownerAccount,
                    expectedActiveWitness: witnessCtx.activeWitness,
                    expectedSetNonce: null,
                    witnessCtx,
                    getPending: () => currentPending,
                    setPending: (nextP) => {
                        currentPending = nextP;
                    },
                });
                const anchoredAt = this.wallClock().toISOString();
                this._updateState({
                    lastAnchoredSeq: currentPending.toSeq,
                    lastAnchoredTxHash: witnessRes.txHash,
                    lastAnchoredCommitment: currentPending.commitment,
                    lastAnchoredAt: anchoredAt,
                    pendingAnchor: null,
                    pendingPayment: null,
                });
                this.lastAnchorMs = this.now();
                this.log(`registry entry now points at seq 1..${currentPending.toSeq}: ${EXPLORER_TX(witnessRes.txHash)}`);
                resumedWitnessPaymentTxHash = witnessRes.txHash;
                resumedPendingOnThisTick = true;
                await applyRefreshedSnapshot({ preserveTimerForTxHash: witnessRes.txHash });
            }
        }

        const anchoredSeq = prev?.toSeq ?? 0;
        const due =
            shouldAnchor({
                localSeq,
                anchoredSeq,
                lastAnchorMs: this.lastAnchorMs,
                nowMs: this.now(),
                everyRecords: this.everyRecords,
                everySeconds: this.everySeconds,
            }) ||
            (this.once && noThresholds && localSeq > anchoredSeq);

        if (!due) {
            return {
                synced: syncResult.added,
                localSeq,
                anchoredSeq,
                anchored: resumedWitnessPaymentTxHash !== null,
                ...(resumedWitnessPaymentTxHash ? { txHash: resumedWitnessPaymentTxHash } : {}),
                dryRun: this.dryRun,
            };
        }

        const toSeq = localSeq;
        const commitmentBuf = this.trail.commitmentsBySeq.get(toSeq);
        const commitmentHex = commitmentBuf.toString('hex');
        const prevAnchorTx = prev?.txHash ?? null;
        const data = encodeAnchor({
            tokenId: this.tokenId,
            toSeq,
            commitment: commitmentBuf,
            prevAnchorTx,
        });

        const useWitnessAnchor = Boolean(this.witnessUrl && !this.hasCustomSubmitAnchor);
        if (!this.witnessUrl && !this.hasCustomSubmitAnchor && witnessStateAtTip.currentWitness !== null) {
            throw new Error(
                `token ${this.tokenId} has active ${WITNESS_KEY} (${witnessStateAtTip.currentWitness}); --witness-url is required and self-anchoring is disabled`,
            );
        }

        if (this.dryRun) {
            const plan = {
                action: 'anchor',
                tokenId: this.tokenId,
                fromSeq: anchoredSeq + 1,
                toSeq,
                commitment: commitmentHex,
                prevAnchorTx,
                bytes: data.length,
            };
            this.log(`[dry-run] anchor plan ${JSON.stringify(plan)}`);
            return {
                synced: syncResult.added,
                localSeq,
                anchoredSeq,
                anchored: false,
                dryRun: true,
                plan,
            };
        }

        const signer = this._resolveSigner();
        if (signer.address !== agent.ownerAccount) {
            throw new Error(
                `signer ${signer.address} must exactly match registered owner ${agent.ownerAccount} (CIS-8004.setMetadata rejects account aliases)`,
            );
        }

        const payerSigner =
            useWitnessAnchor && !this.paymentSignature && !this.payFn
                ? (this.payerSigner ?? (this.payerKeyfile ? loadSignerFromFile(this.payerKeyfile) : signer))
                : null;
        const ownerPaysTransfer = Boolean(
            useWitnessAnchor &&
                !this.paymentSignature &&
                !this.payFn &&
                payerSigner &&
                isSameAccount(payerSigner.address, agent.ownerAccount),
        );
        const requiredOwnerTxs = useWitnessAnchor ? (ownerPaysTransfer ? 2 : 1) : 2;
        if (remainingOwnerBudget < requiredOwnerTxs) {
            throw new Error(
                `owner nonce span ${history.ownerNonceSpan} + ${requiredOwnerTxs} exceeds maxOwnerTxs=${history.maxOwnerTxs}; refusing to submit anchor`,
            );
        }

        const witnessCtx = this.witnessUrl
            ? await this._verifyWitnessAlignment({ c, tipBlockHash, agent, history, onChainWitness })
            : null;

        const latestBeforeAnchor = await readMetadataText(this.tokenId, ANCHOR_KEY, { nodeClient: c });
        if (latestBeforeAnchor !== prevAnchorTx) {
            throw new Error('countersign.anchor moved concurrently; refusing to overwrite pointer');
        }

        let expectedAnchorNonce = null;
        if (!useWitnessAnchor) {
            const anchorNonceBlockHash = resumedPendingOnThisTick
                ? (await withRpcRetry(() => c.getConsensusStatus())).lastFinalizedBlock
                : tipBlockHash;
            const accForAnchor = await withRpcRetry(() => c.getAccountInfo(signer.sender, anchorNonceBlockHash));
            expectedAnchorNonce = BigInt(accForAnchor.accountNonce.value);
        }

        let signedAnchorMeta = null;
        let currentPending = null;
        const onAnchorSigned = ({ txHash: signedHash, expiryEpochSeconds }) => {
            signedAnchorMeta = { txHash: signedHash, expiryEpochSeconds };
            currentPending = {
                txHash: signedHash,
                status: 'signed',
                expiryEpochSeconds,
                tokenId: this.tokenId,
                toSeq,
                commitment: commitmentHex,
                prevAnchorTx,
                sender: signer.address,
                submittedAt: this.wallClock().toISOString(),
                metadataTx: null,
            };
            this._updateState({
                lastAnchoredSeq: anchoredSeq,
                lastAnchoredTxHash: prevAnchorTx,
                lastAnchoredCommitment: prev?.commitment ?? null,
                lastAnchoredAt: prev?.blockTime ?? null,
                pendingAnchor: currentPending,
            });
        };

        let txHash;
        let sender;
        if (useWitnessAnchor) {
            const witnessRes = await this.requestWitnessAnchorFn({
                witnessUrl: this.witnessUrl,
                tokenId: this.tokenId,
                toSeq,
                commitment: commitmentHex,
                prevAnchorTx,
                paymentSignature: this.paymentSignature,
                payFn: this._buildWitnessPayFn(
                    c,
                    signer,
                    witnessCtx,
                    { toSeq, commitment: commitmentHex, prevAnchorTx },
                    payerSigner,
                ),
                expectedPayTo: witnessCtx.health.payTo,
                maxPriceMicroCcd: this.maxPriceMicroCcd,
                expectedWitnessAccount: witnessCtx.health.witnessAccount,
                allowPrivate: this.allowPrivateWitness,
            });
            const { rd } = await verifyWitnessAnchorOnChain({
                nodeClient: c,
                txHash: witnessRes.txHash,
                activeWitness: witnessCtx.activeWitness,
                tokenId: this.tokenId,
                toSeq,
                commitmentHex,
                prevAnchorTx,
            });
            txHash = witnessRes.txHash;
            sender = rd.sender;
        } else {
            const submitted = await this.submitAnchor({
                tokenId: this.tokenId,
                toSeq,
                commitment: commitmentHex,
                prevAnchorTx,
                data,
                signer,
                nodeClient: c,
                onSigned: onAnchorSigned,
                expectedNonce: expectedAnchorNonce,
            });
            txHash = submitted?.txHash ?? submitted?.hash;
            if (!TX_RE.test(txHash ?? '')) {
                throw new Error(`submitAnchor returned invalid txHash: ${txHash}`);
            }
            sender = submitted?.sender ?? signer.address;
        }

        currentPending = {
            txHash,
            status: 'finalized',
            expiryEpochSeconds: signedAnchorMeta?.txHash === txHash ? signedAnchorMeta.expiryEpochSeconds : null,
            tokenId: this.tokenId,
            toSeq,
            commitment: commitmentHex,
            prevAnchorTx,
            sender,
            submittedAt: currentPending?.submittedAt ?? this.wallClock().toISOString(),
            metadataTx: null,
        };
        this._updateState({
            lastAnchoredSeq: anchoredSeq,
            lastAnchoredTxHash: prevAnchorTx,
            lastAnchoredCommitment: prev?.commitment ?? null,
            lastAnchoredAt: prev?.blockTime ?? null,
            pendingPayment: null,
            pendingAnchor: currentPending,
        });
        this.log(`anchored seq 1..${toSeq}: ${EXPLORER_TX(txHash)}`);

        await this._submitPointerUpdate({
            c,
            signer,
            anchorTxHash: txHash,
            expectedPrevTx: prevAnchorTx,
            expectedOwnerAccount: agent.ownerAccount,
            expectedActiveWitness: witnessCtx?.activeWitness ?? witnessStateAtTip.currentWitness,
            expectedSetNonce: useWitnessAnchor ? null : expectedAnchorNonce + 1n,
            witnessCtx,
            getPending: () => currentPending,
            setPending: (nextP) => {
                currentPending = nextP;
            },
        });
        const anchoredAt = this.wallClock().toISOString();
        this._updateState({
            lastAnchoredSeq: toSeq,
            lastAnchoredTxHash: txHash,
            lastAnchoredCommitment: commitmentHex,
            lastAnchoredAt: anchoredAt,
            pendingAnchor: null,
            pendingPayment: null,
        });
        this.lastAnchorMs = this.now();
        this._syncTipFromAnchor(
            {
                txHash,
                toSeq,
                commitment: commitmentHex,
            },
            agent.ownerAccount,
            witnessCtx?.witnessState ?? witnessStateAtTip,
        );
        this.log(`registry entry now points at seq 1..${toSeq}: ${EXPLORER_TX(txHash)}`);

        return {
            synced: syncResult.added,
            localSeq,
            anchoredSeq: toSeq,
            anchored: true,
            txHash,
            dryRun: false,
        };
    }

    _withWorkerLocks(fn) {
        return withFileLock(
            this.lockPath,
            () => withFileLock(this.tokenLockPath, fn, { wallClock: this.wallClock }),
            { wallClock: this.wallClock },
        );
    }

    /** Executes one locked tick (sync trail + reconcile/anchor). */
    async tick() {
        if (this._activeCall) {
            throw new Error(`AnchorWorker ${this._activeCall} already active on this instance`);
        }
        this._activeCall = 'tick';
        try {
            return await this._withWorkerLocks(() => this.reconcileAndAnchor());
        } finally {
            this._activeCall = null;
        }
    }

    async _sleepWithAbort(ms) {
        if (ms <= 0 || this.signal?.aborted) return;
        if (this.customSleep) {
            await this.customSleep(ms, this.signal);
            return;
        }
        await new Promise((resolve) => {
            let settled = false;
            const finish = () => {
                if (settled) return;
                settled = true;
                clearTimeout(timer);
                this.signal?.removeEventListener('abort', finish);
                resolve();
            };
            const timer = setTimeout(finish, ms);
            this.signal?.addEventListener('abort', finish, { once: true });
        });
    }

    /** Runs either a single locked tick (--once) or continuous locked polling loop until AbortSignal aborts. */
    async run() {
        if (this._activeCall) {
            throw new Error(`AnchorWorker ${this._activeCall} already active on this instance`);
        }
        this._activeCall = 'run';
        try {
            return await this._withWorkerLocks(async () => {
                if (this.signal?.aborted) return null;
                if (this.once) {
                    return this.reconcileAndAnchor();
                }

                let consecutiveFailures = 0;
                while (!this.signal?.aborted) {
                    let delaySec;
                    try {
                        await this.reconcileAndAnchor();
                        consecutiveFailures = 0;
                        delaySec = this.pollSeconds;
                    } catch (err) {
                        if (this.signal?.aborted) break;
                        consecutiveFailures += 1;
                        const expWait = Math.min(this.maxBackoffSeconds, this.pollSeconds * 2 ** (consecutiveFailures - 1));
                        const jitter = 0.5 + 0.5 * this.random();
                        delaySec = Math.min(this.maxBackoffSeconds, expWait * jitter);
                        this.log(`watch error (attempt ${consecutiveFailures}): ${err.message}; retrying in ${delaySec.toFixed(1)}s`);
                    }
                    if (this.signal?.aborted) break;
                    await this._sleepWithAbort(Math.max(1, Math.round(delaySec * 1000)));
                }
                return null;
            });
        } finally {
            this._activeCall = null;
        }
    }
}

/** Instantiates and runs an AnchorWorker with the provided options. */
export function runAnchorWorker(opts) {
    return new AnchorWorker(opts).run();
}
