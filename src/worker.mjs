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
    applyNodeOptions,
    assertTestnet,
    client,
    getTransactionState,
    isSameAccount,
    loadAnchorsFromHistory,
    loadSigner,
    readAgentOf,
    readMetadataText,
    readRegisterData,
    readRegistryHistory,
    sendRegisterData,
    sendSetMetadata,
    verifyExistingAnchors,
    waitForFinalizedPolling,
    withRpcRetry,
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
    stepHash,
} from './trail.mjs';

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

/** Returns the canonical exclusive lockfile path derived from the trail file path. */
export function trailLockPath(trailPath) {
    return `${canonicalTrailPath(trailPath)}.lock`;
}

/** Atomically writes bytes or UTF-8 string via same-directory temp file + fsync + rename. */
export function writeFileAtomic(filePath, content) {
    const dir = path.dirname(filePath);
    fs.mkdirSync(dir, { recursive: true });
    const tmpPath = path.join(dir, `.${path.basename(filePath)}.tmp.${process.pid}.${crypto.randomUUID()}`);
    const fd = fs.openSync(tmpPath, 'w', 0o600);
    try {
        const buf = typeof content === 'string' ? Buffer.from(content, 'utf8') : Buffer.from(content);
        let offset = 0;
        while (offset < buf.length) {
            offset += fs.writeSync(fd, buf, offset, buf.length - offset);
        }
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
    try {
        fs.renameSync(tmpPath, filePath);
    } catch (err) {
        try {
            fs.unlinkSync(tmpPath);
        } catch {}
        throw err;
    }
    try {
        const dirFd = fs.openSync(dir, 'r');
        try {
            fs.fsyncSync(dirFd);
        } finally {
            fs.closeSync(dirFd);
        }
    } catch {}
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

/** Acquires an exclusive lockfile with mutually exclusive stale-PID takeover and runs `fn`, releasing in finally. */
export async function withFileLock(
    lockPath,
    fn,
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

    const tryCreate = () => {
        fs.writeFileSync(lockPath, lockBody, { flag: 'wx', mode: 0o600 });
    };

    const acquire = () => {
        try {
            tryCreate();
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
                    tryCreate();
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
                    tryCreate();
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
                tryCreate();
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

    const acquired = acquire();
    try {
        return await fn();
    } finally {
        try {
            if (fs.readFileSync(lockPath, 'utf8') === acquired) {
                fs.unlinkSync(lockPath);
            }
        } catch (err) {
            if (err?.code !== 'ENOENT') throw err;
        }
    }
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

function defaultSubmitAnchor({ data, signer, nodeClient, onSigned }) {
    return sendRegisterData(data, signer, nodeClient, onSigned ? { onSigned } : undefined).then((res) => ({
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
    return (
        v !== null &&
        typeof v === 'object' &&
        !Array.isArray(v) &&
        TX_RE.test(v.txHash ?? '') &&
        (v.expiryEpochSeconds === undefined ||
            v.expiryEpochSeconds === null ||
            (typeof v.expiryEpochSeconds === 'number' && Number.isFinite(v.expiryEpochSeconds) && v.expiryEpochSeconds >= 0))
    );
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
            psql,
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
        this.trailPath = trailPath;
        this.statePath = statePath ?? `${trailPath}.anchor-state.json`;
        this.lockPath = lockPath ? canonicalTrailPath(lockPath) : trailLockPath(trailPath);
        this.psql = psql;
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
        this.source = source ?? ((afterSeq) => fetchCheckpointsAfter({ uuid: this.uuid, afterSeq, psql: this.psql }));
        this.submitAnchor = submitAnchor;
        this.setMetadata = setMetadata;
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

    _readState() {
        if (!fs.existsSync(this.statePath)) return null;
        let parsed;
        try {
            parsed = JSON.parse(fs.readFileSync(this.statePath, 'utf8'));
        } catch (err) {
            throw new Error(`corrupt anchor state file ${this.statePath}: ${err.message}`);
        }
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            throw new Error(`invalid anchor state file ${this.statePath}: expected JSON object`);
        }
        if (parsed.agentUuid !== undefined && parsed.agentUuid !== this.uuid) {
            throw new Error(`state file ${this.statePath} agentUuid ${parsed.agentUuid} does not match ${this.uuid}`);
        }
        if (parsed.tokenId !== undefined && String(parsed.tokenId) !== this.tokenId) {
            throw new Error(`state file ${this.statePath} tokenId ${parsed.tokenId} does not match ${this.tokenId}`);
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
                throw new Error(`corrupt pendingAnchor in ${this.statePath}`);
            }
            if (p.tokenId !== undefined && String(p.tokenId) !== this.tokenId) {
                throw new Error(`pendingAnchor tokenId ${p.tokenId} does not match ${this.tokenId}`);
            }
            if (p.metadataTx !== undefined && p.metadataTx !== null && !isTxRefObj(p.metadataTx)) {
                throw new Error(`corrupt pendingAnchor.metadataTx in ${this.statePath}`);
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
                throw new Error(`corrupt trailAppend in ${this.statePath}`);
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
            trailAppend: null,
            ...current,
            ...patch,
            updatedAt: this.wallClock().toISOString(),
        };
        writeFileAtomic(this.statePath, JSON.stringify(payload, null, 2) + '\n');
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
                lastSeq: count,
                lastCheckpointId: records.at(-1)?.checkpoint_id ?? null,
                commitment: last,
                commitmentsBySeq: at,
            };
        };

        try {
            const loaded = readAndValidate();
            const existingState = this._readState();
            if (existingState?.trailAppend && !this.dryRun) {
                this._updateState({ trailAppend: null });
            }
            return loaded;
        } catch (readErr) {
            const existingState = this._readState();
            const ta = existingState?.trailAppend;
            if (!ta) throw readErr;

            const curSize = fs.statSync(this.trailPath).size;
            if (curSize <= ta.baseSize) throw readErr;

            const prefixBuf = Buffer.alloc(ta.baseSize);
            const fd = fs.openSync(this.trailPath, 'r');
            try {
                let totalRead = 0;
                while (totalRead < ta.baseSize) {
                    const n = fs.readSync(fd, prefixBuf, totalRead, ta.baseSize - totalRead, totalRead);
                    if (n === 0) break;
                    totalRead += n;
                }
                if (totalRead !== ta.baseSize) throw readErr;
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
    }

    /** Initializes or reads/verifies the trail file, then fetches and durably appends any new checkpoints. */
    async syncTrail() {
        let baseTrail;
        if (!fs.existsSync(this.trailPath)) {
            const header = checkHeader({
                schema: SCHEMA,
                source: 'unitares core.checkpoints',
                agent_uuid: this.uuid,
                token_id: this.tokenId,
                registry: { network: NETWORK, ...REGISTRY },
            });
            writeFileAtomic(this.trailPath, canonical(header) + '\n');
            baseTrail = {
                header,
                lastSeq: 0,
                lastCheckpointId: null,
                commitment: genesisHash(header),
                commitmentsBySeq: new Map(),
            };
        } else {
            baseTrail = this._loadOrRecoverExistingTrail();
        }

        this.trail = baseTrail;
        const rows = await this.source(baseTrail.lastSeq);
        if (!Array.isArray(rows)) {
            throw new Error('checkpoint source must return an array');
        }
        if (rows.length === 0) {
            return { ...baseTrail, added: 0 };
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

        const payload = Buffer.from(lines.join(''), 'utf8');
        try {
            const originalSize = fs.statSync(this.trailPath).size;
            if (!this.dryRun) {
                this._updateState({ trailAppend: { baseSize: originalSize, targetSeq: nextSeq } });
            }
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
            if (!this.dryRun) {
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
            this.trail = baseTrail;
            throw err;
        }
    }

    _syncTipFromAnchor(anchorRecord, agentOwnerAccount) {
        this._verifiedTip = {
            pointer: anchorRecord?.txHash ?? null,
            ownerAccount: agentOwnerAccount,
            anchoredSeq: anchorRecord?.toSeq ?? 0,
        };
        if (anchorRecord?.txHash) {
            this._lastSeenAnchorTxHash = anchorRecord.txHash;
        }
    }

    /** Syncs trail, reconciles chain history and pending anchors, and anchors if threshold is met. */
    async reconcileAndAnchor() {
        const syncResult = await this.syncTrail();
        const state = this._readState();

        const c = this.nodeClient ?? (await client());
        await assertTestnet(c);

        const cs = await withRpcRetry(() => c.getConsensusStatus());
        const tipBlockHash = cs.lastFinalizedBlock;
        const tipBlockHeight = cs.lastFinalizedBlockHeight;

        const agent = await readAgentOf(this.tokenId, { blockHash: tipBlockHash, nodeClient: c });
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

        // Idle-poll fast path: skip expensive history scans when pointer, owner, and pending state are unchanged and !due.
        if (
            this._verifiedTip !== null &&
            !state?.pendingAnchor &&
            current === this._verifiedTip.pointer &&
            agent.ownerAccount === this._verifiedTip.ownerAccount &&
            localSeq >= this._verifiedTip.anchoredSeq
        ) {
            const cachedAnchoredSeq = this._verifiedTip.anchoredSeq;
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

        const history = await readRegistryHistory(this.tokenId, {
            tipBlockHash,
            tipBlockHeight,
            agent,
            hintAnchorTxHashes: current ? [current] : [],
            nodeClient: c,
        });
        const existing = await loadAnchorsFromHistory(history, c, tipBlockHeight);
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
        this._syncTipFromAnchor(prev, agent.ownerAccount);

        if (state?.pendingAnchor) {
            let pending = state.pendingAnchor;
            const clearPending = (extraPatch = {}) => {
                if (!this.dryRun) {
                    this._updateState({ pendingAnchor: null, ...extraPatch });
                }
            };

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
                    const metaStatus = await getTransactionState(metaTx.txHash, c);
                    const finishLandedMetadata = () => {
                        const anchoredAt = this.wallClock().toISOString();
                        clearPending({
                            lastAnchoredSeq: pending.toSeq,
                            lastAnchoredTxHash: pending.txHash,
                            lastAnchoredCommitment: pending.commitment,
                            lastAnchoredAt: anchoredAt,
                        });
                        this.lastAnchorMs = this.now();
                        this.log(`resumed pending metadata tx ${metaTx.txHash} for anchor ${pending.txHash}`);
                        current = pending.txHash;
                        prev = {
                            txHash: pending.txHash,
                            tokenId: this.tokenId,
                            toSeq: pending.toSeq,
                            commitment: pending.commitment,
                            prevAnchorTx: pending.prevAnchorTx,
                            sender: pending.sender ?? agent.ownerAccount,
                            blockTime: anchoredAt,
                        };
                        this._syncTipFromAnchor(prev, agent.ownerAccount);
                        metadataHandled = true;
                    };

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
                                finishLandedMetadata();
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
                                finishLandedMetadata();
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
                    } else if (metaStatus.state === 'absent') {
                        const nowEpochSec = Math.floor(this.wallClock().getTime() / 1000);
                        if (nowEpochSec <= (metaTx.expiryEpochSeconds ?? Infinity)) {
                            throw new Error(
                                `pending metadata tx ${metaTx.txHash} in-flight/ambiguous until expiry ${metaTx.expiryEpochSeconds}`,
                            );
                        }
                        this.log(`pending metadata tx ${metaTx.txHash} expired without landing; clearing metadataTx`);
                        pending = { ...pending, metadataTx: null };
                        if (!this.dryRun) this._updateState({ pendingAnchor: pending });
                    }
                }

                if (!metadataHandled) {
                    const rdStatus = await getTransactionState(pending.txHash, c);
                    let pendingCleared = false;

                    if (rdStatus.state === 'pending' || rdStatus.state === 'committed') {
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
                        } catch (waitErr) {
                            if (/was rejected:/.test(waitErr.message)) {
                                this.log(`pending registerData tx ${pending.txHash} rejected; clearing pending state`);
                                clearPending();
                                pendingCleared = true;
                            } else {
                                throw waitErr;
                            }
                        }
                    } else if (rdStatus.state === 'absent') {
                        const nowEpochSec = Math.floor(this.wallClock().getTime() / 1000);
                        if (nowEpochSec <= (pending.expiryEpochSeconds ?? Infinity)) {
                            throw new Error(
                                `pending registerData tx ${pending.txHash} ambiguous before expiry ${pending.expiryEpochSeconds ?? 'unknown'}`,
                            );
                        }
                        this.log(`pending registerData tx ${pending.txHash} expired without landing; clearing pending state`);
                        clearPending();
                        pendingCleared = true;
                    } else if (rdStatus.state === 'finalized') {
                        const failed = rdStatus.summary?.transactionType === 'failed' || Boolean(rdStatus.summary?.rejectReason);
                        if (failed) {
                            this.log(`pending registerData tx ${pending.txHash} failed on chain; clearing pending state`);
                            clearPending();
                            pendingCleared = true;
                        }
                    }

                    if (!pendingCleared) {
                        const rd = await readRegisterData(pending.txHash, c);
                        const d = decodeAnchor(rd.data);
                        const expectedPrevTx = prev?.txHash ?? null;
                        const expectedCommitment = this.trail.commitmentsBySeq.get(d.toSeq)?.toString('hex');
                        const integrityOk =
                            d.tokenId === this.tokenId &&
                            d.toSeq === pending.toSeq &&
                            d.toSeq <= localSeq &&
                            Boolean(expectedCommitment) &&
                            d.commitment === expectedCommitment &&
                            d.commitment === pending.commitment &&
                            isSameAccount(rd.sender, agent.ownerAccount) &&
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
                            const signer = this._resolveSigner();
                            if (signer.address !== agent.ownerAccount) {
                                throw new Error(
                                    `signer ${signer.address} must exactly match registered owner ${agent.ownerAccount} (CIS-8004.setMetadata rejects account aliases)`,
                                );
                            }
                            if (!isSameAccount(rd.sender, signer.address)) {
                                throw new Error(
                                    `pending anchor ${pending.txHash} sender ${rd.sender} does not match signer ${signer.address}`,
                                );
                            }

                            const latestBeforeSet = await readMetadataText(this.tokenId, ANCHOR_KEY, { nodeClient: c });
                            if (latestBeforeSet !== expectedPrevTx) {
                                throw new Error('countersign.anchor moved concurrently; refusing to overwrite pointer');
                            }

                            const onMetadataSigned = ({ txHash: metaTxHash, expiryEpochSeconds: metaExpiry }) => {
                                pending = {
                                    ...pending,
                                    status: 'finalized',
                                    metadataTx: { txHash: metaTxHash, expiryEpochSeconds: metaExpiry },
                                };
                                this._updateState({ pendingAnchor: pending });
                            };

                            await this.setMetadata(this.tokenId, ANCHOR_KEY, pending.txHash, signer, c, {
                                onSigned: onMetadataSigned,
                            });
                            const anchoredAt = this.wallClock().toISOString();
                            clearPending({
                                lastAnchoredSeq: d.toSeq,
                                lastAnchoredTxHash: pending.txHash,
                                lastAnchoredCommitment: d.commitment,
                                lastAnchoredAt: anchoredAt,
                            });
                            this.lastAnchorMs = this.now();
                            this.log(`resumed pending anchor seq 1..${d.toSeq}: ${EXPLORER_TX(pending.txHash)}`);
                            current = pending.txHash;
                            prev = {
                                txHash: pending.txHash,
                                tokenId: this.tokenId,
                                toSeq: d.toSeq,
                                commitment: d.commitment,
                                prevAnchorTx: d.prevAnchorTx,
                                sender: rd.sender,
                                blockTime: rd.blockTime ?? anchoredAt,
                            };
                            this._syncTipFromAnchor(prev, agent.ownerAccount);
                        }
                    }
                }
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
                anchored: false,
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

        const latestBeforeAnchor = await readMetadataText(this.tokenId, ANCHOR_KEY, { nodeClient: c });
        if (latestBeforeAnchor !== prevAnchorTx) {
            throw new Error('countersign.anchor moved concurrently; refusing to overwrite pointer');
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

        const submitted = await this.submitAnchor({
            tokenId: this.tokenId,
            toSeq,
            commitment: commitmentHex,
            prevAnchorTx,
            data,
            signer,
            nodeClient: c,
            onSigned: onAnchorSigned,
        });
        const txHash = submitted?.txHash ?? submitted?.hash;
        if (!TX_RE.test(txHash ?? '')) {
            throw new Error(`submitAnchor returned invalid txHash: ${txHash}`);
        }
        const sender = submitted?.sender ?? signer.address;

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
            pendingAnchor: currentPending,
        });
        this.log(`anchored seq 1..${toSeq}: ${EXPLORER_TX(txHash)}`);

        const latestBeforeSet = await readMetadataText(this.tokenId, ANCHOR_KEY, { nodeClient: c });
        if (latestBeforeSet !== prevAnchorTx) {
            throw new Error('countersign.anchor moved concurrently; refusing to overwrite pointer');
        }

        const onMetadataSigned = ({ txHash: metaTxHash, expiryEpochSeconds: metaExpiry }) => {
            currentPending = {
                ...currentPending,
                metadataTx: { txHash: metaTxHash, expiryEpochSeconds: metaExpiry },
            };
            this._updateState({ pendingAnchor: currentPending });
        };

        await this.setMetadata(this.tokenId, ANCHOR_KEY, txHash, signer, c, {
            onSigned: onMetadataSigned,
        });
        const anchoredAt = this.wallClock().toISOString();
        this._updateState({
            lastAnchoredSeq: toSeq,
            lastAnchoredTxHash: txHash,
            lastAnchoredCommitment: commitmentHex,
            lastAnchoredAt: anchoredAt,
            pendingAnchor: null,
        });
        this.lastAnchorMs = this.now();
        this._syncTipFromAnchor(
            {
                txHash,
                toSeq,
            },
            agent.ownerAccount,
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

    /** Executes one locked tick (sync trail + reconcile/anchor). */
    async tick() {
        if (this._activeCall) {
            throw new Error(`AnchorWorker ${this._activeCall} already active on this instance`);
        }
        this._activeCall = 'tick';
        try {
            return await withFileLock(this.lockPath, () => this.reconcileAndAnchor(), { wallClock: this.wallClock });
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
            return await withFileLock(
                this.lockPath,
                async () => {
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
                },
                { wallClock: this.wallClock },
            );
        } finally {
            this._activeCall = null;
        }
    }
}

/** Instantiates and runs an AnchorWorker with the provided options. */
export function runAnchorWorker(opts) {
    return new AnchorWorker(opts).run();
}
