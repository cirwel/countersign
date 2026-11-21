// Crash-safe, stream-driven automatic anchoring worker for Countersign.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
    ANCHOR_KEY,
    EXPLORER_TX,
    TX_RE,
    UUID_KEY,
    applyNodeOptions,
    assertTestnet,
    client,
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

function defaultSubmitAnchor({ data, signer, nodeClient }) {
    return sendRegisterData(data, signer, nodeClient).then((res) => ({
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
        this.lockPath = lockPath ?? `${this.statePath}.lock`;
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
        this._lockHeld = false;
    }

    _resolveSigner() {
        if (!this.signer) this.signer = this._loadSigner();
        return this.signer;
    }

    _acquireLock() {
        fs.mkdirSync(path.dirname(this.lockPath), { recursive: true });
        const lockBody = JSON.stringify({
            pid: process.pid,
            startedAt: this.wallClock().toISOString(),
            token: crypto.randomUUID(),
        }) + '\n';

        const tryCreate = () => {
            fs.writeFileSync(this.lockPath, lockBody, { flag: 'wx', mode: 0o600 });
        };

        try {
            tryCreate();
            return lockBody;
        } catch (err) {
            if (err?.code !== 'EEXIST') throw err;
        }

        let raw;
        try {
            raw = fs.readFileSync(this.lockPath, 'utf8');
        } catch (err) {
            if (err?.code === 'ENOENT') {
                try {
                    tryCreate();
                    return lockBody;
                } catch (retryErr) {
                    if (retryErr?.code === 'EEXIST') {
                        throw new Error(`lockfile ${this.lockPath} is held by another worker`);
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
            throw new Error(`corrupt lockfile ${this.lockPath}; remove manually if no worker is running`);
        }
        const pid = existing?.pid;
        if (!Number.isInteger(pid) || pid <= 0) {
            throw new Error(`invalid pid in lockfile ${this.lockPath}`);
        }
        if (isPidAlive(pid)) {
            throw new Error(`lockfile ${this.lockPath} is already held by active process ${pid}`);
        }

        try {
            fs.unlinkSync(this.lockPath);
        } catch (err) {
            if (err?.code !== 'ENOENT') throw err;
        }
        try {
            tryCreate();
            return lockBody;
        } catch (err) {
            if (err?.code === 'EEXIST') {
                throw new Error(`lockfile ${this.lockPath} is held by another worker`);
            }
            throw err;
        }
    }

    _releaseLock(lockBody) {
        try {
            const current = fs.readFileSync(this.lockPath, 'utf8');
            if (current === lockBody) fs.unlinkSync(this.lockPath);
        } catch (err) {
            if (err?.code !== 'ENOENT') throw err;
        }
    }

    async _withLock(fn) {
        if (this._lockHeld) return fn();
        const lockBody = this._acquireLock();
        this._lockHeld = true;
        try {
            return await fn();
        } finally {
            this._lockHeld = false;
            this._releaseLock(lockBody);
        }
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
        }
        return parsed;
    }

    _writeState(fields) {
        const payload = {
            version: 1,
            agentUuid: this.uuid,
            tokenId: this.tokenId,
            ...fields,
            updatedAt: this.wallClock().toISOString(),
        };
        writeFileAtomic(this.statePath, JSON.stringify(payload, null, 2) + '\n');
        return payload;
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
            const { header, records } = readTrail(this.trailPath);
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
            const wanted = new Set(records.map((_, i) => i + 1));
            const { last, count, at } = commitments(header, records, wanted);
            baseTrail = {
                header,
                lastSeq: count,
                lastCheckpointId: records.at(-1)?.checkpoint_id ?? null,
                commitment: last,
                commitmentsBySeq: at,
            };
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

    /** Syncs trail, reconciles chain history and pending anchors, and anchors if threshold is met. */
    async reconcileAndAnchor() {
        const syncResult = await this.syncTrail();
        const c = this.nodeClient ?? (await client());
        await assertTestnet(c);

        const cs = await withRpcRetry(() => c.getConsensusStatus());
        const tipBlockHash = cs.lastFinalizedBlock;
        const tipBlockHeight = cs.lastFinalizedBlockHeight;

        const agent = await readAgentOf(this.tokenId, { blockHash: tipBlockHash, nodeClient: c });
        if (!agent) throw new Error(`registry token ${this.tokenId} is not registered`);
        if (agent.status && agent.status !== 'Active') {
            throw new Error(`registry token ${this.tokenId} status is ${agent.status}; refusing to anchor`);
        }

        const onChainUuid = await readMetadataText(this.tokenId, UUID_KEY, { blockHash: tipBlockHash, nodeClient: c });
        if (onChainUuid !== null && onChainUuid !== this.uuid) {
            throw new Error(`on-chain ${UUID_KEY} (${onChainUuid}) does not match worker uuid ${this.uuid}`);
        }

        const current = await readMetadataText(this.tokenId, ANCHOR_KEY, { blockHash: tipBlockHash, nodeClient: c });
        if (current !== null && !TX_RE.test(current)) {
            throw new Error(`metadata ${ANCHOR_KEY} is not a transaction hash`);
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

        const state = this._readState();
        if (state?.pendingAnchor) {
            const pending = state.pendingAnchor;
            if (current === pending.txHash) {
                if (
                    !prev ||
                    prev.toSeq !== pending.toSeq ||
                    prev.commitment !== pending.commitment ||
                    prev.prevAnchorTx !== pending.prevAnchorTx
                ) {
                    throw new Error(`pending anchor ${pending.txHash} disagrees with on-chain anchor record`);
                }
                this.log(`pending anchor ${pending.txHash} (seq 1..${prev.toSeq}) already landed on chain; clearing pending state`);
                if (!this.dryRun) {
                    this._writeState({
                        lastAnchoredSeq: prev.toSeq,
                        lastAnchoredTxHash: prev.txHash,
                        lastAnchoredCommitment: prev.commitment,
                        lastAnchoredAt: prev.blockTime ?? this.wallClock().toISOString(),
                        pendingAnchor: null,
                    });
                }
            } else {
                const rd = await readRegisterData(pending.txHash, c);
                const d = decodeAnchor(rd.data);
                const expectedPrevTx = prev?.txHash ?? null;
                const expectedCommitment = this.trail.commitmentsBySeq.get(d.toSeq)?.toString('hex');
                const valid =
                    d.tokenId === this.tokenId &&
                    d.toSeq === pending.toSeq &&
                    d.toSeq > (prev?.toSeq ?? 0) &&
                    d.toSeq <= this.trail.lastSeq &&
                    Boolean(expectedCommitment) &&
                    d.commitment === expectedCommitment &&
                    d.commitment === pending.commitment &&
                    d.prevAnchorTx === expectedPrevTx &&
                    pending.prevAnchorTx === expectedPrevTx &&
                    isSameAccount(rd.sender, agent.ownerAccount) &&
                    (!pending.sender || isSameAccount(rd.sender, pending.sender));
                if (!valid) {
                    throw new Error(`pending anchor ${pending.txHash} does not match current trail/chain state; refusing to resume`);
                }

                if (this.dryRun) {
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
                        localSeq: this.trail.lastSeq,
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
                if (!isSameAccount(rd.sender, signer.address)) {
                    throw new Error(`pending anchor ${pending.txHash} sender ${rd.sender} does not match signer ${signer.address}`);
                }

                const latestBeforeSet = await readMetadataText(this.tokenId, ANCHOR_KEY, { nodeClient: c });
                if (latestBeforeSet !== expectedPrevTx) {
                    throw new Error('countersign.anchor moved concurrently; refusing to overwrite pointer');
                }

                await this.setMetadata(this.tokenId, ANCHOR_KEY, pending.txHash, signer, c);
                const anchoredAt = this.wallClock().toISOString();
                this._writeState({
                    lastAnchoredSeq: d.toSeq,
                    lastAnchoredTxHash: pending.txHash,
                    lastAnchoredCommitment: d.commitment,
                    lastAnchoredAt: anchoredAt,
                    pendingAnchor: null,
                });
                this.lastAnchorMs = this.now();
                this.log(`resumed pending anchor seq 1..${d.toSeq}: ${EXPLORER_TX(pending.txHash)}`);
                prev = {
                    txHash: pending.txHash,
                    tokenId: this.tokenId,
                    toSeq: d.toSeq,
                    commitment: d.commitment,
                    prevAnchorTx: d.prevAnchorTx,
                    sender: rd.sender,
                    blockTime: rd.blockTime ?? anchoredAt,
                };
            }
        }

        const localSeq = this.trail.lastSeq;
        const anchoredSeq = prev?.toSeq ?? 0;
        const nowMs = this.now();
        const noThresholds = this.everyRecords === null && this.everySeconds === null;
        const due =
            shouldAnchor({
                localSeq,
                anchoredSeq,
                lastAnchorMs: this.lastAnchorMs,
                nowMs,
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

        const submitted = await this.submitAnchor({
            tokenId: this.tokenId,
            toSeq,
            commitment: commitmentHex,
            prevAnchorTx,
            data,
            signer,
            nodeClient: c,
        });
        const txHash = submitted?.txHash ?? submitted?.hash;
        if (!TX_RE.test(txHash ?? '')) {
            throw new Error(`submitAnchor returned invalid txHash: ${txHash}`);
        }
        const sender = submitted?.sender ?? signer.address;

        this._writeState({
            lastAnchoredSeq: anchoredSeq,
            lastAnchoredTxHash: prevAnchorTx,
            lastAnchoredCommitment: prev?.commitment ?? null,
            lastAnchoredAt: prev?.blockTime ?? null,
            pendingAnchor: {
                txHash,
                tokenId: this.tokenId,
                toSeq,
                commitment: commitmentHex,
                prevAnchorTx,
                sender,
                submittedAt: this.wallClock().toISOString(),
            },
        });
        this.log(`anchored seq 1..${toSeq}: ${EXPLORER_TX(txHash)}`);

        const latestBeforeSet = await readMetadataText(this.tokenId, ANCHOR_KEY, { nodeClient: c });
        if (latestBeforeSet !== prevAnchorTx) {
            throw new Error('countersign.anchor moved concurrently; refusing to overwrite pointer');
        }

        await this.setMetadata(this.tokenId, ANCHOR_KEY, txHash, signer, c);
        const anchoredAt = this.wallClock().toISOString();
        this._writeState({
            lastAnchoredSeq: toSeq,
            lastAnchoredTxHash: txHash,
            lastAnchoredCommitment: commitmentHex,
            lastAnchoredAt: anchoredAt,
            pendingAnchor: null,
        });
        this.lastAnchorMs = this.now();
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
    tick() {
        return this._withLock(() => this.reconcileAndAnchor());
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
        return this._withLock(async () => {
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
                await this._sleepWithAbort(Math.round(delaySec * 1000));
            }
            return null;
        });
    }
}

/** Instantiates and runs an AnchorWorker with the provided options. */
export function runAnchorWorker(opts) {
    return new AnchorWorker(opts).run();
}
