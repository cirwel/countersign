import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, test } from 'node:test';
import { AccountAddress, ReturnValue, Transaction, TransactionHash, buildBasicAccountSigner } from '@concordium/web-sdk';
import { TESTNET_GENESIS } from '../src/chain.mjs';
import {
    buildCheckpointStreamSql,
    fetchCheckpointsAfter,
    parseDatabaseUrlToPgEnv,
    parsePsqlCommand,
} from '../src/checkpoints.mjs';
import { encodeBadge, encodeTokenId } from '../src/cis8004.mjs';
import { commands } from '../src/cli.mjs';
import { REGISTRY, REGISTRY_MODULE_REF } from '../src/registry.mjs';
import { canonical, commitments, decodeAnchor, encodeAnchor, readTrail, writeTrail } from '../src/trail.mjs';
import { AnchorWorker, runAnchorWorker, shouldAnchor, trailLockPath, withFileLock } from '../src/worker.mjs';

const AGENT_UUID = '907e3195-c649-49db-b753-1edc1a105f33';
const TOKEN_ID = '1315';
const BADGE = encodeBadge(TOKEN_ID);
const GENESIS_PREFIX = TESTNET_GENESIS.slice(0, 32);
const OWNER_A = '4NAnnhZUSYiyJLM9k6H7dVPn1uuPGStu2LZEety7zmp1LBYw41';
const OWNER_A_ALIAS = AccountAddress.getAlias(AccountAddress.fromBase58(OWNER_A), 1).address;
const OWNER_B = '3dt3UMPzRASZndjmKpSWgCP2HhmoxZrgs8FDPtZjNHZzj13hhB';

const tempDirs = [];
afterEach(() => {
    while (tempDirs.length > 0) {
        fs.rmSync(tempDirs.pop(), { recursive: true, force: true });
    }
});

function makeTempDir() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'countersign-worker-test-'));
    tempDirs.push(dir);
    return dir;
}

const u32le = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n, 0);
    return b;
};

const u64le = (n) => {
    const b = Buffer.alloc(8);
    b.writeBigUInt64LE(BigInt(n), 0);
    return b;
};

const acctBytes = (b58) => Buffer.from(AccountAddress.fromBase58(b58).decodedAddress);
const txHashFor = (label) => crypto.createHash('sha256').update(label).digest('hex');

const evMint = (tokenId, owner) =>
    Buffer.concat([Buffer.from([0xfe]), encodeTokenId(tokenId), Buffer.from([1, 0]), acctBytes(owner)]);

const evMetadataSet = (tokenId, key, valueUtf8, tsMs = 1700000000000) => {
    const k = Buffer.from(key, 'utf8');
    const v = Buffer.from(valueUtf8, 'utf8');
    return Buffer.concat([Buffer.from([0xf3]), encodeTokenId(tokenId), u32le(k.length), k, u32le(v.length), v, u64le(tsMs)]);
};

function encodeAgentOfReturn(agent) {
    if (!agent) return Buffer.from([0]);
    const uriBuf = Buffer.from(agent.agentUri, 'utf8');
    const hashBuf = Buffer.from(agent.metadataHashHex, 'hex');
    return Buffer.concat([
        Buffer.from([1]),
        encodeTokenId(agent.tokenId),
        acctBytes(agent.ownerAccount),
        Buffer.from([1]),
        u32le(uriBuf.length),
        uriBuf,
        Buffer.from([1]),
        hashBuf,
        Buffer.from([0]),
        Buffer.from([0]),
        Buffer.from([agent.status === 'Revoked' ? 1 : 0]),
        u64le(agent.registeredAtMs),
        Buffer.from([0]),
        Buffer.from([0]),
        u32le(0),
    ]);
}

function encodeGetMetadataReturn(val) {
    if (val === null || val === undefined) return Buffer.from([0]);
    const b = Buffer.from(val, 'utf8');
    return Buffer.concat([Buffer.from([1]), u32le(b.length), b]);
}

function makeCardBytes({ badge = BADGE, ownerAccount = OWNER_A } = {}) {
    const card = {
        name: 'WorkerTestAgent',
        capabilities: {
            extensions: [
                {
                    uri: 'https://docs.concordium.com/a2a-extensions/concordium-badge/v1',
                    params: {
                        tokenAddress: `ccd:${GENESIS_PREFIX}/cis-2:${badge}`,
                        owner: { account: `ccd:${GENESIS_PREFIX}:${ownerAccount}` },
                        contracts: { cis8004: `ccd:${GENESIS_PREFIX}:${REGISTRY.index}.${REGISTRY.subindex}` },
                    },
                },
            ],
        },
    };
    const bytes = Buffer.from(JSON.stringify(card), 'utf8');
    return { bytes, hashHex: crypto.createHash('sha256').update(bytes).digest('hex') };
}

function makeRecord(seq, prevId = seq === 1 ? null : `cp-${seq - 1}`, excerpt = `report ${seq}`) {
    const sec = String(seq % 60).padStart(2, '0');
    const min = String(Math.floor(seq / 60) % 60).padStart(2, '0');
    return {
        seq,
        checkpoint_id: `cp-${seq}`,
        prev_checkpoint_id: prevId,
        recorded_at: `2026-11-21T00:${min}:${sec}.123456Z`,
        report_excerpt: excerpt,
        provenance: { producer: 'sync_state', seq },
    };
}

function makeSigner(address = OWNER_A) {
    return {
        address,
        sender: AccountAddress.fromBase58(address),
        signer: buildBasicAccountSigner(crypto.randomBytes(32).toString('hex')),
    };
}

function blockHashFor(h) {
    return {
        height: BigInt(h),
        toString() {
            return `block-${h}`;
        },
    };
}

function createMutableMockNode({
    genesisBlock = TESTNET_GENESIS,
    tipHeight = 2000n,
    regHeight = 1000n,
    owner = OWNER_A,
    status = 'Active',
    uuid = AGENT_UUID,
    includeUuidMetadata = true,
    onInvokeContract = null,
    onSendTransaction = null,
    statusForHash = null,
    onRpc = null,
} = {}) {
    const baseTimeMs = 1700000000000;
    const card = makeCardBytes({ ownerAccount: owner });
    const timeForHeight = (h) => baseTimeMs + Number(h) * 2000;
    const agent = {
        tokenId: TOKEN_ID,
        ownerAccount: owner,
        agentUri: 'https://agent.example/card.json',
        metadataHashHex: card.hashHex,
        status,
        registeredAtMs: timeForHeight(regHeight),
    };

    const state = {
        tipHeight,
        metadata: includeUuidMetadata ? { 'unitares.agent_uuid': uuid } : {},
        txsByHeight: new Map(),
        registerDataByHash: new Map(),
        nonceChanges: [],
        submitted: [],
        submitSeq: 0,
    };

    const addTx = (tx) => {
        const h = BigInt(tx.height);
        if (!state.txsByHeight.has(h)) state.txsByHeight.set(h, []);
        state.txsByHeight.get(h).push(tx);
        if (tx.sender) state.nonceChanges.push({ sender: tx.sender, height: h });
        if (tx.registerData) state.registerDataByHash.set(tx.hash, tx);
        if (h > state.tipHeight) state.tipHeight = h;
    };

    addTx({ height: regHeight, hash: txHashFor('mint'), sender: owner, contractEvents: [evMint(TOKEN_ID, owner)] });

    const heightFromBlockHash = (bh) => {
        if (typeof bh?.height === 'bigint') return bh.height;
        const m = /^block-(\d+)$/.exec(String(bh));
        if (!m) throw new Error(`unknown mock blockHash ${bh}`);
        return BigInt(m[1]);
    };

    const node = {
        card,
        agent,
        state,
        submitted: state.submitted,
        addRegisterData({ sender = owner, data, txHash, height }) {
            const h = BigInt(height ?? state.tipHeight + 1n);
            const hash = txHash ?? txHashFor(`rd-${++state.submitSeq}`);
            const buf = Buffer.from(data);
            addTx({ height: h, hash, sender, registerData: buf });
            return { txHash: hash, sender, height: h };
        },
        addSetMetadata({ sender = owner, key = 'countersign.anchor', value, txHash, height }) {
            const h = BigInt(height ?? state.tipHeight + 1n);
            const hash = txHash ?? txHashFor(`meta-${++state.submitSeq}`);
            state.metadata[key] = value;
            addTx({ height: h, hash, sender, contractEvents: [evMetadataSet(TOKEN_ID, key, value)] });
            return { hash, height: h };
        },
        async getConsensusStatus() {
            return {
                genesisBlock: { toString: () => genesisBlock },
                lastFinalizedBlock: blockHashFor(state.tipHeight),
                lastFinalizedBlockHeight: state.tipHeight,
            };
        },
        async getBlocksAtHeight(h) {
            return [blockHashFor(BigInt(h))];
        },
        async getBlockInfo(bh) {
            const h = heightFromBlockHash(bh);
            return { blockHeight: h, blockSlotTime: new Date(timeForHeight(h)) };
        },
        async getAccountInfo(acct, bh) {
            onRpc?.('getAccountInfo', bh);
            const h = heightFromBlockHash(bh);
            let count = 1n;
            for (const nc of state.nonceChanges) {
                if (nc.height <= h && nc.sender === acct.address) count += 1n;
            }
            return { accountNonce: { value: count } };
        },
        async getNextAccountNonce(acct) {
            onRpc?.('getNextAccountNonce', acct.address);
            let count = 1n;
            for (const nc of state.nonceChanges) {
                if (nc.sender === acct.address) count += 1n;
            }
            return { nonce: { value: count } };
        },
        async getInstanceInfo() {
            onRpc?.('getInstanceInfo');
            return { sourceModule: { moduleRef: REGISTRY_MODULE_REF } };
        },
        async instanceStateLookup() {
            onRpc?.('instanceStateLookup');
            const err = new Error('Key not found');
            err.code = 'NOT_FOUND';
            throw err;
        },
        async *getBlockTransactionEvents(bh) {
            onRpc?.('getBlockTransactionEvents', bh);
            const h = heightFromBlockHash(bh);
            const list = state.txsByHeight.get(h) ?? [];
            for (const tx of list) {
                if (tx.registerData) {
                    yield {
                        type: 'accountTransaction',
                        transactionType: 'registerData',
                        hash: { toString: () => tx.hash },
                        sender: { address: tx.sender },
                        dataRegistered: { data: tx.registerData.toString('hex') },
                    };
                } else {
                    yield {
                        type: 'accountTransaction',
                        transactionType: 'update',
                        hash: { toString: () => tx.hash },
                        sender: { address: tx.sender },
                        events: [
                            {
                                tag: 'Updated',
                                address: { index: BigInt(REGISTRY.index), subindex: BigInt(REGISTRY.subindex) },
                                events: (tx.contractEvents ?? []).map((buf) => ({ buffer: buf })),
                            },
                        ],
                    };
                }
            }
        },
        async getBlockItemStatus(txHash) {
            const hHex = txHash.toString();
            onRpc?.('getBlockItemStatus', hHex);
            if (statusForHash) {
                const custom = await statusForHash(hHex, node);
                if (custom !== undefined) return custom;
            }
            const tx = state.registerDataByHash.get(hHex);
            if (tx) {
                return {
                    status: 'finalized',
                    outcome: {
                        blockHash: blockHashFor(tx.height),
                        summary: {
                            transactionType: 'registerData',
                            sender: { address: tx.sender },
                            dataRegistered: { data: tx.registerData.toString('hex') },
                        },
                    },
                };
            }
            for (const [h, list] of state.txsByHeight.entries()) {
                for (const item of list) {
                    if (item.hash === hHex) {
                        return {
                            status: 'finalized',
                            outcome: {
                                blockHash: blockHashFor(h),
                                summary: {
                                    transactionType: 'update',
                                    sender: { address: item.sender },
                                    events: [],
                                },
                            },
                        };
                    }
                }
            }
            const err = new Error(`mock tx ${hHex} not found`);
            err.code = 'NOT_FOUND';
            throw err;
        },
        async sendTransaction(signed) {
            const hashHex = Buffer.from(Transaction.getAccountTransactionHash(signed)).toString('hex');
            const sender = signed.header.sender.address;
            const entry = { hashHex, payload: signed.payload, sender };
            state.submitted.push(entry);
            if (onSendTransaction) await onSendTransaction(entry, node);
            if (signed.payload?.type === 21) {
                const dataBuf = Buffer.from(signed.payload.data.data);
                node.addRegisterData({ sender, data: dataBuf, txHash: hashHex });
            } else {
                const p = Buffer.from(signed.payload.message.buffer);
                const klen = p.readUInt32LE(9);
                const key = p.subarray(13, 13 + klen).toString('utf8');
                const vlen = p.readUInt32LE(13 + klen);
                const val = p.subarray(17 + klen, 17 + klen + vlen).toString('utf8');
                node.addSetMetadata({ sender, key, value: val, txHash: hashHex });
            }
            return TransactionHash.fromHexString(hashHex);
        },
        async invokeContract(ctx, bh) {
            if (onInvokeContract) {
                const custom = onInvokeContract(ctx, bh, node);
                if (custom) return custom;
            }
            const method = ctx.method.value ?? String(ctx.method);
            if (method === 'CIS-8004.agentOf') {
                return { tag: 'success', usedEnergy: { value: 1000n }, returnValue: ReturnValue.fromBuffer(encodeAgentOfReturn(agent)) };
            }
            if (method === 'CIS-8004.getMetadata') {
                const p = Buffer.from(ctx.parameter.buffer);
                const klen = p.readUInt32LE(9);
                const key = p.subarray(13, 13 + klen).toString('utf8');
                return {
                    tag: 'success',
                    usedEnergy: { value: 1000n },
                    returnValue: ReturnValue.fromBuffer(encodeGetMetadataReturn(state.metadata[key] ?? null)),
                };
            }
            if (method === 'CIS-8004.getAdmin') {
                return { tag: 'success', usedEnergy: { value: 1000n }, returnValue: ReturnValue.fromBuffer(Buffer.from([0])) };
            }
            if (method === 'CIS-8004.setMetadata') {
                return { tag: 'success', usedEnergy: { value: 1500n }, returnValue: ReturnValue.empty() };
            }
            return { tag: 'failure', usedEnergy: { value: 500n }, reason: { tag: 'InvalidReceive' } };
        },
    };
    return node;
}

function findDeadPid() {
    for (let pid = 999999; pid >= 100000; pid -= 1) {
        try {
            process.kill(pid, 0);
        } catch (err) {
            if (err && err.code === 'ESRCH') return pid;
        }
    }
    throw new Error('no dead pid found');
}

test('parsePsqlCommand handles quoting, escapes, env defaults, and invalid inputs', () => {
    assert.deepEqual(parsePsqlCommand(undefined, {}), ['psql', '-d', 'governance']);
    assert.deepEqual(parsePsqlCommand(undefined, { DATABASE_URL: 'postgres://localhost/gov' }), ['psql']);
    assert.deepEqual(parsePsqlCommand(undefined, { PGDATABASE: 'unitares' }), ['psql']);
    assert.deepEqual(parsePsqlCommand('psql -h localhost -d gov', { DATABASE_URL: 'postgres://ignored' }), ['psql', '-h', 'localhost', '-d', 'gov']);

    assert.deepEqual(
        parsePsqlCommand(`/opt/pg/psql --set="a=1 2" 'postgresql://u:p@h/db?sslmode=require' -d "foo\\"bar\\\\baz" foo\\ bar --empty=''`),
        ['/opt/pg/psql', '--set=a=1 2', 'postgresql://u:p@h/db?sslmode=require', '-d', 'foo"bar\\baz', 'foo bar', '--empty='],
    );

    assert.throws(() => parsePsqlCommand(''), /empty/);
    assert.throws(() => parsePsqlCommand('   \t '), /empty/);
    assert.throws(() => parsePsqlCommand('""'), /empty/);
    assert.throws(() => parsePsqlCommand("psql 'unclosed"), /unbalanced quotes/);
    assert.throws(() => parsePsqlCommand('psql "unclosed\\"'), /unbalanced quotes/);
    assert.throws(() => parsePsqlCommand('psql \\'), /unbalanced escape/);
});

test('buildCheckpointStreamSql & fetchCheckpointsAfter preserve escapes/NULLs, validate continuity, and power cli export', async () => {
    assert.throws(() => buildCheckpointStreamSql({ uuid: "not-a-uuid' OR 1=1--" }), /invalid agent UUID/);
    assert.throws(() => buildCheckpointStreamSql({ uuid: AGENT_UUID, afterSeq: -1 }), /non-negative safe integer/);
    assert.throws(() => buildCheckpointStreamSql({ uuid: AGENT_UUID, afterSeq: 1.5 }), /non-negative safe integer/);

    const sql = buildCheckpointStreamSql({ uuid: AGENT_UUID, afterSeq: 10 });
    assert.match(sql, /FROM core\.checkpoint_outbox o/);
    assert.match(sql, /JOIN core\.checkpoints c ON c\.checkpoint_id = o\.event_id AND c\.identity_id = o\.identity_id AND c\.seq = o\.seq/);
    assert.match(sql, /COALESCE\(c\.report_excerpt, ''\)/);
    assert.match(sql, /o\.event_schema = 'checkpoint\.recorded\.v1'/);
    assert.match(sql, /o\.seq > 10/);

    const r1 = makeRecord(1, null, 'back\\\\slash "quote" \'sq\'\nline2\rCR 😀 ～');
    const r2 = makeRecord(2, 'cp-1', ''); // simulates NULL COALESCE(report_excerpt, '')

    let capturedCall = null;
    const rows = fetchCheckpointsAfter({
        uuid: AGENT_UUID,
        afterSeq: 0,
        psql: 'psql "dbname=my db"',
        execFile: (bin, args, opts) => {
            capturedCall = { bin, args, opts };
            return `${JSON.stringify(r1)}\n${JSON.stringify(r2)}\n`;
        },
    });
    assert.equal(capturedCall.bin, 'psql');
    assert.deepEqual(capturedCall.args.slice(0, 7), ['dbname=my db', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-At', '-c']);
    assert.equal(capturedCall.opts.env.PGCLIENTENCODING, 'UTF8');
    assert.match(capturedCall.opts.env.PGOPTIONS, /default_transaction_read_only=on/);
    assert.equal(rows.length, 2);
    assert.equal(rows[0].report_excerpt, 'back\\\\slash "quote" \'sq\'\nline2\rCR 😀 ～');
    assert.equal(rows[1].report_excerpt, '');

    // Empty result set
    assert.deepEqual(fetchCheckpointsAfter({ uuid: AGENT_UUID, afterSeq: 5, execFile: () => '' }), []);

    // Reject non-monotonic seq, gaps, and broken prev_checkpoint_id links
    assert.throws(
        () => fetchCheckpointsAfter({ uuid: AGENT_UUID, afterSeq: 5, execFile: () => `${JSON.stringify(makeRecord(5, 'cp-4'))}\n` }),
        /strictly greater than 5/,
    );
    assert.throws(
        () => fetchCheckpointsAfter({ uuid: AGENT_UUID, afterSeq: 5, execFile: () => `${JSON.stringify(makeRecord(7, 'cp-6'))}\n` }),
        /expected seq 6, found 7/,
    );
    assert.throws(
        () =>
            fetchCheckpointsAfter({
                uuid: AGENT_UUID,
                afterSeq: 0,
                execFile: () => `${JSON.stringify(makeRecord(1, null))}\n${JSON.stringify(makeRecord(3, 'cp-1'))}\n`,
            }),
        /expected seq 2, found 3/,
    );
    assert.throws(
        () =>
            fetchCheckpointsAfter({
                uuid: AGENT_UUID,
                afterSeq: 0,
                execFile: () => `${JSON.stringify(makeRecord(1, null))}\n${JSON.stringify(makeRecord(2, 'wrong-prev'))}\n`,
            }),
        /does not link/,
    );
    assert.throws(
        () => fetchCheckpointsAfter({ uuid: AGENT_UUID, afterSeq: 5, execFile: () => `${JSON.stringify(makeRecord(6, null))}\n` }),
        /prev_checkpoint_id/,
    );

    // commands.export reuses fetchCheckpointsAfter + parsePsqlCommand cleanly
    const dir = makeTempDir();
    const outPath = path.join(dir, 'exported.jsonl');
    const origLog = console.log;
    console.log = () => {};
    try {
        await commands.export({
            uuid: AGENT_UUID,
            token: TOKEN_ID,
            out: outPath,
            psql: 'psql -d testgov',
            execFile: () => `${JSON.stringify(r1)}\n${JSON.stringify(r2)}\n`,
        });
    } finally {
        console.log = origLog;
    }
    const parsed = readTrail(outPath);
    assert.equal(parsed.records.length, 2);
    assert.equal(parsed.records[0].report_excerpt, r1.report_excerpt);
});

test('shouldAnchor enforces record delta, monotonic time delta, and null lastAnchorMs', () => {
    assert.equal(shouldAnchor({ localSeq: 5, anchoredSeq: 5, lastAnchorMs: null, nowMs: 1000, everyRecords: 1, everySeconds: 1 }), false);
    assert.equal(shouldAnchor({ localSeq: 4, anchoredSeq: 5, lastAnchorMs: null, nowMs: 1000, everyRecords: 1, everySeconds: 1 }), false);
    assert.equal(shouldAnchor({ localSeq: 7, anchoredSeq: 5, lastAnchorMs: 1000, nowMs: 2000, everyRecords: 3, everySeconds: null }), false);
    assert.equal(shouldAnchor({ localSeq: 8, anchoredSeq: 5, lastAnchorMs: 1000, nowMs: 2000, everyRecords: 3, everySeconds: null }), true);
    assert.equal(shouldAnchor({ localSeq: 6, anchoredSeq: 5, lastAnchorMs: null, nowMs: 100, everyRecords: null, everySeconds: 60 }), true);
    assert.equal(shouldAnchor({ localSeq: 6, anchoredSeq: 5, lastAnchorMs: 1000, nowMs: 60999, everyRecords: null, everySeconds: 60 }), false);
    assert.equal(shouldAnchor({ localSeq: 6, anchoredSeq: 5, lastAnchorMs: 1000, nowMs: 61000, everyRecords: null, everySeconds: 60 }), true);
});

test('AnchorWorker initializes trail, tails incrementally, preserves commitment continuity, and verifies end-to-end', async () => {
    const dir = makeTempDir();
    const trailPath = path.join(dir, 'agent.jsonl');
    const cardPath = path.join(dir, 'card.json');
    const node = createMutableMockNode();
    fs.writeFileSync(cardPath, node.card.bytes);
    const signer = makeSigner(OWNER_A);

    const stream = [makeRecord(1), makeRecord(2)];
    const worker = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath,
        everyRecords: 3,
        nodeClient: node,
        signer,
        source: (afterSeq) => stream.filter((r) => r.seq > afterSeq),
        log: () => {},
    });

    const origLog = console.log;
    console.log = () => {};
    let verified;
    try {
        // Tick 1: creates canonical header + records 1..2, below threshold 3 -> 0 anchors
        const t1 = await worker.tick();
        assert.equal(t1.synced, 2);
        assert.equal(t1.localSeq, 2);
        assert.equal(t1.anchored, false);
        assert.equal(node.submitted.length, 0);
        assert.equal(readTrail(trailPath).records.length, 2);

        // Tick 2: record 3 arrives -> hits everyRecords=3 -> anchors 1..3
        stream.push(makeRecord(3));
        const t2 = await worker.tick();
        assert.equal(t2.synced, 1);
        assert.equal(t2.localSeq, 3);
        assert.equal(t2.anchoredSeq, 3);
        assert.equal(t2.anchored, true);
        assert.equal(node.submitted.length, 2);

        // Tick 3: records 4..6 arrive -> chains anchor 1..6 onto first anchor
        stream.push(makeRecord(4), makeRecord(5), makeRecord(6));
        const t3 = await worker.tick();
        assert.equal(t3.anchored, true);
        assert.equal(t3.anchoredSeq, 6);
        assert.equal(node.submitted.length, 4);

        // Verify produced trail + anchors using real verify command!
        verified = await commands.verify({ badge: BADGE, trail: trailPath, card: cardPath, nodeClient: node });
    } finally {
        console.log = origLog;
    }
    assert.equal(verified, true);
});

test('AnchorWorker rolls back in-memory state and file tail if disk write fails during syncTrail', async (t) => {
    const dir = makeTempDir();
    const trailPath = path.join(dir, 'rollback.jsonl');
    const stream = [makeRecord(1)];

    const worker = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath,
        once: true,
        source: (afterSeq) => stream.filter((r) => r.seq > afterSeq),
        log: () => {},
    });

    await worker.syncTrail();
    const beforeBytes = fs.readFileSync(trailPath, 'utf8');
    assert.equal(worker.trail.lastSeq, 1);

    stream.push(makeRecord(2));
    const fsyncMock = t.mock.method(fs, 'fsyncSync', () => {
        throw new Error('simulated disk EIO');
    });
    await assert.rejects(() => worker.syncTrail(), /simulated disk EIO/);
    fsyncMock.mock.restore();

    // In-memory state and file on disk must both be rolled back to seq 1
    assert.equal(worker.trail.lastSeq, 1);
    assert.equal(worker.trail.lastCheckpointId, 'cp-1');
    assert.equal(fs.readFileSync(trailPath, 'utf8'), beforeBytes);

    // Next sync succeeds cleanly without gaps or duplicates
    const res = await worker.syncTrail();
    assert.equal(res.added, 1);
    assert.equal(res.lastSeq, 2);
    assert.equal(readTrail(trailPath).records.length, 2);
});

test('AnchorWorker --every-seconds respects injected monotonic clock', async () => {
    const dir = makeTempDir();
    const trailPath = path.join(dir, 'time-policy.jsonl');
    const node = createMutableMockNode();
    const signer = makeSigner(OWNER_A);
    let monoMs = 10_000;
    const stream = [makeRecord(1), makeRecord(2)];

    const worker = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath,
        everySeconds: 60,
        nodeClient: node,
        signer,
        source: (afterSeq) => stream.filter((r) => r.seq > afterSeq),
        now: () => monoMs,
        log: () => {},
    });

    const origLog = console.log;
    console.log = () => {};
    try {
        // First tick with lastAnchorMs === null triggers anchor at monoMs = 10_000
        const r1 = await worker.tick();
        assert.equal(r1.anchored, true);
        assert.equal(r1.anchoredSeq, 2);

        // Add record 3; 59.999s later -> NOT due yet
        stream.push(makeRecord(3));
        monoMs = 69_999;
        const r2 = await worker.tick();
        assert.equal(r2.anchored, false);

        // At exactly +60s -> triggers anchor for seq 1..3
        monoMs = 70_000;
        const r3 = await worker.tick();
        assert.equal(r3.anchored, true);
        assert.equal(r3.anchoredSeq, 3);
    } finally {
        console.log = origLog;
    }
});

test('AnchorWorker --once and --dry-run behave properly (zero chain/state writes, no signer needed)', async () => {
    const dir = makeTempDir();
    const trailPath = path.join(dir, 'dry.jsonl');
    const statePath = `${trailPath}.anchor-state.json`;
    const node = createMutableMockNode();
    const header = {
        schema: 'countersign.trail.v1',
        source: 'test',
        agent_uuid: AGENT_UUID,
        token_id: TOKEN_ID,
        registry: { network: 'testnet', ...REGISTRY },
    };
    writeTrail(trailPath, header, [makeRecord(1), makeRecord(2)]);

    const logs = [];
    let signerLoaded = false;
    await runAnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath,
        statePath,
        once: true,
        dryRun: true,
        nodeClient: node,
        loadSignerFn: () => {
            signerLoaded = true;
            throw new Error('signer must not be loaded in dryRun');
        },
        source: () => [],
        log: (m) => logs.push(m),
    });

    assert.equal(signerLoaded, false);
    assert.equal(node.submitted.length, 0);
    assert.equal(fs.existsSync(statePath), false);
    assert.ok(logs.some((l) => l.includes('[dry-run] anchor plan') && l.includes('"toSeq":2')));

    // --once WITH --every-records 5 and only 2 unanchored records does NOT anchor
    const resBelow = await runAnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath,
        statePath,
        once: true,
        everyRecords: 5,
        nodeClient: node,
        signer: makeSigner(OWNER_A),
        source: () => [],
        log: () => {},
    });
    assert.equal(resBelow.anchored, false);
    assert.equal(node.submitted.length, 0);

    // --once WITHOUT thresholds anchors unanchored records once
    const origLog = console.log;
    console.log = () => {};
    let resOnce;
    try {
        resOnce = await runAnchorWorker({
            uuid: AGENT_UUID,
            tokenId: TOKEN_ID,
            trailPath,
            statePath,
            once: true,
            nodeClient: node,
            signer: makeSigner(OWNER_A),
            source: () => [],
            log: () => {},
        });
    } finally {
        console.log = origLog;
    }
    assert.equal(resOnce.anchored, true);
    assert.equal(resOnce.anchoredSeq, 2);
});

test('AnchorWorker recovers from crash between submitAnchor and setMetadata with zero duplicate registerData', async () => {
    const dir = makeTempDir();
    const trailPath = path.join(dir, 'crash.jsonl');
    const statePath = `${trailPath}.anchor-state.json`;
    const node = createMutableMockNode();
    const signer = makeSigner(OWNER_A);
    const stream = [makeRecord(1), makeRecord(2)];

    let registerCalls = 0;
    let setMetadataCalls = 0;

    // Run 1: submitAnchor lands registerData, pendingAnchor persists atomically, then setMetadata crashes
    const crashingWorker = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath,
        statePath,
        everyRecords: 1,
        nodeClient: node,
        signer,
        source: (afterSeq) => stream.filter((r) => r.seq > afterSeq),
        submitAnchor: async ({ data, signer: s }) => {
            registerCalls += 1;
            const rd = node.addRegisterData({ sender: s.address, data });
            return { txHash: rd.txHash, sender: rd.sender };
        },
        setMetadata: async () => {
            setMetadataCalls += 1;
            throw new Error('simulated crash before setMetadata');
        },
        log: () => {},
    });

    await assert.rejects(() => crashingWorker.tick(), /simulated crash before setMetadata/);
    assert.equal(registerCalls, 1);
    assert.equal(setMetadataCalls, 1);
    const saved = JSON.parse(fs.readFileSync(statePath, 'utf8'));
    assert.ok(saved.pendingAnchor);
    assert.equal(saved.pendingAnchor.toSeq, 2);

    // Run 2: restart recovers pendingAnchor, skips registerData, calls ONLY setMetadata
    const recoveredWorker = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath,
        statePath,
        everyRecords: 1,
        nodeClient: node,
        signer,
        source: (afterSeq) => stream.filter((r) => r.seq > afterSeq),
        submitAnchor: async () => {
            registerCalls += 1;
            throw new Error('must NOT call submitAnchor again');
        },
        setMetadata: async (_tokenId, key, val, s) => {
            setMetadataCalls += 1;
            return node.addSetMetadata({ sender: s.address, key, value: val });
        },
        log: () => {},
    });

    const res = await recoveredWorker.tick();
    assert.equal(registerCalls, 1, 'must NOT submit duplicate registerData');
    assert.equal(setMetadataCalls, 2);
    assert.equal(res.anchoredSeq, 2);

    const afterState = JSON.parse(fs.readFileSync(statePath, 'utf8'));
    assert.equal(afterState.pendingAnchor, null);
    assert.equal(afterState.lastAnchoredSeq, 2);
    assert.equal(afterState.lastAnchoredTxHash, saved.pendingAnchor.txHash);
});

test('AnchorWorker clears pendingAnchor without chain writes when it already landed on chain', async () => {
    const dir = makeTempDir();
    const trailPath = path.join(dir, 'landed.jsonl');
    const statePath = `${trailPath}.anchor-state.json`;
    const node = createMutableMockNode();
    const signer = makeSigner(OWNER_A);

    const header = {
        schema: 'countersign.trail.v1',
        source: 'test',
        agent_uuid: AGENT_UUID,
        token_id: TOKEN_ID,
        registry: { network: 'testnet', ...REGISTRY },
    };
    const recs = [makeRecord(1), makeRecord(2)];
    writeTrail(trailPath, header, recs);
    const { last } = commitments(header, recs);
    const data = encodeAnchor({ tokenId: TOKEN_ID, toSeq: 2, commitment: last, prevAnchorTx: null });
    const rd = node.addRegisterData({ sender: OWNER_A, data });
    node.addSetMetadata({ sender: OWNER_A, value: rd.txHash });

    fs.writeFileSync(
        statePath,
        JSON.stringify({
            version: 1,
            agentUuid: AGENT_UUID,
            tokenId: TOKEN_ID,
            lastAnchoredSeq: 0,
            lastAnchoredTxHash: null,
            pendingAnchor: {
                txHash: rd.txHash,
                tokenId: TOKEN_ID,
                toSeq: 2,
                commitment: last.toString('hex'),
                prevAnchorTx: null,
                sender: OWNER_A,
            },
        }),
    );

    const worker = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath,
        statePath,
        everyRecords: 1,
        nodeClient: node,
        signer,
        source: () => [],
        submitAnchor: () => {
            throw new Error('must not submit');
        },
        setMetadata: () => {
            throw new Error('must not setMetadata');
        },
        log: () => {},
    });

    const res = await worker.tick();
    assert.equal(res.anchored, false);
    assert.equal(res.anchoredSeq, 2);
    const st = JSON.parse(fs.readFileSync(statePath, 'utf8'));
    assert.equal(st.pendingAnchor, null);
    assert.equal(st.lastAnchoredSeq, 2);
    assert.equal(st.lastAnchoredTxHash, rd.txHash);
});

test('AnchorWorker aborts cleanly on concurrent pointer move, trail drift, alias signer, and mainnet node', async () => {
    const dir = makeTempDir();
    const header = {
        schema: 'countersign.trail.v1',
        source: 'test',
        agent_uuid: AGENT_UUID,
        token_id: TOKEN_ID,
        registry: { network: 'testnet', ...REGISTRY },
    };

    // 1. Concurrent pointer move BEFORE submitAnchor -> 0 tx submitted
    {
        const trailPath = path.join(dir, 'race-before-rd.jsonl');
        writeTrail(trailPath, header, [makeRecord(1), makeRecord(2)]);
        let getMetaCalls = 0;
        const node = createMutableMockNode({
            onInvokeContract: (ctx) => {
                if (ctx.method.value === 'CIS-8004.getMetadata') {
                    getMetaCalls += 1;
                    // Calls 1=uuid, 2=anchor(tip), 3=latestBeforeAnchor
                    if (getMetaCalls === 3) {
                        return {
                            tag: 'success',
                            usedEnergy: { value: 1000n },
                            returnValue: ReturnValue.fromBuffer(encodeGetMetadataReturn(txHashFor('raced-1'))),
                        };
                    }
                }
            },
        });
        let submitCalled = false;
        const worker = new AnchorWorker({
            uuid: AGENT_UUID,
            tokenId: TOKEN_ID,
            trailPath,
            everyRecords: 1,
            nodeClient: node,
            signer: makeSigner(OWNER_A),
            source: () => [],
            submitAnchor: () => {
                submitCalled = true;
                return { txHash: txHashFor('unused'), sender: OWNER_A };
            },
            log: () => {},
        });
        await assert.rejects(() => worker.tick(), /moved concurrently/);
        assert.equal(submitCalled, false);
    }

    // 2. Concurrent pointer move BEFORE setMetadata -> pendingAnchor saved, setMetadata aborted
    {
        const trailPath = path.join(dir, 'race-before-set.jsonl');
        const statePath = `${trailPath}.anchor-state.json`;
        writeTrail(trailPath, header, [makeRecord(1), makeRecord(2)]);
        let getMetaCalls = 0;
        const node = createMutableMockNode({
            onInvokeContract: (ctx) => {
                if (ctx.method.value === 'CIS-8004.getMetadata') {
                    getMetaCalls += 1;
                    // Calls 1=uuid, 2=anchor(tip), 3=latestBeforeAnchor, 4=latestBeforeSet
                    if (getMetaCalls === 4) {
                        return {
                            tag: 'success',
                            usedEnergy: { value: 1000n },
                            returnValue: ReturnValue.fromBuffer(encodeGetMetadataReturn(txHashFor('raced-2'))),
                        };
                    }
                }
            },
        });
        let setCalled = false;
        const worker = new AnchorWorker({
            uuid: AGENT_UUID,
            tokenId: TOKEN_ID,
            trailPath,
            statePath,
            everyRecords: 1,
            nodeClient: node,
            signer: makeSigner(OWNER_A),
            source: () => [],
            submitAnchor: ({ data, signer: s }) => node.addRegisterData({ sender: s.address, data }),
            setMetadata: () => {
                setCalled = true;
            },
            log: () => {},
        });
        await assert.rejects(() => worker.tick(), /moved concurrently/);
        assert.equal(setCalled, false);
        assert.ok(JSON.parse(fs.readFileSync(statePath, 'utf8')).pendingAnchor);
    }

    // 3. Trail drift refusal
    {
        const trailPath = path.join(dir, 'drift.jsonl');
        const origRecs = [makeRecord(1), makeRecord(2)];
        const { last } = commitments(header, origRecs);
        const node = createMutableMockNode();
        const rd = node.addRegisterData({
            sender: OWNER_A,
            data: encodeAnchor({ tokenId: TOKEN_ID, toSeq: 2, commitment: last, prevAnchorTx: null }),
        });
        node.addSetMetadata({ sender: OWNER_A, value: rd.txHash });

        const tampered = [makeRecord(1), makeRecord(2, 'cp-1', 'TAMPERED')];
        writeTrail(trailPath, header, tampered);
        const worker = new AnchorWorker({
            uuid: AGENT_UUID,
            tokenId: TOKEN_ID,
            trailPath,
            everyRecords: 1,
            nodeClient: node,
            signer: makeSigner(OWNER_A),
            source: () => [],
            log: () => {},
        });
        await assert.rejects(() => worker.tick(), /does not match the anchor/);
    }

    // 4. Account alias signer refusal before submitting registerData
    {
        const trailPath = path.join(dir, 'alias.jsonl');
        writeTrail(trailPath, header, [makeRecord(1)]);
        const node = createMutableMockNode();
        let submitted = false;
        const worker = new AnchorWorker({
            uuid: AGENT_UUID,
            tokenId: TOKEN_ID,
            trailPath,
            everyRecords: 1,
            nodeClient: node,
            signer: makeSigner(OWNER_A_ALIAS),
            source: () => [],
            submitAnchor: () => {
                submitted = true;
                return { txHash: txHashFor('x'), sender: OWNER_A_ALIAS };
            },
            log: () => {},
        });
        await assert.rejects(() => worker.tick(), /must exactly match registered owner/);
        assert.equal(submitted, false);
    }

    // 5. Non-testnet genesis refusal
    {
        const trailPath = path.join(dir, 'mainnet.jsonl');
        writeTrail(trailPath, header, [makeRecord(1)]);
        const badNode = createMutableMockNode({ genesisBlock: '9dd9ca4d19e9393877d2c44b70f89acbfc0883c2243e5eeaecc0d1cd0503f478' });
        const worker = new AnchorWorker({
            uuid: AGENT_UUID,
            tokenId: TOKEN_ID,
            trailPath,
            everyRecords: 1,
            nodeClient: badNode,
            signer: makeSigner(OWNER_A),
            source: () => [],
            log: () => {},
        });
        await assert.rejects(() => worker.tick(), /not Concordium testnet/);
    }
});

test('AnchorWorker lockfile blocks concurrent live PIDs and cleans up stale PIDs', async () => {
    const dir = makeTempDir();
    const trailPath = path.join(dir, 'lock.jsonl');
    const statePath = `${trailPath}.anchor-state.json`;
    const lockPath = `${statePath}.lock`;
    const node = createMutableMockNode();
    const signer = makeSigner(OWNER_A);

    // Active PID in lockfile -> rejects
    fs.writeFileSync(lockPath, JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() }) + '\n');
    const worker = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath,
        statePath,
        lockPath,
        once: true,
        nodeClient: node,
        signer,
        source: () => [],
        log: () => {},
    });
    await assert.rejects(() => worker.tick(), /already held by active process/);

    // Stale dead PID in lockfile -> cleaned up, tick runs, lock released in finally
    const deadPid = findDeadPid();
    fs.writeFileSync(lockPath, JSON.stringify({ pid: deadPid, startedAt: new Date().toISOString() }) + '\n');
    await worker.tick();
    assert.equal(fs.existsSync(lockPath), false, 'lockfile must be released in finally');
});

test('AnchorWorker loop mode performs capped exponential backoff with jitter, resets on clean tick, and exits on AbortSignal', async () => {
    const dir = makeTempDir();
    const trailPath = path.join(dir, 'loop.jsonl');
    const lockPath = `${trailPath}.anchor-state.json.lock`;
    const node = createMutableMockNode();
    const signer = makeSigner(OWNER_A);
    const ac = new AbortController();

    const sleepDelays = [];
    let attempt = 0;

    // Sequence: fail 1, fail 2, fail 3, fail 4 (hit cap), succeed (reset), fail 5 (back to poll), abort
    const worker = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath,
        lockPath,
        everyRecords: 1,
        pollSeconds: 10,
        maxBackoffSeconds: 30,
        nodeClient: node,
        signer,
        random: () => 1, // deterministic top of jitter range (0.5 + 0.5*1 = 1.0)
        source: () => {
            attempt += 1;
            if (attempt <= 4 || attempt === 6) {
                throw new Error(`transient source failure #${attempt}`);
            }
            return [];
        },
        sleep: async (ms) => {
            sleepDelays.push(ms);
            if (sleepDelays.length >= 6) ac.abort();
        },
        log: () => {},
        signal: ac.signal,
    });

    await worker.run();
    // attempt 1 fail -> 10s; 2 fail -> 20s; 3 fail -> min(30, 40)=30s; 4 fail -> 30s; 5 ok -> 10s; 6 fail -> 10s
    assert.deepEqual(sleepDelays, [10_000, 20_000, 30_000, 30_000, 10_000, 10_000]);
    assert.equal(fs.existsSync(lockPath), false, 'lockfile must be released when aborted');
});

test('cli watch command validates flags and executes --once --dry-run cleanly', async () => {
    const dir = makeTempDir();
    const trailPath = path.join(dir, 'cli-watch.jsonl');
    const node = createMutableMockNode();

    await assert.rejects(
        () => commands.watch({ uuid: AGENT_UUID, token: TOKEN_ID, trail: trailPath }),
        /everyRecords or everySeconds/,
    );
    await assert.rejects(
        () => commands.watch({ uuid: AGENT_UUID, token: TOKEN_ID, trail: trailPath, 'every-records': '0' }),
        /positive safe integer/,
    );
    await assert.rejects(
        () => commands.watch({ uuid: AGENT_UUID, token: TOKEN_ID, trail: trailPath, 'every-records': '10abc' }),
        /positive integer/,
    );
    await assert.rejects(
        () => commands.watch({ uuid: AGENT_UUID, token: TOKEN_ID, trail: trailPath, 'every-seconds': '-5' }),
        /positive finite number/,
    );

    const logs = [];
    const res = await commands.watch({
        uuid: AGENT_UUID,
        token: TOKEN_ID,
        trail: trailPath,
        'every-records': '2',
        once: true,
        'dry-run': true,
        nodeClient: node,
        source: (afterSeq) => (afterSeq === 0 ? [makeRecord(1), makeRecord(2)] : []),
        log: (m) => logs.push(m),
    });

    assert.equal(res.dryRun, true);
    assert.equal(res.localSeq, 2);
    assert.equal(node.submitted.length, 0);
    assert.ok(logs.some((l) => l.includes('[dry-run] anchor plan')));
    assert.equal(readTrail(trailPath).records.length, 2);
});

test('AnchorWorker clears orphaned/existing pendingAnchor, refuses drifted pendingAnchor, supports --dry-run recovery plan, and cancels real sleep on AbortSignal', async () => {
    const dir = makeTempDir();
    const header = {
        schema: 'countersign.trail.v1',
        source: 'test',
        agent_uuid: AGENT_UUID,
        token_id: TOKEN_ID,
        registry: { network: 'testnet', ...REGISTRY },
    };

    // 1a. Superseded orphaned pendingAnchor (someone else anchored seq 1..3) -> logs orphan, clears pendingAnchor, 0 setMetadata
    {
        const trailPath = path.join(dir, 'superseded.jsonl');
        const statePath = `${trailPath}.anchor-state.json`;
        const recs = [makeRecord(1), makeRecord(2), makeRecord(3)];
        writeTrail(trailPath, header, recs);
        const { at } = commitments(header, recs, new Set([2, 3]));
        const node = createMutableMockNode();
        const stalePendingRd = node.addRegisterData({
            sender: OWNER_A,
            data: encodeAnchor({ tokenId: TOKEN_ID, toSeq: 2, commitment: at.get(2), prevAnchorTx: null }),
        });
        const winnerRd = node.addRegisterData({
            sender: OWNER_A,
            data: encodeAnchor({ tokenId: TOKEN_ID, toSeq: 3, commitment: at.get(3), prevAnchorTx: null }),
        });
        node.addSetMetadata({ sender: OWNER_A, value: winnerRd.txHash });

        fs.writeFileSync(
            statePath,
            JSON.stringify({
                version: 1,
                agentUuid: AGENT_UUID,
                tokenId: TOKEN_ID,
                pendingAnchor: {
                    txHash: stalePendingRd.txHash,
                    tokenId: TOKEN_ID,
                    toSeq: 2,
                    commitment: at.get(2).toString('hex'),
                    prevAnchorTx: null,
                    sender: OWNER_A,
                },
            }),
        );

        let setMetaCalled = false;
        const logs = [];
        const worker = new AnchorWorker({
            uuid: AGENT_UUID,
            tokenId: TOKEN_ID,
            trailPath,
            statePath,
            everyRecords: 1,
            nodeClient: node,
            signer: makeSigner(OWNER_A),
            source: () => [],
            setMetadata: () => {
                setMetaCalled = true;
            },
            log: (m) => logs.push(m),
        });
        const res = await worker.tick();
        assert.equal(setMetaCalled, false);
        assert.equal(res.anchoredSeq, 3);
        assert.ok(logs.some((m) => /orphaned pending anchor/.test(m)));
        const cleared = JSON.parse(fs.readFileSync(statePath, 'utf8'));
        assert.equal(cleared.pendingAnchor, null);
        assert.equal(cleared.lastAnchoredSeq, 3);
        assert.equal(cleared.lastAnchoredTxHash, winnerRd.txHash);
    }

    // 1b. pendingAnchor already present in existing anchors (followed by a newer anchor) -> clears pendingAnchor cleanly
    {
        const trailPath = path.join(dir, 'in-existing.jsonl');
        const statePath = `${trailPath}.anchor-state.json`;
        const recs = [makeRecord(1), makeRecord(2), makeRecord(3)];
        writeTrail(trailPath, header, recs);
        const { at } = commitments(header, recs, new Set([2, 3]));
        const node = createMutableMockNode();
        const rd1 = node.addRegisterData({
            sender: OWNER_A,
            data: encodeAnchor({ tokenId: TOKEN_ID, toSeq: 2, commitment: at.get(2), prevAnchorTx: null }),
        });
        node.addSetMetadata({ sender: OWNER_A, value: rd1.txHash });
        const rd2 = node.addRegisterData({
            sender: OWNER_A,
            data: encodeAnchor({ tokenId: TOKEN_ID, toSeq: 3, commitment: at.get(3), prevAnchorTx: rd1.txHash }),
        });
        node.addSetMetadata({ sender: OWNER_A, value: rd2.txHash });

        fs.writeFileSync(
            statePath,
            JSON.stringify({
                version: 1,
                agentUuid: AGENT_UUID,
                tokenId: TOKEN_ID,
                pendingAnchor: {
                    txHash: rd1.txHash,
                    tokenId: TOKEN_ID,
                    toSeq: 2,
                    commitment: at.get(2).toString('hex'),
                    prevAnchorTx: null,
                    sender: OWNER_A,
                },
            }),
        );

        const worker = new AnchorWorker({
            uuid: AGENT_UUID,
            tokenId: TOKEN_ID,
            trailPath,
            statePath,
            everyRecords: 1,
            nodeClient: node,
            signer: makeSigner(OWNER_A),
            source: () => [],
            log: () => {},
        });
        const res = await worker.tick();
        assert.equal(res.anchoredSeq, 3);
        const st = JSON.parse(fs.readFileSync(statePath, 'utf8'));
        assert.equal(st.pendingAnchor, null);
        assert.equal(st.lastAnchoredTxHash, rd2.txHash);
    }

    // 1c. pendingAnchor whose commitment disagrees with local trail still refuses to resume
    {
        const trailPath = path.join(dir, 'drifted-pending.jsonl');
        const statePath = `${trailPath}.anchor-state.json`;
        const recs = [makeRecord(1), makeRecord(2)];
        writeTrail(trailPath, header, recs);
        const node = createMutableMockNode();
        const bogusCommitment = Buffer.alloc(32, 0xaa);
        const rd = node.addRegisterData({
            sender: OWNER_A,
            data: encodeAnchor({ tokenId: TOKEN_ID, toSeq: 2, commitment: bogusCommitment, prevAnchorTx: null }),
        });
        fs.writeFileSync(
            statePath,
            JSON.stringify({
                version: 1,
                agentUuid: AGENT_UUID,
                tokenId: TOKEN_ID,
                pendingAnchor: {
                    txHash: rd.txHash,
                    tokenId: TOKEN_ID,
                    toSeq: 2,
                    commitment: bogusCommitment.toString('hex'),
                    prevAnchorTx: null,
                    sender: OWNER_A,
                },
            }),
        );
        const worker = new AnchorWorker({
            uuid: AGENT_UUID,
            tokenId: TOKEN_ID,
            trailPath,
            statePath,
            everyRecords: 1,
            nodeClient: node,
            signer: makeSigner(OWNER_A),
            source: () => [],
            log: () => {},
        });
        await assert.rejects(() => worker.tick(), /refusing to resume/);
    }

    // 2. --dry-run with valid pendingAnchor logs resume_set_metadata without writing chain or state
    {
        const trailPath = path.join(dir, 'dry-resume.jsonl');
        const statePath = `${trailPath}.anchor-state.json`;
        const recs = [makeRecord(1), makeRecord(2)];
        writeTrail(trailPath, header, recs);
        const { last } = commitments(header, recs);
        const node = createMutableMockNode();
        const pendingRd = node.addRegisterData({
            sender: OWNER_A,
            data: encodeAnchor({ tokenId: TOKEN_ID, toSeq: 2, commitment: last, prevAnchorTx: null }),
        });
        const stateBody = JSON.stringify({
            version: 1,
            agentUuid: AGENT_UUID,
            tokenId: TOKEN_ID,
            pendingAnchor: {
                txHash: pendingRd.txHash,
                tokenId: TOKEN_ID,
                toSeq: 2,
                commitment: last.toString('hex'),
                prevAnchorTx: null,
                sender: OWNER_A,
            },
        });
        fs.writeFileSync(statePath, stateBody);

        const logs = [];
        const res = await runAnchorWorker({
            uuid: AGENT_UUID,
            tokenId: TOKEN_ID,
            trailPath,
            statePath,
            once: true,
            dryRun: true,
            nodeClient: node,
            loadSignerFn: () => {
                throw new Error('must not load signer');
            },
            source: () => [],
            log: (m) => logs.push(m),
        });
        assert.equal(res.dryRun, true);
        assert.equal(res.plan.action, 'resume_set_metadata');
        assert.equal(fs.readFileSync(statePath, 'utf8'), stateBody);
    }

    // 3. Real setTimeout sleep in loop mode exits promptly on AbortSignal and releases lock
    {
        const trailPath = path.join(dir, 'real-abort.jsonl');
        const lockPath = `${trailPath}.anchor-state.json.lock`;
        const node = createMutableMockNode();
        const ac = new AbortController();
        const worker = new AnchorWorker({
            uuid: AGENT_UUID,
            tokenId: TOKEN_ID,
            trailPath,
            lockPath,
            everyRecords: 1,
            pollSeconds: 60, // long sleep that must be cancelled immediately by AbortSignal
            nodeClient: node,
            signer: makeSigner(OWNER_A),
            source: () => {
                ac.abort();
                return [];
            },
            log: () => {},
            signal: ac.signal,
        });
        await worker.run();
        assert.equal(fs.existsSync(lockPath), false);
    }

    // 4. CLI entrypoint parses watch flags properly via process.execPath (works with PATH=/nonexistent)
    assert.throws(
        () =>
            execFileSync(process.execPath, [
                'src/cli.mjs',
                'watch',
                '--uuid',
                AGENT_UUID,
                '--token',
                TOKEN_ID,
                '--trail',
                path.join(dir, 'unused.jsonl'),
            ], { encoding: 'utf8', stdio: 'pipe' }),
        (err) => err.status === 1 && /everyRecords or everySeconds/.test(err.stderr),
    );
});

test('pre-broadcast pendingAnchor & metadataTx handle absent before/after expiry and pending/committed polling without duplicates', async () => {
    const dir = makeTempDir();
    const signer = makeSigner(OWNER_A);
    const origLog = console.log;
    console.log = () => {};

    try {
        // 1. Pre-broadcast crash BEFORE sendTransaction broadcasts registerData (tx absent on node)
        {
            const trailPath = path.join(dir, 'prebroadcast-rd.jsonl');
            const statePath = `${trailPath}.anchor-state.json`;
            let nowSec = 1_700_000_000;
            const node = createMutableMockNode({
                onSendTransaction: () => {
                    throw new Error('simulated crash right before sendTransaction');
                },
            });

            const w1 = new AnchorWorker({
                uuid: AGENT_UUID,
                tokenId: TOKEN_ID,
                trailPath,
                statePath,
                everyRecords: 1,
                nodeClient: node,
                signer,
                source: (afterSeq) => (afterSeq === 0 ? [makeRecord(1)] : []),
                wallClock: () => new Date(nowSec * 1000),
                log: () => {},
            });

            await assert.rejects(() => w1.tick(), /simulated crash right before sendTransaction/);
            const saved = JSON.parse(fs.readFileSync(statePath, 'utf8'));
            assert.ok(saved.pendingAnchor);
            assert.equal(saved.pendingAnchor.status, 'signed');
            assert.ok(saved.pendingAnchor.expiryEpochSeconds > 0);
            const firstSignedHash = saved.pendingAnchor.txHash;

            // Restart BEFORE expiry while tx is absent -> throws retryable ambiguous error, 0 new broadcasts
            let sendCalls = 0;
            const node2 = createMutableMockNode({
                onSendTransaction: () => {
                    sendCalls += 1;
                },
            });
            nowSec = saved.pendingAnchor.expiryEpochSeconds - 10;
            const w2 = new AnchorWorker({
                uuid: AGENT_UUID,
                tokenId: TOKEN_ID,
                trailPath,
                statePath,
                everyRecords: 1,
                nodeClient: node2,
                signer,
                source: () => [],
                wallClock: () => new Date(nowSec * 1000),
                log: () => {},
            });
            await assert.rejects(() => w2.tick(), /ambiguous before expiry/);
            assert.equal(sendCalls, 0);

            // Restart AFTER expiry while tx is still absent -> clears expired pendingAnchor and submits cleanly
            node2.state.nonceChanges.push({ sender: OWNER_A, height: 1100n });
            nowSec = saved.pendingAnchor.expiryEpochSeconds + 5;
            const res = await w2.tick();
            assert.equal(res.anchored, true);
            assert.equal(res.anchoredSeq, 1);
            assert.equal(sendCalls, 2); // 1 registerData + 1 setMetadata
            assert.notEqual(res.txHash, firstSignedHash);
            assert.equal(JSON.parse(fs.readFileSync(statePath, 'utf8')).pendingAnchor, null);
        }

        // 2. registerData in 'received'/'committed' state polls to finalization without duplicate registerData
        {
            const trailPath = path.join(dir, 'inflight-rd.jsonl');
            const statePath = `${trailPath}.anchor-state.json`;
            const recs = [makeRecord(1), makeRecord(2)];
            const header = {
                schema: 'countersign.trail.v1',
                source: 'test',
                agent_uuid: AGENT_UUID,
                token_id: TOKEN_ID,
                registry: { network: 'testnet', ...REGISTRY },
            };
            writeTrail(trailPath, header, recs);
            const { last } = commitments(header, recs);
            const pendingHash = txHashFor('inflight-rd-tx');
            const data = encodeAnchor({ tokenId: TOKEN_ID, toSeq: 2, commitment: last, prevAnchorTx: null });

            let polls = 0;
            const node = createMutableMockNode({
                statusForHash: (h) => {
                    if (h !== pendingHash) return undefined;
                    polls += 1;
                    if (polls === 1) return { status: 'received' };
                    if (polls === 2) return { status: 'committed' };
                    return {
                        status: 'finalized',
                        outcome: {
                            blockHash: { height: 2001n, toString: () => 'block-2001' },
                            summary: {
                                transactionType: 'registerData',
                                sender: { address: OWNER_A },
                                dataRegistered: { data: data.toString('hex') },
                            },
                        },
                    };
                },
            });
            // Also register for readRegisterData once finalized
            node.state.registerDataByHash.set(pendingHash, {
                height: 2001n,
                hash: pendingHash,
                sender: OWNER_A,
                registerData: data,
            });

            fs.writeFileSync(
                statePath,
                JSON.stringify({
                    version: 1,
                    agentUuid: AGENT_UUID,
                    tokenId: TOKEN_ID,
                    pendingAnchor: {
                        txHash: pendingHash,
                        status: 'signed',
                        expiryEpochSeconds: 9_999_999_999,
                        tokenId: TOKEN_ID,
                        toSeq: 2,
                        commitment: last.toString('hex'),
                        prevAnchorTx: null,
                        sender: OWNER_A,
                    },
                }),
            );

            // Override getBlockItemStatus only for first 2 polls, then let registerDataByHash return finalized
            const origGetStatus = node.getBlockItemStatus.bind(node);
            let rdPolls = 0;
            node.getBlockItemStatus = async (txHash) => {
                if (txHash.toString() === pendingHash) {
                    rdPolls += 1;
                    if (rdPolls === 1) return { status: 'received' };
                    if (rdPolls === 2) return { status: 'committed' };
                }
                return origGetStatus(txHash);
            };

            const w = new AnchorWorker({
                uuid: AGENT_UUID,
                tokenId: TOKEN_ID,
                trailPath,
                statePath,
                everyRecords: 1,
                nodeClient: node,
                signer,
                source: () => [],
                log: () => {},
            });
            const res = await w.tick();
            assert.equal(res.anchoredSeq, 2);
            // Only setMetadata was broadcast (no duplicate registerData!)
            assert.equal(node.submitted.length, 1);
            assert.equal(node.submitted[0].payload.receiveName.value, 'CIS-8004.setMetadata');
        }

        // 3. Pre-broadcast crash BEFORE setMetadata sendTransaction -> ambiguous before expiry, re-submits after expiry, polls committed when landed
        {
            const trailPath = path.join(dir, 'prebroadcast-meta.jsonl');
            const statePath = `${trailPath}.anchor-state.json`;
            let nowSec = 1_700_000_000;
            let failOnSetMeta = true;

            const node = createMutableMockNode({
                onSendTransaction: (entry) => {
                    if (entry.payload?.type !== 21 && failOnSetMeta) {
                        throw new Error('simulated crash before setMetadata broadcast');
                    }
                },
            });

            const w1 = new AnchorWorker({
                uuid: AGENT_UUID,
                tokenId: TOKEN_ID,
                trailPath,
                statePath,
                everyRecords: 1,
                nodeClient: node,
                signer,
                source: (afterSeq) => (afterSeq === 0 ? [makeRecord(1)] : []),
                wallClock: () => new Date(nowSec * 1000),
                log: () => {},
            });

            await assert.rejects(() => w1.tick(), /simulated crash before setMetadata broadcast/);
            const saved = JSON.parse(fs.readFileSync(statePath, 'utf8'));
            assert.ok(saved.pendingAnchor?.metadataTx?.txHash);
            const metaExpiry = saved.pendingAnchor.metadataTx.expiryEpochSeconds;

            // Before expiry with absent metadataTx -> throws ambiguous error, 0 broadcasts
            nowSec = metaExpiry - 5;
            await assert.rejects(() => w1.tick(), /in-flight\/ambiguous until expiry/);

            // If metadataTx actually enters 'committed' and finalizes on node -> polls it with 0 duplicate setMetadata!
            const metaHash = saved.pendingAnchor.metadataTx.txHash;
            const rdHash = saved.pendingAnchor.txHash;
            let metaPolls = 0;
            const origGetStatus = node.getBlockItemStatus.bind(node);
            node.getBlockItemStatus = async (txHash) => {
                if (txHash.toString() === metaHash) {
                    metaPolls += 1;
                    if (metaPolls === 1) return { status: 'committed' };
                    node.state.metadata['countersign.anchor'] = rdHash;
                    return {
                        status: 'finalized',
                        outcome: {
                            blockHash: { height: 2002n, toString: () => 'block-2002' },
                            summary: { transactionType: 'update', sender: { address: OWNER_A }, events: [] },
                        },
                    };
                }
                return origGetStatus(txHash);
            };
            const submittedBefore = node.submitted.length;
            const res = await w1.tick();
            assert.equal(node.submitted.length, submittedBefore, 'must NOT send duplicate setMetadata');
            assert.equal(res.anchoredSeq, 1);
            assert.equal(JSON.parse(fs.readFileSync(statePath, 'utf8')).pendingAnchor, null);
        }
    } finally {
        console.log = origLog;
    }
});

test('canonical trail lock blocks differing --state workers, serializes stale-lock takeover race, and rejects concurrent in-process calls', async () => {
    const dir = makeTempDir();
    const trailPath = path.join(dir, 'shared.jsonl');
    const symlinkTrail = path.join(dir, 'shared-link.jsonl');
    fs.writeFileSync(trailPath, '');
    fs.symlinkSync(trailPath, symlinkTrail);

    const w1 = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath,
        statePath: path.join(dir, 'state-1.json'),
        once: true,
        log: () => {},
    });
    const w2 = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath: symlinkTrail,
        statePath: path.join(dir, 'state-2.json'),
        once: true,
        log: () => {},
    });
    assert.equal(w1.lockPath, w2.lockPath, 'lockPath must derive canonically from trailPath, never statePath');

    // Mutual stale-lock takeover race: two concurrent contenders on one stale lock -> exactly 1 wins!
    const lockPath = trailLockPath(trailPath);
    const deadPid = findDeadPid();
    fs.writeFileSync(lockPath, JSON.stringify({ pid: deadPid, host: os.hostname(), startedAt: new Date().toISOString() }) + '\n');

    let holdGate;
    const gatePromise = new Promise((r) => {
        holdGate = r;
    });
    let enteredGate;
    const enteredPromise = new Promise((r) => {
        enteredGate = r;
    });

    const contender1 = withFileLock(lockPath, async () => {
        enteredGate();
        await gatePromise;
        return 'won-1';
    });
    const contender2 = withFileLock(lockPath, async () => 'won-2');

    const results = await Promise.allSettled([
        (async () => {
            await enteredPromise;
            holdGate();
            return contender1;
        })(),
        contender2,
    ]);
    const fulfilled = results.filter((r) => r.status === 'fulfilled');
    const rejected = results.filter((r) => r.status === 'rejected');
    assert.equal(fulfilled.length, 1);
    assert.equal(rejected.length, 1);
    assert.equal(fs.existsSync(lockPath), false);

    // Concurrent tick() on same AnchorWorker instance rejects cleanly
    const node = createMutableMockNode();
    let releaseSource;
    const sourceGate = new Promise((r) => {
        releaseSource = r;
    });
    let insideSource;
    const insidePromise = new Promise((r) => {
        insideSource = r;
    });
    const wSlow = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath: path.join(dir, 'concurrent-instance.jsonl'),
        once: true,
        dryRun: true,
        nodeClient: node,
        source: async () => {
            insideSource();
            await sourceGate;
            return [];
        },
        log: () => {},
    });
    const p1 = wSlow.tick();
    await insidePromise;
    await assert.rejects(() => wSlow.tick(), /already active on this instance/);
    releaseSource();
    await p1;
});

test('AnchorWorker recovers torn trail append via trailAppend journal and fails closed on unjournaled corruption', async () => {
    const dir = makeTempDir();
    const trailPath = path.join(dir, 'torn.jsonl');
    const statePath = `${trailPath}.anchor-state.json`;
    const header = {
        schema: 'countersign.trail.v1',
        source: 'test',
        agent_uuid: AGENT_UUID,
        token_id: TOKEN_ID,
        registry: { network: 'testnet', ...REGISTRY },
    };
    writeTrail(trailPath, header, [makeRecord(1)]);
    const baseSize = fs.statSync(trailPath).size;

    // Simulate SIGKILL mid-append: journaled trailAppend + torn partial line on disk
    fs.writeFileSync(
        statePath,
        JSON.stringify({
            version: 1,
            agentUuid: AGENT_UUID,
            tokenId: TOKEN_ID,
            trailAppend: { baseSize, targetSeq: 2 },
        }),
    );
    fs.appendFileSync(trailPath, '{"checkpoint_id":"cp-2","partial');

    const stream = [makeRecord(1), makeRecord(2)];
    const logs = [];
    const worker = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath,
        statePath,
        once: true,
        source: (afterSeq) => stream.filter((r) => r.seq > afterSeq),
        log: (m) => logs.push(m),
    });

    const synced = await worker.syncTrail();
    assert.equal(synced.lastSeq, 2);
    assert.equal(readTrail(trailPath).records.length, 2);
    assert.equal(JSON.parse(fs.readFileSync(statePath, 'utf8')).trailAppend, null);
    assert.ok(logs.some((l) => /recovering interrupted trail append/.test(l)));

    // Unjournaled corruption (no trailAppend) MUST fail closed
    fs.appendFileSync(trailPath, '{"corrupt');
    await assert.rejects(() => worker.syncTrail(), /newline|not JSON/);
});

test('DATABASE_URL extracts PG* env vars without exposing password in argv and rejects non-postgres URLs', () => {
    const pgEnv = parseDatabaseUrlToPgEnv('postgresql://alice:s3cr3t%21@pg.internal:5433/unitares?sslmode=require');
    assert.deepEqual(pgEnv, {
        PGHOST: 'pg.internal',
        PGPORT: '5433',
        PGUSER: 'alice',
        PGPASSWORD: 's3cr3t!',
        PGDATABASE: 'unitares',
        PGSSLMODE: 'require',
    });

    assert.equal(parseDatabaseUrlToPgEnv('postgres://[::1]:5432/gov').PGHOST, '::1');
    assert.equal(parseDatabaseUrlToPgEnv('postgresql:///gov?host=/var/run/postgresql').PGHOST, '/var/run/postgresql');
    assert.throws(() => parsePsqlCommand(undefined, { DATABASE_URL: 'http://evil.example/db' }), /unsupported DATABASE_URL scheme/);

    let call = null;
    const rows = fetchCheckpointsAfter({
        uuid: AGENT_UUID,
        afterSeq: 0,
        env: { DATABASE_URL: 'postgresql://alice:topsecret@db.host:5432/gov?sslmode=verify-full' },
        execFile: (bin, args, opts) => {
            call = { bin, args, opts };
            return '';
        },
    });
    assert.deepEqual(rows, []);
    assert.equal(call.bin, 'psql');
    assert.equal(call.args.join(' ').includes('topsecret'), false, 'password must never appear in argv');
    assert.equal(call.opts.env.PGPASSWORD, 'topsecret');
    assert.equal(call.opts.env.PGHOST, 'db.host');
    assert.equal(call.opts.env.PGDATABASE, 'gov');
    assert.equal(call.opts.env.PGSSLMODE, 'verify-full');
    assert.match(call.opts.env.PGOPTIONS, /default_transaction_read_only=on/);
});

test('AnchorWorker seeds --every-seconds from prev.blockTime across restarts, requires unitares.agent_uuid, and skips history scans on idle polls', async () => {
    const dir = makeTempDir();
    const trailPath = path.join(dir, 'restart-seed.jsonl');
    const header = {
        schema: 'countersign.trail.v1',
        source: 'test',
        agent_uuid: AGENT_UUID,
        token_id: TOKEN_ID,
        registry: { network: 'testnet', ...REGISTRY },
    };
    const recs = [makeRecord(1), makeRecord(2), makeRecord(3)];
    writeTrail(trailPath, header, recs);
    const { at } = commitments(header, recs, new Set([2]));

    let historyRpcCount = 0;
    const node = createMutableMockNode({
        onRpc: (m) => {
            if (m === 'getBlockTransactionEvents' || m === 'getAccountInfo' || m === 'getInstanceInfo') {
                historyRpcCount += 1;
            }
        },
    });
    const rd = node.addRegisterData({
        sender: OWNER_A,
        height: 1500n, // blockTime = 1700000000000 + 1500*2000 = 1700003000000
        data: encodeAnchor({ tokenId: TOKEN_ID, toSeq: 2, commitment: at.get(2), prevAnchorTx: null }),
    });
    node.addSetMetadata({ sender: OWNER_A, height: 1501n, value: rd.txHash });

    const prevBlockMs = 1_700_003_000_000;
    let wallNowMs = prevBlockMs + 10_000; // only 10s elapsed since prev.blockTime
    let monoMs = 5_000;

    const worker = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath,
        everySeconds: 3600,
        nodeClient: node,
        signer: makeSigner(OWNER_A),
        source: () => [],
        now: () => monoMs,
        wallClock: () => new Date(wallNowMs),
        log: () => {},
    });

    // Tick 1: runs initial full history reconciliation, seeds lastAnchorMs from prev.blockTime -> 10s < 3600s -> no anchor
    const t1 = await worker.tick();
    assert.equal(t1.anchored, false);
    assert.equal(t1.anchoredSeq, 2);
    assert.ok(historyRpcCount > 0);

    // Ticks 2 & 3 (idle polls): pointer unchanged & !due -> ZERO history RPCs!
    const countAfterT1 = historyRpcCount;
    monoMs += 15_000;
    wallNowMs += 15_000;
    await worker.tick();
    monoMs += 15_000;
    wallNowMs += 15_000;
    await worker.tick();
    assert.equal(historyRpcCount, countAfterT1, 'idle polls must skip readRegistryHistory');

    // Missing unitares.agent_uuid metadata fails closed
    const missingUuidNode = createMutableMockNode({ includeUuidMetadata: false });
    const wMissing = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath: path.join(dir, 'missing-uuid.jsonl'),
        once: true,
        nodeClient: missingUuidNode,
        signer: makeSigner(OWNER_A),
        source: () => [],
        log: () => {},
    });
    await assert.rejects(() => wMissing.tick(), /on-chain unitares\.agent_uuid/);
});
