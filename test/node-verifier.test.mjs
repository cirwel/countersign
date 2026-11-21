import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, test } from 'node:test';
import { AccountAddress, ReturnValue, TransactionHash } from '@concordium/web-sdk';
import {
    TESTNET_GENESIS,
    assertTestnet,
    configureNode,
    createGrpcClient,
    createRpcPool,
    formatGrpcHost,
    isSameAccount,
    isTransientRpcError,
    readRegisterData,
    readRegistryHistory,
    sendSetMetadata,
    withRpcRetry,
} from '../src/chain.mjs';
import { encodeBadge, encodeTokenId } from '../src/cis8004.mjs';
import { commands } from '../src/cli.mjs';
import { REGISTRY, REGISTRY_MODULE_REF } from '../src/registry.mjs';
import { commitments, decodeAnchor, encodeAnchor, writeTrail } from '../src/trail.mjs';

const GENESIS_PREFIX = TESTNET_GENESIS.slice(0, 32);
const OWNER_A = '4NAnnhZUSYiyJLM9k6H7dVPn1uuPGStu2LZEety7zmp1LBYw41';
const OWNER_A_ALIAS = AccountAddress.getAlias(AccountAddress.fromBase58(OWNER_A), 1).address;
const OWNER_B = '3dt3UMPzRASZndjmKpSWgCP2HhmoxZrgs8FDPtZjNHZzj13hhB';
// Real <12802,0> testnet operator accounts captured directly from live contract state:
const LIVE_OWNER_WITH_OP = '3qYSik7b8w9NsgeAk91Mrpapq9T5S7EGvmsa3Ecf4449xiJ8cX';
const LIVE_OWNER_WITH_OP_STATE_KEY = '0500000000000000759cef9edac9d4c5f2852631ba6e6e3d97ab99d18c6f429b9fd0021216864425';
const LIVE_OWNER_WITH_OP_SUBMAP_HEX = '0700000000000000';
const LIVE_OWNER_WITH_OP_SUBMAP_ENTRY = '070000000000000000376c1ae7a9f159e28efc2933df252557526b5b4cf89cf2637c83e96472713291';
// Real <12802,0> testnet account whose operator was added & later removed (0600000000000000 has 0 entries):
const LIVE_EMPTY_OP_SUBMAP_KEY = '0500000000000000eaaab5e295100b4431e8cda1ffea74e4a6545c9ea2cd4135e56118041f0ee520';
const LIVE_EMPTY_OP_SUBMAP_HEX = '0600000000000000';

const AGENT_UUID = '00000000-0000-4000-8000-000000000001';
const TOKEN_ID = '7';
const BADGE = encodeBadge(TOKEN_ID);
const OTHER_MOD_REF = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

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
const acctHex = (b58) => acctBytes(b58).toString('hex');

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

function encodeGetAdminReturn(admin) {
    if (admin === null || admin === undefined) return Buffer.from([0]);
    return Buffer.concat([Buffer.from([1]), acctBytes(admin)]);
}

const evMint = (tokenId, owner) =>
    Buffer.concat([Buffer.from([0xfe]), encodeTokenId(tokenId), Buffer.from([1, 0]), acctBytes(owner)]);

const evTransfer = (tokenId, from, to) =>
    Buffer.concat([Buffer.from([0xff]), encodeTokenId(tokenId), Buffer.from([1, 0]), acctBytes(from), Buffer.from([0]), acctBytes(to)]);

const evBurn = (tokenId, owner) =>
    Buffer.concat([Buffer.from([0xfd]), encodeTokenId(tokenId), Buffer.from([1, 0]), acctBytes(owner)]);

const evUpdateOperator = (update, owner, operator) =>
    Buffer.concat([Buffer.from([0xfc, update === 'Add' ? 1 : 0, 0]), acctBytes(owner), Buffer.from([0]), acctBytes(operator)]);

const evAdminTransferred = (previous, next, tsMs = 1700000000000) =>
    Buffer.concat([
        Buffer.from([0xf7]),
        previous ? Buffer.concat([Buffer.from([1]), acctBytes(previous)]) : Buffer.from([0]),
        next ? Buffer.concat([Buffer.from([1]), acctBytes(next)]) : Buffer.from([0]),
        u64le(tsMs),
    ]);

const evMetadataSet = (tokenId, key, valueUtf8, tsMs = 1700000000000) => {
    const k = Buffer.from(key, 'utf8');
    const v = Buffer.from(valueUtf8, 'utf8');
    return Buffer.concat([Buffer.from([0xf3]), encodeTokenId(tokenId), u32le(k.length), k, u32le(v.length), v, u64le(tsMs)]);
};

function makeCardBytes({ badge = BADGE, ownerAccount = OWNER_A } = {}) {
    const card = {
        name: 'TestAgent',
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

function makeTrailFixtures(count = 4) {
    const header = {
        schema: 'countersign.trail.v1',
        source: 'test',
        agent_uuid: AGENT_UUID,
        token_id: TOKEN_ID,
        registry: { network: 'testnet', ...REGISTRY },
    };
    const recs = [];
    for (let i = 1; i <= count; i++) {
        recs.push({
            seq: i,
            checkpoint_id: `cp-${i}`,
            prev_checkpoint_id: i === 1 ? null : `cp-${i - 1}`,
            recorded_at: `2026-11-01T00:00:${String(i).padStart(2, '0')}.000000Z`,
            report_excerpt: `report ${i}`,
            provenance: { producer: 'test' },
        });
    }
    return { header, records: recs };
}

function txHashFor(label) {
    return crypto.createHash('sha256').update(label).digest('hex');
}

function blockHashFor(h) {
    return {
        height: BigInt(h),
        toString() {
            return `block-${h}`;
        },
    };
}

function createMockNode({
    genesisBlock = TESTNET_GENESIS,
    tipHeight = 60000n,
    baseTimeMs = 1700000000000,
    agent,
    metadata = {},
    txs = [], // { height, hash, sender, registerData?: Buffer, contractEvents?: Buffer[], traceTag?: string }
    moduleRefAt = () => REGISTRY_MODULE_REF,
    adminAt = () => null,
    stateLookupMap = new Map(), // full state keyHex -> valueHex
    stateEntries = [], // { key, value }
    beforeRpc = null,
    onInvokeContract = null,
    onSendTransaction = null,
    pollSequenceForSubmitted = null, // optional function (hash, pollIndex) => status
    stallBlockEventsAt = null, // optional height to stall on signal
    stallAbortError = null,
} = {}) {
    const txsByHeight = new Map();
    const registerDataByHash = new Map();
    const submittedByHash = new Map();
    const pollCounts = new Map();
    const nonceChanges = [];

    for (const tx of txs) {
        const h = BigInt(tx.height);
        if (!txsByHeight.has(h)) txsByHeight.set(h, []);
        txsByHeight.get(h).push(tx);
        if (tx.sender) nonceChanges.push({ sender: tx.sender, height: h });
        if (tx.registerData) registerDataByHash.set(tx.hash, tx);
    }

    const timeForHeight = (h) => {
        const hn = Number(h);
        return baseTimeMs + hn * 2000 + Math.floor(Math.sin(hn / 1000) * 50) + (hn % 3) * 10;
    };

    const heightFromBlockHash = (bh) => {
        if (typeof bh?.height === 'bigint') return bh.height;
        const m = /^block-(\d+)$/.exec(String(bh));
        if (!m) throw new Error(`unknown mock blockHash ${bh}`);
        return BigInt(m[1]);
    };

    const callRpc = async (method, fn, arg) => {
        if (beforeRpc) await beforeRpc(method, arg);
        return fn();
    };

    let submitSeq = 0;

    const nodeObj = {
        timeForHeight,
        submitted: [],
        metadata,
        stallBlockEventsAt,
        async getConsensusStatus() {
            return callRpc('getConsensusStatus', () => ({
                genesisBlock: { toString: () => genesisBlock },
                lastFinalizedBlock: blockHashFor(tipHeight),
                lastFinalizedBlockHeight: BigInt(tipHeight),
            }));
        },
        async getBlocksAtHeight(h) {
            return callRpc('getBlocksAtHeight', () => [blockHashFor(BigInt(h))], h);
        },
        async getBlockInfo(bh) {
            return callRpc('getBlockInfo', () => {
                const h = heightFromBlockHash(bh);
                return { blockHeight: h, blockSlotTime: new Date(timeForHeight(h)) };
            }, bh);
        },
        async getAccountInfo(acct, bh) {
            return callRpc('getAccountInfo', () => {
                const h = heightFromBlockHash(bh);
                let count = 1n;
                for (const nc of nonceChanges) {
                    if (nc.height <= h && isSameAccount(nc.sender, acct.address)) count += 1n;
                }
                return { accountNonce: { value: count } };
            }, bh);
        },
        async getNextAccountNonce(acct) {
            return callRpc('getNextAccountNonce', () => {
                let count = 1n;
                for (const nc of nonceChanges) {
                    if (isSameAccount(nc.sender, acct.address)) count += 1n;
                }
                return { nonce: { value: count }, allFinal: true };
            }, acct.address);
        },
        async getInstanceInfo(_addr, bh) {
            return callRpc('getInstanceInfo', () => {
                const h = heightFromBlockHash(bh);
                return { sourceModule: { moduleRef: moduleRefAt(h) } };
            }, bh);
        },
        async instanceStateLookup(_addr, keyHex, _bh) {
            return callRpc('instanceStateLookup', () => {
                if (stateLookupMap.has(keyHex)) return stateLookupMap.get(keyHex);
                const err = new Error('Key not found.');
                err.code = 'NOT_FOUND';
                throw err;
            }, keyHex);
        },
        async *getInstanceState(_addr, _bh, _signal) {
            await callRpc('getInstanceState', () => {});
            for (const entry of stateEntries) yield entry;
        },
        async *getBlockTransactionEvents(bh, signal) {
            await callRpc('getBlockTransactionEvents', () => {}, bh);
            const h = heightFromBlockHash(bh);
            if (nodeObj.stallBlockEventsAt !== null && h === BigInt(nodeObj.stallBlockEventsAt)) {
                await new Promise((_resolve, reject) => {
                    const fail = () => reject(stallAbortError ?? signal.reason);
                    if (signal?.aborted) return fail();
                    signal?.addEventListener('abort', fail, { once: true });
                });
            }
            const list = txsByHeight.get(h) ?? [];
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
                        type: tx.summaryType ?? 'accountTransaction',
                        transactionType: 'update',
                        hash: { toString: () => tx.hash },
                        sender: tx.sender ? { address: tx.sender } : undefined,
                        events: [
                            {
                                tag: tx.traceTag ?? 'Updated',
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
            return callRpc('getBlockItemStatus', () => {
                if (submittedByHash.has(hHex)) {
                    const count = (pollCounts.get(hHex) ?? 0) + 1;
                    pollCounts.set(hHex, count);
                    if (pollSequenceForSubmitted) {
                        const custom = pollSequenceForSubmitted(hHex, count);
                        if (custom) return custom;
                    }
                    const sub = submittedByHash.get(hHex);
                    return {
                        status: 'finalized',
                        outcome: {
                            blockHash: blockHashFor(tipHeight),
                            summary: sub.summary,
                        },
                    };
                }
                const tx = registerDataByHash.get(hHex);
                if (!tx) throw new Error(`mock tx ${hHex} not found`);
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
            }, hHex);
        },
        async sendTransaction(signed) {
            submitSeq += 1;
            const hashHex = txHashFor(`submitted-${submitSeq}`);
            const entry = { hashHex, payload: signed.payload, sender: signed.header.sender.address };
            this.submitted.push(entry);
            if (onSendTransaction) await onSendTransaction(entry, this);
            nonceChanges.push({ sender: entry.sender, height: tipHeight });

            if (signed.payload?.type === 21) {
                const dataBuf = Buffer.from(signed.payload.data.data);
                submittedByHash.set(hashHex, {
                    summary: {
                        transactionType: 'registerData',
                        sender: { address: entry.sender },
                        dataRegistered: { data: dataBuf.toString('hex') },
                    },
                });
                registerDataByHash.set(hashHex, {
                    height: tipHeight,
                    hash: hashHex,
                    sender: entry.sender,
                    registerData: dataBuf,
                });
            } else {
                submittedByHash.set(hashHex, {
                    summary: {
                        transactionType: 'update',
                        sender: { address: entry.sender },
                        events: [],
                    },
                });
            }
            return TransactionHash.fromHexString(hashHex);
        },
        async invokeContract(ctx, bh) {
            return callRpc('invokeContract', () => {
                if (onInvokeContract) {
                    const custom = onInvokeContract(ctx, bh, this);
                    if (custom) return custom;
                }
                const method = ctx.method.value ?? String(ctx.method);
                if (method === 'CIS-8004.agentOf') {
                    return {
                        tag: 'success',
                        usedEnergy: { value: 1000n },
                        returnValue: ReturnValue.fromBuffer(encodeAgentOfReturn(agent)),
                    };
                }
                if (method === 'CIS-8004.getMetadata') {
                    const p = Buffer.from(ctx.parameter.buffer);
                    const klen = p.readUInt32LE(9);
                    const key = p.subarray(13, 13 + klen).toString('utf8');
                    return {
                        tag: 'success',
                        usedEnergy: { value: 1000n },
                        returnValue: ReturnValue.fromBuffer(encodeGetMetadataReturn(metadata[key] ?? null)),
                    };
                }
                if (method === 'CIS-8004.getAdmin') {
                    const h = heightFromBlockHash(bh);
                    return {
                        tag: 'success',
                        usedEnergy: { value: 1000n },
                        returnValue: ReturnValue.fromBuffer(encodeGetAdminReturn(adminAt(h))),
                    };
                }
                if (method === 'CIS-8004.setMetadata') {
                    return {
                        tag: 'success',
                        usedEnergy: { value: 1790n },
                        returnValue: ReturnValue.empty(),
                    };
                }
                return { tag: 'failure', usedEnergy: { value: 500n }, reason: { tag: 'InvalidReceive' } };
            }, ctx.method.value ?? String(ctx.method));
        },
    };
    return nodeObj;
}

function buildScenario({
    tipHeight = 60000n,
    regHeight = 1000n,
    mintOwner = OWNER_A,
    agentOwner = OWNER_A,
    agentStatus = 'Active',
    agentRegistered = true,
    includeMint = true,
    anchorHeights = [1050n, 55000n],
    anchorToSeqs = [2, 4],
    extraTxs = [],
    moduleRefAt = () => REGISTRY_MODULE_REF,
    adminAt = () => null,
    stateLookupMap = new Map(),
    stateEntries = [],
    overrideCurrentPointer = undefined,
    overrideCardHash = null,
    beforeRpc = null,
    onInvokeContract = null,
    onSendTransaction = null,
    stallBlockEventsAt = null,
    stallAbortError = null,
    trailCount = 4,
} = {}) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'countersign-node-test-'));
    const { header, records } = makeTrailFixtures(trailCount);
    const trailFile = path.join(dir, 'trail.jsonl');
    writeTrail(trailFile, header, records);

    const { bytes: cardBytes, hashHex } = makeCardBytes({ ownerAccount: agentOwner });
    const cardFile = path.join(dir, 'card.json');
    fs.writeFileSync(cardFile, cardBytes);

    const { at } = commitments(header, records, new Set(anchorToSeqs));
    const dummyNode = createMockNode({ tipHeight });
    const regMs = dummyNode.timeForHeight(regHeight);

    const txs = [];
    if (includeMint) {
        txs.push({
            height: regHeight,
            hash: txHashFor('mint'),
            sender: mintOwner,
            contractEvents: [evMint(TOKEN_ID, mintOwner)],
        });
    }

    let prevAnchorTx = null;
    for (let i = 0; i < anchorHeights.length; i++) {
        const ah = anchorHeights[i];
        const toSeq = anchorToSeqs[i];
        const aHash = txHashFor(`anchor-${i}`);
        const aData = encodeAnchor({ tokenId: TOKEN_ID, toSeq, commitment: at.get(toSeq), prevAnchorTx });
        txs.push({ height: ah, hash: aHash, sender: agentOwner, registerData: aData });
        txs.push({
            height: ah + 3n,
            hash: txHashFor(`setmeta-${i}`),
            sender: agentOwner,
            contractEvents: [evMetadataSet(TOKEN_ID, 'countersign.anchor', aHash, regMs + i * 5000)],
        });
        prevAnchorTx = aHash;
    }
    txs.push(...extraTxs);

    const agent = agentRegistered
        ? {
              tokenId: TOKEN_ID,
              ownerAccount: agentOwner,
              agentUri: 'https://example.com/card.json',
              metadataHashHex: overrideCardHash ?? hashHex,
              status: agentStatus,
              registeredAtMs: regMs,
          }
        : null;

    const currentPtr = overrideCurrentPointer !== undefined ? overrideCurrentPointer : prevAnchorTx;
    const node = createMockNode({
        tipHeight,
        agent,
        metadata: {
            'unitares.agent_uuid': AGENT_UUID,
            ...(currentPtr ? { 'countersign.anchor': currentPtr } : {}),
        },
        txs,
        moduleRefAt,
        adminAt,
        stateLookupMap,
        stateEntries,
        beforeRpc,
        onInvokeContract,
        onSendTransaction,
        stallBlockEventsAt,
        stallAbortError,
    });

    return {
        dir,
        trailFile,
        cardFile,
        cardBytes,
        node,
        agent,
        header,
        records,
        anchorHashes: anchorHeights.map((_, i) => txHashFor(`anchor-${i}`)),
        lastAnchor: prevAnchorTx,
    };
}

function makeTempKeyfile(dir, accountAddress = OWNER_A) {
    const keyfile = path.join(dir, 'test-key.json');
    fs.writeFileSync(keyfile, JSON.stringify({ accountAddress, signKey: crypto.randomBytes(32).toString('hex') }), { mode: 0o600 });
    return keyfile;
}

async function runVerifyQuiet(args) {
    const origLog = console.log;
    const lines = [];
    console.log = (...a) => lines.push(a.join(' '));
    const prevExit = process.exitCode;
    try {
        const ok = await commands.verify(args);
        return { ok, output: lines.join('\n') };
    } finally {
        console.log = origLog;
        process.exitCode = prevExit ?? 0;
    }
}

async function runAnchorQuiet(args) {
    const origLog = console.log;
    const lines = [];
    console.log = (...a) => lines.push(a.join(' '));
    try {
        await commands.anchor(args);
        return { output: lines.join('\n') };
    } finally {
        console.log = origLog;
    }
}

afterEach(() => {
    configureNode(null);
    delete process.env.COUNTERSIGN_NODE;
    delete process.env.COUNTERSIGN_NODE_INSECURE;
    delete process.env.COUNTERSIGN_KEYFILE;
    process.exitCode = 0;
});

test('verifies normal multi-anchor history end-to-end (both --card and fetchCard HTTPS branch)', async () => {
    const s = buildScenario({ anchorHeights: [1050n, 3000n, 55000n], anchorToSeqs: [1, 2, 4] });
    try {
        const resCard = await runVerifyQuiet({ badge: BADGE, trail: s.trailFile, card: s.cardFile, nodeClient: s.node });
        assert.equal(resCard.ok, true, resCard.output);
        assert.match(resCard.output, /VERIFIED: records 1\.\.4 match what was anchored\./);
        assert.match(resCard.output, /3 pointer updates/);

        // Exercise non-card HTTPS fetch branch (with stubbed fetchCard).
        let fetchedUri = null;
        const resFetch = await runVerifyQuiet({
            badge: BADGE,
            trail: s.trailFile,
            nodeClient: s.node,
            fetchCard: async (uri, opts) => {
                fetchedUri = { uri, opts };
                return s.cardBytes;
            },
        });
        assert.equal(resFetch.ok, true, resFetch.output);
        assert.equal(fetchedUri.uri, 'https://example.com/card.json');
        assert.equal(fetchedUri.opts.allowPrivate, false);
    } finally {
        fs.rmSync(s.dir, { recursive: true });
    }
});

test('catches adversarial A -> B -> A pointer hijack hidden inside a 50k-block gap', async () => {
    const evilHash = txHashFor('evil-anchor');
    const evilData = encodeAnchor({
        tokenId: TOKEN_ID,
        toSeq: 3,
        commitment: Buffer.alloc(32, 0xaa),
        prevAnchorTx: txHashFor('anchor-0'),
    });
    const s = buildScenario({
        tipHeight: 60000n,
        regHeight: 1000n,
        anchorHeights: [1050n],
        anchorToSeqs: [2],
        overrideCurrentPointer: txHashFor('anchor-0'),
        extraTxs: [
            { height: 26000n, hash: evilHash, sender: OWNER_A, registerData: evilData },
            {
                height: 26002n,
                hash: txHashFor('evil-ptr'),
                sender: OWNER_A,
                contractEvents: [evMetadataSet(TOKEN_ID, 'countersign.anchor', evilHash, 1700005000000)],
            },
            {
                height: 26005n,
                hash: txHashFor('restore-ptr'),
                sender: OWNER_A,
                contractEvents: [evMetadataSet(TOKEN_ID, 'countersign.anchor', txHashFor('anchor-0'), 1700006000000)],
            },
        ],
    });
    try {
        const { ok, output } = await runVerifyQuiet({ badge: BADGE, trail: s.trailFile, card: s.cardFile, nodeClient: s.node });
        assert.equal(ok, false);
        assert.match(output, /NOT VERIFIED\./);
        assert.match(output, /3 pointer updates/);
        assert.match(output, /FAIL\s+anchors form one unbroken chain/);
    } finally {
        fs.rmSync(s.dir, { recursive: true });
    }
});

test('rejects transfer-and-return, Burn, Mint mismatch, missing Mint, Upgraded, and Unknown event tags', async () => {
    // Transfer-and-return
    const sXfer = buildScenario({
        tipHeight: 60000n,
        anchorHeights: [1050n, 55000n],
        anchorToSeqs: [2, 4],
        extraTxs: [
            { height: 27123n, hash: txHashFor('x-out'), sender: OWNER_A, contractEvents: [evTransfer(TOKEN_ID, OWNER_A, OWNER_B)] },
            { height: 27125n, hash: txHashFor('x-back'), sender: OWNER_B, contractEvents: [evTransfer(TOKEN_ID, OWNER_B, OWNER_A)] },
        ],
    });
    try {
        const { ok, output } = await runVerifyQuiet({ badge: BADGE, trail: sXfer.trailFile, card: sXfer.cardFile, nodeClient: sXfer.node });
        assert.equal(ok, false);
        assert.match(output, /transferred/);
    } finally {
        fs.rmSync(sXfer.dir, { recursive: true });
    }

    // Burn event
    const sBurn = buildScenario({
        anchorHeights: [1050n],
        anchorToSeqs: [2],
        extraTxs: [{ height: 25000n, hash: txHashFor('burn'), sender: OWNER_A, contractEvents: [evBurn(TOKEN_ID, OWNER_A)] }],
    });
    try {
        const { ok, output } = await runVerifyQuiet({ badge: BADGE, trail: sBurn.trailFile, card: sBurn.cardFile, nodeClient: sBurn.node });
        assert.equal(ok, false);
        assert.match(output, /was burned/);
    } finally {
        fs.rmSync(sBurn.dir, { recursive: true });
    }

    // Mint to different owner
    const sWrongMint = buildScenario({ mintOwner: OWNER_B, agentOwner: OWNER_A, anchorHeights: [1050n], anchorToSeqs: [2] });
    try {
        const { ok, output } = await runVerifyQuiet({ badge: BADGE, trail: sWrongMint.trailFile, card: sWrongMint.cardFile, nodeClient: sWrongMint.node });
        assert.equal(ok, false);
        assert.match(output, /minted to .* not current owner/);
    } finally {
        fs.rmSync(sWrongMint.dir, { recursive: true });
    }

    // Missing Mint event
    const sNoMint = buildScenario({ includeMint: false, anchorHeights: [1050n], anchorToSeqs: [2] });
    try {
        const { ok, output } = await runVerifyQuiet({ badge: BADGE, trail: sNoMint.trailFile, card: sNoMint.cardFile, nodeClient: sNoMint.node });
        assert.equal(ok, false);
        assert.match(output, /expected 1 Mint event/);
    } finally {
        fs.rmSync(sNoMint.dir, { recursive: true });
    }

    // Upgraded trace event inside scanned block
    const sUpgradedTrace = buildScenario({
        anchorHeights: [1050n],
        anchorToSeqs: [2],
        extraTxs: [{ height: 20000n, hash: txHashFor('up'), sender: OWNER_A, traceTag: 'Upgraded', contractEvents: [] }],
    });
    try {
        const { ok, output } = await runVerifyQuiet({ badge: BADGE, trail: sUpgradedTrace.trailFile, card: sUpgradedTrace.cardFile, nodeClient: sUpgradedTrace.node });
        assert.equal(ok, false);
        assert.match(output, /contract upgraded/);
    } finally {
        fs.rmSync(sUpgradedTrace.dir, { recursive: true });
    }

    // Unknown contract event tag fails closed
    const sUnknownEv = buildScenario({
        anchorHeights: [1050n],
        anchorToSeqs: [2],
        extraTxs: [{ height: 20000n, hash: txHashFor('unk'), sender: OWNER_A, contractEvents: [Buffer.from('ea0102', 'hex')] }],
    });
    try {
        const { ok, output } = await runVerifyQuiet({ badge: BADGE, trail: sUnknownEv.trailFile, card: sUnknownEv.cardFile, nodeClient: sUnknownEv.node });
        assert.equal(ok, false);
        assert.match(output, /unknown CIS-8004 event tag 0xea/);
    } finally {
        fs.rmSync(sUnknownEv.dir, { recursive: true });
    }
});

test('verifies Revoked and unregistered agents fail verify, and supports account aliases canonically', async () => {
    const sRev = buildScenario({ agentStatus: 'Revoked', anchorHeights: [1050n], anchorToSeqs: [2] });
    try {
        const { ok, output } = await runVerifyQuiet({ badge: BADGE, trail: sRev.trailFile, card: sRev.cardFile, nodeClient: sRev.node });
        assert.equal(ok, false);
        assert.match(output, /agent status is Revoked/);
    } finally {
        fs.rmSync(sRev.dir, { recursive: true });
    }

    const sUnreg = buildScenario({ agentRegistered: false, anchorHeights: [1050n], anchorToSeqs: [2] });
    try {
        const { ok, output } = await runVerifyQuiet({ badge: BADGE, trail: sUnreg.trailFile, card: sUnreg.cardFile, nodeClient: sUnreg.node });
        assert.equal(ok, false);
        assert.match(output, /token 7 is not registered/);
    } finally {
        fs.rmSync(sUnreg.dir, { recursive: true });
    }

    // Account alias sending MetadataSet + registerData must verify canonically and store sender!
    const sAlias = buildScenario({ anchorHeights: [], anchorToSeqs: [] });
    try {
        const { at } = commitments(sAlias.header, sAlias.records, new Set([4]));
        const aliasAnchorHash = txHashFor('alias-anchor');
        const aliasAnchorData = encodeAnchor({ tokenId: TOKEN_ID, toSeq: 4, commitment: at.get(4), prevAnchorTx: null });
        const aliasNode = createMockNode({
            tipHeight: 60000n,
            agent: sAlias.agent,
            metadata: { 'unitares.agent_uuid': AGENT_UUID, 'countersign.anchor': aliasAnchorHash },
            txs: [
                { height: 1000n, hash: txHashFor('mint'), sender: OWNER_A, contractEvents: [evMint(TOKEN_ID, OWNER_A)] },
                { height: 1050n, hash: aliasAnchorHash, sender: OWNER_A_ALIAS, registerData: aliasAnchorData },
                {
                    height: 1053n,
                    hash: txHashFor('set-alias'),
                    sender: OWNER_A_ALIAS,
                    contractEvents: [evMetadataSet(TOKEN_ID, 'countersign.anchor', aliasAnchorHash)],
                },
            ],
        });
        const hist = await readRegistryHistory(TOKEN_ID, {
            tipBlockHash: blockHashFor(60000n),
            tipBlockHeight: 60000n,
            agent: sAlias.agent,
            hintAnchorTxHashes: [aliasAnchorHash],
            nodeClient: aliasNode,
        });
        assert.equal(hist.events[0].sender, OWNER_A_ALIAS);

        const { ok } = await runVerifyQuiet({ badge: BADGE, trail: sAlias.trailFile, card: sAlias.cardFile, nodeClient: aliasNode });
        assert.equal(ok, true);
    } finally {
        fs.rmSync(sAlias.dir, { recursive: true });
    }

    // Non-owner MetadataSet sender in same block as owner tx fails closed.
    const sSameBlockNonOwner = buildScenario({
        anchorHeights: [1050n],
        anchorToSeqs: [2],
        extraTxs: [
            { height: 2000n, hash: txHashFor('bump-a'), sender: OWNER_A, contractEvents: [] },
            {
                height: 2000n,
                hash: txHashFor('forged-meta'),
                sender: OWNER_B,
                contractEvents: [evMetadataSet(TOKEN_ID, 'extra', 'v')],
            },
        ],
    });
    try {
        const { ok, output } = await runVerifyQuiet({ badge: BADGE, trail: sSameBlockNonOwner.trailFile, card: sSameBlockNonOwner.cardFile, nodeClient: sSameBlockNonOwner.node });
        assert.equal(ok, false);
        assert.match(output, /not owner/);
    } finally {
        fs.rmSync(sSameBlockNonOwner.dir, { recursive: true });
    }
});

test('uses real <12802,0> operator state fixture (0700000000000000 rejects, empty 0600000000000000 passes) and rejects UpdateOperator(Add)', async () => {
    let lookedUpKey = null;
    const liveOpLookup = new Map([[LIVE_OWNER_WITH_OP_STATE_KEY, LIVE_OWNER_WITH_OP_SUBMAP_HEX]]);
    const sPre = buildScenario({
        agentOwner: LIVE_OWNER_WITH_OP,
        mintOwner: LIVE_OWNER_WITH_OP,
        anchorHeights: [1050n],
        anchorToSeqs: [2],
        stateLookupMap: liveOpLookup,
        stateEntries: [{ key: LIVE_OWNER_WITH_OP_SUBMAP_ENTRY, value: '' }],
        beforeRpc: (method, arg) => {
            if (method === 'instanceStateLookup') lookedUpKey = arg;
        },
    });
    try {
        const { ok, output } = await runVerifyQuiet({ badge: BADGE, trail: sPre.trailFile, card: sPre.cardFile, nodeClient: sPre.node });
        assert.equal(ok, false);
        assert.equal(lookedUpKey, LIVE_OWNER_WITH_OP_STATE_KEY);
        assert.equal(liveOpLookup.get(lookedUpKey), '0700000000000000');
        assert.match(output, /pre-existing CIS-2 operator/);
    } finally {
        fs.rmSync(sPre.dir, { recursive: true });
    }

    // Real empty submap 0600000000000000 (operator added then removed before registration) must pass!
    const emptyOwner = AccountAddress.fromBuffer(Buffer.from(LIVE_EMPTY_OP_SUBMAP_KEY.slice(16), 'hex')).address;
    const sEmpty = buildScenario({
        agentOwner: emptyOwner,
        mintOwner: emptyOwner,
        anchorHeights: [1050n],
        anchorToSeqs: [2],
        stateLookupMap: new Map([[LIVE_EMPTY_OP_SUBMAP_KEY, LIVE_EMPTY_OP_SUBMAP_HEX]]),
        stateEntries: [{ key: LIVE_OWNER_WITH_OP_SUBMAP_ENTRY, value: '' }], // unrelated 07... key
    });
    try {
        const { ok, output } = await runVerifyQuiet({ badge: BADGE, trail: sEmpty.trailFile, card: sEmpty.cardFile, nodeClient: sEmpty.node });
        assert.equal(ok, true, output);
    } finally {
        fs.rmSync(sEmpty.dir, { recursive: true });
    }

    const sAdd = buildScenario({
        tipHeight: 60000n,
        anchorHeights: [1050n, 55000n],
        anchorToSeqs: [2, 4],
        extraTxs: [
            { height: 30000n, hash: txHashFor('op-add'), sender: OWNER_A, contractEvents: [evUpdateOperator('Add', OWNER_A, LIVE_OWNER_WITH_OP)] },
            { height: 30005n, hash: txHashFor('op-rem'), sender: OWNER_A, contractEvents: [evUpdateOperator('Remove', OWNER_A, LIVE_OWNER_WITH_OP)] },
        ],
    });
    try {
        const { ok, output } = await runVerifyQuiet({ badge: BADGE, trail: sAdd.trailFile, card: sAdd.cardFile, nodeClient: sAdd.node });
        assert.equal(ok, false);
        assert.match(output, /added CIS-2 operator/);
    } finally {
        fs.rmSync(sAdd.dir, { recursive: true });
    }
});

test('pins REGISTRY_MODULE_REF at both reg & tip (even when equal to another module) and resolves omitted tipBlockHash', async () => {
    // Reject even when reg and tip share a non-pinned moduleRef!
    const sUnpinned = buildScenario({
        anchorHeights: [1050n],
        anchorToSeqs: [2],
        moduleRefAt: () => OTHER_MOD_REF,
    });
    try {
        const { ok, output } = await runVerifyQuiet({ badge: BADGE, trail: sUnpinned.trailFile, card: sUnpinned.cardFile, nodeClient: sUnpinned.node });
        assert.equal(ok, false);
        assert.match(output, /sourceModule mismatch/);
    } finally {
        fs.rmSync(sUnpinned.dir, { recursive: true });
    }

    // Reject upgrade mid-life.
    const sUpgrade = buildScenario({
        anchorHeights: [1050n],
        anchorToSeqs: [2],
        moduleRefAt: (h) => (h >= 30000n ? OTHER_MOD_REF : REGISTRY_MODULE_REF),
    });
    try {
        const { ok, output } = await runVerifyQuiet({ badge: BADGE, trail: sUpgrade.trailFile, card: sUpgrade.cardFile, nodeClient: sUpgrade.node });
        assert.equal(ok, false);
        assert.match(output, /sourceModule mismatch/);
    } finally {
        fs.rmSync(sUpgrade.dir, { recursive: true });
    }

    // Omitting tipBlockHash in readRegistryHistory resolves blockHashAt(tipH) cleanly.
    const sOmitted = buildScenario({ anchorHeights: [1050n], anchorToSeqs: [2] });
    try {
        const hist = await readRegistryHistory(TOKEN_ID, {
            tipBlockHeight: 60000n,
            agent: sOmitted.agent,
            hintAnchorTxHashes: [sOmitted.lastAnchor],
            nodeClient: sOmitted.node,
        });
        assert.equal(hist.events.length, 1);
    } finally {
        fs.rmSync(sOmitted.dir, { recursive: true });
    }
});

test('enforces maxOwnerTxs BEFORE hint traversal and bounds/validates hint links', async () => {
    let hintStatusCalls = 0;
    const s = buildScenario({
        anchorHeights: [1050n, 2000n],
        anchorToSeqs: [2, 4],
        beforeRpc: (m) => {
            if (m === 'getBlockItemStatus') hintStatusCalls += 1;
        },
    });
    try {
        await assert.rejects(
            () =>
                readRegistryHistory(TOKEN_ID, {
                    tipBlockHash: blockHashFor(60000n),
                    tipBlockHeight: 60000n,
                    agent: s.agent,
                    hintAnchorTxHashes: [s.lastAnchor],
                    maxOwnerTxs: 3,
                    nodeClient: s.node,
                }),
            /exceeding maxOwnerTxs=3/,
        );
        assert.equal(hintStatusCalls, 0, 'getBlockItemStatus must not be called when maxOwnerTxs is exceeded');
    } finally {
        fs.rmSync(s.dir, { recursive: true });
    }

    // Foreign-sender hint stops traversal and 300-hop hint chain caps at 256.
    const txs = [{ height: 1000n, hash: txHashFor('mint'), sender: OWNER_A, contractEvents: [evMint(TOKEN_ID, OWNER_A)] }];
    let prev = null;
    for (let i = 0; i < 300; i++) {
        const h = txHashFor(`chain-${i}`);
        txs.push({
            height: BigInt(1010 + i),
            hash: h,
            sender: OWNER_A,
            registerData: encodeAnchor({ tokenId: TOKEN_ID, toSeq: i + 1, commitment: Buffer.alloc(32, 1), prevAnchorTx: prev }),
        });
        prev = h;
    }
    const foreignPrev = txHashFor('foreign-prev');
    const foreignHint = txHashFor('foreign-hint');
    txs.push({
        height: 1500n,
        hash: foreignPrev,
        sender: OWNER_B,
        registerData: encodeAnchor({ tokenId: TOKEN_ID, toSeq: 1, commitment: Buffer.alloc(32, 2), prevAnchorTx: null }),
    });
    txs.push({
        height: 1505n,
        hash: foreignHint,
        sender: OWNER_B,
        registerData: encodeAnchor({ tokenId: TOKEN_ID, toSeq: 2, commitment: Buffer.alloc(32, 3), prevAnchorTx: foreignPrev }),
    });

    const dummy = createMockNode({ tipHeight: 60000n });
    const agent = { tokenId: TOKEN_ID, ownerAccount: OWNER_A, registeredAtMs: dummy.timeForHeight(1000n) };
    const statusLookups = [];
    const hintNode = createMockNode({
        tipHeight: 60000n,
        agent,
        txs,
        beforeRpc: (m, arg) => {
            if (m === 'getBlockItemStatus') statusLookups.push(arg);
        },
    });
    await readRegistryHistory(TOKEN_ID, {
        tipBlockHash: blockHashFor(60000n),
        tipBlockHeight: 60000n,
        agent,
        hintAnchorTxHashes: [foreignHint, prev],
        maxOwnerTxs: 400,
        nodeClient: hintNode,
    });
    assert.equal(statusLookups.includes(foreignPrev), false, 'must stop following foreign-sender hint prevAnchorTx');
    assert.ok(statusLookups.length <= 256, `hint lookups (${statusLookups.length}) exceeded cap 256`);
});

test('anchor command covers happy path, concurrent pointer moves, --tx resume, dry-run/energy caps, and trail drift', async () => {
    // 1. Happy path anchor extending existing seq 1..2 to seq 1..4
    const s = buildScenario({ anchorHeights: [1050n], anchorToSeqs: [2] });
    try {
        process.env.COUNTERSIGN_KEYFILE = makeTempKeyfile(s.dir, OWNER_A);
        const { output } = await runAnchorQuiet({ trail: s.trailFile, nodeClient: s.node });
        assert.match(output, /anchored seq 1\.\.4:/);
        assert.match(output, /registry entry now points at the anchor:/);
        assert.equal(s.node.submitted.length, 2);
        const rdPayload = Buffer.from(s.node.submitted[0].payload.data.data);
        const dec = decodeAnchor(rdPayload);
        assert.equal(dec.tokenId, TOKEN_ID);
        assert.equal(dec.toSeq, 4);
        assert.equal(dec.prevAnchorTx, s.lastAnchor);
        assert.equal(s.node.submitted[1].payload.receiveName.value, 'CIS-8004.setMetadata');

        // 2. --tx resume path skips sendRegisterData and only submits setMetadata
        const sResume = buildScenario({ anchorHeights: [1050n], anchorToSeqs: [2] });
        try {
            process.env.COUNTERSIGN_KEYFILE = makeTempKeyfile(sResume.dir, OWNER_A);
            const preHash = txHashFor('precomputed-anchor');
            const { at } = commitments(sResume.header, sResume.records, new Set([4]));
            const preData = encodeAnchor({ tokenId: TOKEN_ID, toSeq: 4, commitment: at.get(4), prevAnchorTx: sResume.lastAnchor });
            const resumeNode = createMockNode({
                tipHeight: 60000n,
                agent: sResume.agent,
                metadata: { 'unitares.agent_uuid': AGENT_UUID, 'countersign.anchor': sResume.lastAnchor },
                txs: [
                    { height: 1000n, hash: txHashFor('mint'), sender: OWNER_A, contractEvents: [evMint(TOKEN_ID, OWNER_A)] },
                    { height: 1050n, hash: sResume.lastAnchor, sender: OWNER_A, registerData: encodeAnchor({ tokenId: TOKEN_ID, toSeq: 2, commitment: commitments(sResume.header, sResume.records, new Set([2])).at.get(2), prevAnchorTx: null }) },
                    { height: 1053n, hash: txHashFor('set-0'), sender: OWNER_A, contractEvents: [evMetadataSet(TOKEN_ID, 'countersign.anchor', sResume.lastAnchor)] },
                    { height: 1100n, hash: preHash, sender: OWNER_A, registerData: preData },
                ],
            });
            await runAnchorQuiet({ trail: sResume.trailFile, tx: preHash, nodeClient: resumeNode });
            assert.equal(resumeNode.submitted.length, 1);
            assert.equal(resumeNode.submitted[0].payload.receiveName.value, 'CIS-8004.setMetadata');
        } finally {
            fs.rmSync(sResume.dir, { recursive: true });
        }

        // 3. Concurrent pointer move right BEFORE sendRegisterData
        let getMetaCount1 = 0;
        const sRace1 = buildScenario({
            anchorHeights: [1050n],
            anchorToSeqs: [2],
            onInvokeContract: (ctx) => {
                if (ctx.method.value === 'CIS-8004.getMetadata') {
                    getMetaCount1 += 1;
                    if (getMetaCount1 === 2) {
                        return { tag: 'success', usedEnergy: { value: 1000n }, returnValue: ReturnValue.fromBuffer(encodeGetMetadataReturn(txHashFor('other'))) };
                    }
                }
            },
        });
        try {
            process.env.COUNTERSIGN_KEYFILE = makeTempKeyfile(sRace1.dir, OWNER_A);
            await assert.rejects(() => runAnchorQuiet({ trail: sRace1.trailFile, nodeClient: sRace1.node }), /moved concurrently/);
            assert.equal(sRace1.node.submitted.length, 0);
        } finally {
            fs.rmSync(sRace1.dir, { recursive: true });
        }

        // 4. Concurrent pointer move right BEFORE sendSetMetadata (after registerData landed)
        let getMetaCount2 = 0;
        const sRace2 = buildScenario({
            anchorHeights: [1050n],
            anchorToSeqs: [2],
            onInvokeContract: (ctx) => {
                if (ctx.method.value === 'CIS-8004.getMetadata') {
                    getMetaCount2 += 1;
                    if (getMetaCount2 === 3) {
                        return { tag: 'success', usedEnergy: { value: 1000n }, returnValue: ReturnValue.fromBuffer(encodeGetMetadataReturn(txHashFor('other-2'))) };
                    }
                }
            },
        });
        try {
            process.env.COUNTERSIGN_KEYFILE = makeTempKeyfile(sRace2.dir, OWNER_A);
            await assert.rejects(() => runAnchorQuiet({ trail: sRace2.trailFile, nodeClient: sRace2.node }), /moved concurrently/);
            assert.equal(sRace2.node.submitted.length, 1, 'only registerData should have been sent, not setMetadata');
        } finally {
            fs.rmSync(sRace2.dir, { recursive: true });
        }

        // 5. Dry-run failure refusal
        const sDryFail = buildScenario({
            anchorHeights: [1050n],
            anchorToSeqs: [2],
            onInvokeContract: (ctx) => {
                if (ctx.method.value === 'CIS-8004.setMetadata') {
                    return { tag: 'failure', usedEnergy: { value: 500n }, reason: { tag: 'Unauthorized' } };
                }
            },
        });
        try {
            process.env.COUNTERSIGN_KEYFILE = makeTempKeyfile(sDryFail.dir, OWNER_A);
            await assert.rejects(() => runAnchorQuiet({ trail: sDryFail.trailFile, nodeClient: sDryFail.node }), /dry-run CIS-8004\.setMetadata failed/);
            assert.equal(sDryFail.node.submitted.length, 1);
        } finally {
            fs.rmSync(sDryFail.dir, { recursive: true });
        }

        // 6. Energy cap refusal (> 100,000)
        const sEnergy = buildScenario({
            anchorHeights: [1050n],
            anchorToSeqs: [2],
            onInvokeContract: (ctx) => {
                if (ctx.method.value === 'CIS-8004.setMetadata') {
                    return { tag: 'success', usedEnergy: { value: 95000n }, returnValue: ReturnValue.empty() };
                }
            },
        });
        try {
            process.env.COUNTERSIGN_KEYFILE = makeTempKeyfile(sEnergy.dir, OWNER_A);
            await assert.rejects(() => runAnchorQuiet({ trail: sEnergy.trailFile, nodeClient: sEnergy.node }), /cap 100000/);
            assert.equal(sEnergy.node.submitted.length, 1);
        } finally {
            fs.rmSync(sEnergy.dir, { recursive: true });
        }

        // 7. Trail drift refusal
        const driftedTrail = path.join(s.dir, 'drifted.jsonl');
        const driftedRecords = structuredClone(s.records);
        driftedRecords[0].report_excerpt = 'TAMPERED';
        writeTrail(driftedTrail, s.header, driftedRecords);
        process.env.COUNTERSIGN_KEYFILE = makeTempKeyfile(s.dir, OWNER_A);
        await assert.rejects(() => runAnchorQuiet({ trail: driftedTrail, nodeClient: s.node }), /does not match the anchor/);

        // 8. Alias signer refusal before submitting registerData
        const sAliasSigner = buildScenario({ anchorHeights: [1050n], anchorToSeqs: [2] });
        try {
            process.env.COUNTERSIGN_KEYFILE = makeTempKeyfile(sAliasSigner.dir, OWNER_A_ALIAS);
            await assert.rejects(
                () => runAnchorQuiet({ trail: sAliasSigner.trailFile, nodeClient: sAliasSigner.node }),
                /must exactly match registered owner/,
            );
            assert.equal(sAliasSigner.node.submitted.length, 0, 'must abort before submitting registerData');
        } finally {
            fs.rmSync(sAliasSigner.dir, { recursive: true });
        }
    } finally {
        fs.rmSync(s.dir, { recursive: true });
    }
});

test('polls getBlockItemStatus through received -> finalized in signSendWait', async () => {
    const s = buildScenario({ anchorHeights: [], anchorToSeqs: [] });
    let polls = 0;
    const pollNode = createMockNode({
        tipHeight: 60000n,
        agent: s.agent,
        pollSequenceForSubmitted: (_h, count) => {
            polls = count;
            if (count < 3) return { status: 'received' };
            return null;
        },
    });
    const origLog = console.log;
    console.log = () => {};
    try {
        const who = {
            address: OWNER_A,
            sender: AccountAddress.fromBase58(OWNER_A),
            signer: (await import('@concordium/web-sdk')).buildBasicAccountSigner(crypto.randomBytes(32).toString('hex')),
        };
        const res = await sendSetMetadata(TOKEN_ID, 'k', 'v', who, pollNode, { pollIntervalMs: 5, timeoutMs: 2000 });
        assert.ok(res.hash);
        assert.equal(polls, 3);
    } finally {
        console.log = origLog;
        fs.rmSync(s.dir, { recursive: true });
    }
});

test('createRpcPool retries DEADLINE_EXCEEDED/429/UNAVAILABLE, does NOT retry "block height 429", and aborts stalled streams', async () => {
    assert.equal(isTransientRpcError(new Error('block height 429 not found')), false);
    assert.equal(isTransientRpcError(new Error('Received HTTP status code 429')), true);
    assert.equal(isTransientRpcError(Object.assign(new Error('timeout'), { code: 'DEADLINE_EXCEEDED' })), true);
    assert.equal(isTransientRpcError(Object.assign(new Error('timeout'), { code: 4 })), true);

    const pool = createRpcPool(5, { maxRetries: 4, baseDelayMs: 5 });
    let heightErrCalls = 0;
    await assert.rejects(
        () =>
            pool.run(async () => {
                heightErrCalls += 1;
                throw new Error('block height 429');
            }),
        /block height 429/,
    );
    assert.equal(heightErrCalls, 1, 'must NOT retry non-HTTP-429 error mentioning 429');

    let attempts = 0;
    const res = await pool.run(async () => {
        attempts += 1;
        if (attempts === 1) throw Object.assign(new Error('Received HTTP status code 429'), { code: 'UNAVAILABLE' });
        if (attempts === 2) throw Object.assign(new Error('limit'), { code: 'RESOURCE_EXHAUSTED' });
        if (attempts === 3) throw Object.assign(new Error('deadline'), { code: 'DEADLINE_EXCEEDED' });
        return 'ok';
    });
    assert.equal(res, 'ok');
    assert.equal(attempts, 4);

    // Stalled gRPC stream throwing CANCELLED upon abortSignal abort translates to DEADLINE_EXCEEDED and retries cleanly to success.
    let stallAttempts = 0;
    const cancelErr = Object.assign(new Error('Cancelled on client'), { code: 'CANCELLED', details: 'Cancelled on client' });
    const sStall = buildScenario({
        anchorHeights: [1050n],
        anchorToSeqs: [2],
        stallBlockEventsAt: 1053n,
        stallAbortError: cancelErr,
        beforeRpc: (method, bh) => {
            if (method === 'getBlockTransactionEvents' && String(bh) === 'block-1053') {
                stallAttempts += 1;
                if (stallAttempts === 2) sStall.node.stallBlockEventsAt = null;
            }
        },
    });
    try {
        // First fails when maxRetries=0 (single stalled attempt) -> DEADLINE_EXCEEDED
        await assert.rejects(
            () =>
                readRegistryHistory(TOKEN_ID, {
                    tipBlockHash: blockHashFor(60000n),
                    tipBlockHeight: 60000n,
                    agent: sStall.agent,
                    hintAnchorTxHashes: [sStall.lastAnchor],
                    streamTimeoutMs: 20,
                    pool: createRpcPool(5, { maxRetries: 0, baseDelayMs: 5 }),
                    nodeClient: sStall.node,
                }),
            (err) => err.code === 'DEADLINE_EXCEEDED' && /timed out/.test(err.message),
        );
        // Next retry succeeds once stream stops stalling!
        const hist = await readRegistryHistory(TOKEN_ID, {
            tipBlockHash: blockHashFor(60000n),
            tipBlockHeight: 60000n,
            agent: sStall.agent,
            hintAnchorTxHashes: [sStall.lastAnchor],
            streamTimeoutMs: 20,
            pool: createRpcPool(5, { maxRetries: 2, baseDelayMs: 5 }),
            nodeClient: sStall.node,
        });
        assert.equal(hist.events.length, 1);
        assert.equal(stallAttempts, 2);
    } finally {
        fs.rmSync(sStall.dir, { recursive: true });
    }
});

test('node configuration never inherits overridden COUNTERSIGN_NODE plaintext scheme', async () => {
    const mainnetGenesis = '9dd9ca4d19e9393877d2c44b70f89acbfc0883c2243e5eeaecc0d1cd0503f478';
    const badNode = createMockNode({ genesisBlock: mainnetGenesis });
    await assert.rejects(() => assertTestnet(badNode), /not Concordium testnet/);

    assert.deepEqual(configureNode('http://127.0.0.1:20001'), { host: '127.0.0.1', port: 20001, tls: false, rpcTimeoutMs: 30000 });
    assert.deepEqual(configureNode('grpc://localhost:20002'), { host: 'localhost', port: 20002, tls: false, rpcTimeoutMs: 30000 });
    assert.deepEqual(configureNode('grpcs://node.example:20003'), { host: 'node.example', port: 20003, tls: true, rpcTimeoutMs: 30000 });
    assert.throws(() => configureNode({ host: 'https://node.example:20000', tls: false }), /explicit TLS scheme/);

    // Overridden COUNTERSIGN_NODE=http://... must NOT leak tls:false into bare host overrides!
    process.env.COUNTERSIGN_NODE = 'http://old:20000';
    assert.equal(configureNode(null).tls, false);
    assert.deepEqual(configureNode({ host: 'new', port: 20000 }), { host: 'new', port: 20000, tls: true, rpcTimeoutMs: 30000 });
    assert.deepEqual(configureNode('new:20000'), { host: 'new', port: 20000, tls: true, rpcTimeoutMs: 30000 });
    assert.deepEqual(configureNode({ host: 'new', insecure: true }), { host: 'new', port: 20000, tls: false, rpcTimeoutMs: 30000 });

    configureNode(null);
    process.env.COUNTERSIGN_NODE = '[::1]:20000';
    process.env.COUNTERSIGN_NODE_INSECURE = '1';
    const ipv6Cfg = configureNode(null);
    assert.equal(ipv6Cfg.host, '::1');
    assert.equal(ipv6Cfg.port, 20000);
    assert.equal(ipv6Cfg.tls, false);
    assert.equal(formatGrpcHost(ipv6Cfg.host), '[::1]');

    const grpcClient = createGrpcClient(ipv6Cfg);
    assert.equal(grpcClient.client._transport.defaultOptions.host, '[::1]:20000');
    assert.equal(grpcClient.client._transport.defaultOptions.timeout, 30000);
});

test('getAdmin + admin nonce scan catches transient upgrade and AdminTransferred even with 0 owner txs', async () => {
    // 1. Admin present (OWNER_B) with unchanged adminNonce passes with 0 extra block scans.
    let scannedHeights = [];
    const sCleanAdmin = buildScenario({
        anchorHeights: [1050n],
        anchorToSeqs: [2],
        adminAt: () => OWNER_B,
        beforeRpc: (m, bh) => {
            if (m === 'getBlockTransactionEvents') scannedHeights.push(String(bh));
        },
    });
    try {
        const { ok, output } = await runVerifyQuiet({ badge: BADGE, trail: sCleanAdmin.trailFile, card: sCleanAdmin.cardFile, nodeClient: sCleanAdmin.node });
        assert.equal(ok, true, output);
        // Only block-1000 (Mint), block-1050 (registerData), block-1053 (setMetadata) were fetched.
        assert.deepEqual(scannedHeights.sort(), ['block-1000', 'block-1050', 'block-1053']);
    } finally {
        fs.rmSync(sCleanAdmin.dir, { recursive: true });
    }

    // 2. Transient upgrade M_orig -> M_evil -> M_orig by OWNER_B with 0 owner txs after anchor must fail closed!
    const sTransientUpgrade = buildScenario({
        anchorHeights: [1050n],
        anchorToSeqs: [2],
        adminAt: () => OWNER_B,
        moduleRefAt: (h) => (h >= 20000n && h < 20010n ? OTHER_MOD_REF : REGISTRY_MODULE_REF),
        extraTxs: [
            { height: 20000n, hash: txHashFor('adm-up-1'), sender: OWNER_B, traceTag: 'Upgraded', contractEvents: [] },
            { height: 20010n, hash: txHashFor('adm-up-2'), sender: OWNER_B, traceTag: 'Upgraded', contractEvents: [] },
        ],
    });
    try {
        const { ok, output } = await runVerifyQuiet({ badge: BADGE, trail: sTransientUpgrade.trailFile, card: sTransientUpgrade.cardFile, nodeClient: sTransientUpgrade.node });
        assert.equal(ok, false);
        assert.match(output, /contract upgraded/);
    } finally {
        fs.rmSync(sTransientUpgrade.dir, { recursive: true });
    }

    // 3. Transient AdminTransferred (OWNER_B -> LIVE_OWNER_WITH_OP -> OWNER_B) caught even when regAdmin === tipAdmin!
    const sAdminTransfer = buildScenario({
        anchorHeights: [1050n],
        anchorToSeqs: [2],
        adminAt: () => OWNER_B,
        extraTxs: [
            { height: 25000n, hash: txHashFor('adm-x1'), sender: OWNER_B, contractEvents: [evAdminTransferred(OWNER_B, LIVE_OWNER_WITH_OP)] },
            { height: 25005n, hash: txHashFor('adm-x2'), sender: LIVE_OWNER_WITH_OP, contractEvents: [evAdminTransferred(LIVE_OWNER_WITH_OP, OWNER_B)] },
        ],
    });
    try {
        const { ok, output } = await runVerifyQuiet({ badge: BADGE, trail: sAdminTransfer.trailFile, card: sAdminTransfer.cardFile, nodeClient: sAdminTransfer.node });
        assert.equal(ok, false);
        assert.match(output, /registry admin transferred/);
    } finally {
        fs.rmSync(sAdminTransfer.dir, { recursive: true });
    }

    // 4. Admin changed between reg and tip fails closed.
    const sAdminDiff = buildScenario({
        anchorHeights: [1050n],
        anchorToSeqs: [2],
        adminAt: (h) => (h >= 20000n ? LIVE_OWNER_WITH_OP : OWNER_B),
    });
    try {
        const { ok, output } = await runVerifyQuiet({ badge: BADGE, trail: sAdminDiff.trailFile, card: sAdminDiff.cardFile, nodeClient: sAdminDiff.node });
        assert.equal(ok, false);
        assert.match(output, /registry admin changed/);
    } finally {
        fs.rmSync(sAdminDiff.dir, { recursive: true });
    }

    // 5. Upgraded trace event in regHeight BEFORE Mint tx fails closed!
    const sPreMintUpgrade = buildScenario({
        anchorHeights: [1050n],
        anchorToSeqs: [2],
        extraTxs: [{ height: 1000n, hash: txHashFor('pre-mint-up'), sender: OWNER_B, traceTag: 'Upgraded', contractEvents: [] }],
    });
    // Put pre-mint upgrade BEFORE Mint in block 1000 by ordering it first in txs!
    const preMintNode = createMockNode({
        tipHeight: 60000n,
        agent: sPreMintUpgrade.agent,
        metadata: { 'unitares.agent_uuid': AGENT_UUID, 'countersign.anchor': sPreMintUpgrade.lastAnchor },
        txs: [
            { height: 1000n, hash: txHashFor('pre-mint-up'), sender: OWNER_B, traceTag: 'Upgraded', contractEvents: [] },
            { height: 1000n, hash: txHashFor('mint'), sender: OWNER_A, contractEvents: [evMint(TOKEN_ID, OWNER_A)] },
        ],
    });
    try {
        await assert.rejects(
            () =>
                readRegistryHistory(TOKEN_ID, {
                    tipBlockHash: blockHashFor(60000n),
                    tipBlockHeight: 60000n,
                    agent: sPreMintUpgrade.agent,
                    nodeClient: preMintNode,
                }),
            /contract upgraded/,
        );
    } finally {
        fs.rmSync(sPreMintUpgrade.dir, { recursive: true });
    }
});

test('preserves ascending history order across multiple BATCH_SIZE=10 block batches', async () => {
    const count = 14;
    const anchorHeights = Array.from({ length: count }, (_, i) => BigInt(1050 + i * 20));
    const anchorToSeqs = Array.from({ length: count }, (_, i) => i + 1);
    const s = buildScenario({ trailCount: count, anchorHeights, anchorToSeqs });
    try {
        const { ok, output } = await runVerifyQuiet({ badge: BADGE, trail: s.trailFile, card: s.cardFile, nodeClient: s.node });
        assert.equal(ok, true, output);
        assert.match(output, /VERIFIED: records 1\.\.14 match what was anchored\./);
        assert.match(output, /14 pointer updates/);
    } finally {
        fs.rmSync(s.dir, { recursive: true });
    }
});

test('bounds signSendWait polling and transient retry budget by remaining finalization timeout', async () => {
    const s = buildScenario({ anchorHeights: [], anchorToSeqs: [] });
    let pollCalls = 0;
    const timeoutNode = createMockNode({
        tipHeight: 60000n,
        agent: s.agent,
        pollSequenceForSubmitted: () => {
            pollCalls += 1;
            const e = new Error('transient');
            e.code = 'UNAVAILABLE';
            throw e;
        },
    });
    const origLog = console.log;
    console.log = () => {};
    const t0 = Date.now();
    try {
        const who = {
            address: OWNER_A,
            sender: AccountAddress.fromBase58(OWNER_A),
            signer: (await import('@concordium/web-sdk')).buildBasicAccountSigner(crypto.randomBytes(32).toString('hex')),
        };
        await assert.rejects(
            () => sendSetMetadata(TOKEN_ID, 'k', 'v', who, timeoutNode, { pollIntervalMs: 10, timeoutMs: 40 }),
            /transient/,
        );
        const elapsed = Date.now() - t0;
        assert.ok(elapsed < 500, `expected short bounded timeout, took ${elapsed}ms`);
        assert.equal(pollCalls, 1, 'remaining <= 1500ms must pass maxRetries=0');
    } finally {
        console.log = origLog;
        fs.rmSync(s.dir, { recursive: true });
    }
});

test('readRegisterData returns blockHeight alongside sender, data, and blockTime', async () => {
    const s = buildScenario({ anchorHeights: [1050n], anchorToSeqs: [2] });
    try {
        const rd = await readRegisterData(s.lastAnchor, s.node);
        assert.equal(rd.blockHeight, 1050);
        assert.equal(rd.sender, OWNER_A);
        assert.equal(rd.data.length, 85);
        assert.ok(Date.parse(rd.blockTime) > 0);
    } finally {
        fs.rmSync(s.dir, { recursive: true });
    }
});

test('enforces wall-clock timeout even when in-flight getBlockItemStatus resolves after deadline', async () => {
    const s = buildScenario({ anchorHeights: [], anchorToSeqs: [] });
    const slowNode = createMockNode({ tipHeight: 60000n, agent: s.agent });
    const origGetStatus = slowNode.getBlockItemStatus.bind(slowNode);
    let releaseRpc;
    let rpcSettled = false;
    slowNode.getBlockItemStatus = async (txHash) => {
        await new Promise((resolve) => {
            releaseRpc = () => {
                rpcSettled = true;
                resolve();
            };
        });
        return origGetStatus(txHash);
    };
    const origLog = console.log;
    console.log = () => {};
    try {
        const who = {
            address: OWNER_A,
            sender: AccountAddress.fromBase58(OWNER_A),
            signer: (await import('@concordium/web-sdk')).buildBasicAccountSigner(crypto.randomBytes(32).toString('hex')),
        };
        await assert.rejects(
            () => sendSetMetadata(TOKEN_ID, 'k', 'v', who, slowNode, { pollIntervalMs: 10, timeoutMs: 25 }),
            /did not finalize within 25ms/,
        );
        assert.equal(rpcSettled, false, 'must reject while in-flight getBlockItemStatus is still pending');
    } finally {
        releaseRpc?.();
        console.log = origLog;
        fs.rmSync(s.dir, { recursive: true });
    }
});

test('rejects via post-race monotonic deadline check when clock expires before synchronous finalized return', async () => {
    const s = buildScenario({ anchorHeights: [], anchorToSeqs: [] });
    const expiredNode = createMockNode({ tipHeight: 60000n, agent: s.agent });
    const origGetStatus = expiredNode.getBlockItemStatus.bind(expiredNode);
    let t = 0;
    expiredNode.getBlockItemStatus = async (txHash) => {
        t = 30; // advances past timeoutMs = 25 synchronously before timer fires
        return origGetStatus(txHash);
    };
    const origLog = console.log;
    console.log = () => {};
    try {
        const who = {
            address: OWNER_A,
            sender: AccountAddress.fromBase58(OWNER_A),
            signer: (await import('@concordium/web-sdk')).buildBasicAccountSigner(crypto.randomBytes(32).toString('hex')),
        };
        await assert.rejects(
            () => sendSetMetadata(TOKEN_ID, 'k', 'v', who, expiredNode, { pollIntervalMs: 10, timeoutMs: 25, now: () => t }),
            /did not finalize within 25ms/,
        );
    } finally {
        console.log = origLog;
        fs.rmSync(s.dir, { recursive: true });
    }
});

test('cancels getInstanceState stream immediately on first matching operator key without retrying', async () => {
    const s = buildScenario({
        agentOwner: LIVE_OWNER_WITH_OP,
        mintOwner: LIVE_OWNER_WITH_OP,
        anchorHeights: [1050n],
        anchorToSeqs: [2],
        stateLookupMap: new Map([[LIVE_OWNER_WITH_OP_STATE_KEY, LIVE_OWNER_WITH_OP_SUBMAP_HEX]]),
    });
    let getInstanceStateCalls = 0;
    let yieldedCount = 0;
    let signalAbortedOnExit = false;
    const entries = [
        { key: LIVE_OWNER_WITH_OP_SUBMAP_ENTRY, value: '' },
        { key: '0700000000000000deadbeef', value: '' },
        { key: '0700000000000000cafebabe', value: '' },
        { key: '080000000000000000000001', value: '' },
    ];
    s.node.getInstanceState = async function* (_addr, _bh, signal) {
        getInstanceStateCalls += 1;
        try {
            for (const e of entries) {
                yieldedCount += 1;
                yield e;
            }
        } finally {
            signalAbortedOnExit = Boolean(signal?.aborted);
        }
    };
    try {
        await assert.rejects(
            () =>
                readRegistryHistory(TOKEN_ID, {
                    tipBlockHash: blockHashFor(60000n),
                    tipBlockHeight: 60000n,
                    agent: s.agent,
                    hintAnchorTxHashes: [s.lastAnchor],
                    nodeClient: s.node,
                }),
            /pre-existing CIS-2 operator/,
        );
        assert.equal(getInstanceStateCalls, 1, 'must not retry after intentional early match');
        assert.equal(yieldedCount, 1, 'must stop iterating immediately on first matching key');
        assert.equal(signalAbortedOnExit, true, 'abortSignal must be aborted immediately on first match');
    } finally {
        fs.rmSync(s.dir, { recursive: true });
    }
});

test('withRpcRetry preserves Date.now epoch-based deadlineMs default when no custom clock is supplied', async () => {
    let calls = 0;
    await assert.rejects(
        () =>
            withRpcRetry(
                async () => {
                    calls += 1;
                    const err = new Error('temporary failure');
                    err.code = 'UNAVAILABLE';
                    throw err;
                },
                { deadlineMs: Date.now() - 1, maxRetries: 2, baseDelayMs: 0 },
            ),
        /temporary failure/,
    );
    assert.equal(calls, 1, 'already-expired Date.now() deadlineMs must stop before retrying');
});
