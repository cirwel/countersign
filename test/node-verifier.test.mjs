import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, test } from 'node:test';
import { AccountAddress, ReturnValue } from '@concordium/web-sdk';
import {
    TESTNET_GENESIS,
    assertTestnet,
    configureNode,
    createRpcPool,
    readRegisterData,
    readRegistryHistory,
} from '../src/chain.mjs';
import { encodeBadge, encodeTokenId } from '../src/cis8004.mjs';
import { commands } from '../src/cli.mjs';
import { REGISTRY } from '../src/registry.mjs';
import { commitments, encodeAnchor, writeTrail } from '../src/trail.mjs';

const GENESIS_PREFIX = TESTNET_GENESIS.slice(0, 32);
const OWNER_A = '4NAnnhZUSYiyJLM9k6H7dVPn1uuPGStu2LZEety7zmp1LBYw41';
const OWNER_B = '3dt3UMPzRASZndjmKpSWgCP2HhmoxZrgs8FDPtZjNHZzj13hhB';
const OPERATOR_C = '3qYSik7b8w9NsgeAk91Mrpapq9T5S7EGvmsa3Ecf4449xiJ8cX';
const AGENT_UUID = '00000000-0000-4000-8000-000000000001';
const TOKEN_ID = '7';
const BADGE = encodeBadge(TOKEN_ID);
const MOD_REF_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const MOD_REF_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

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
        Buffer.from([0]), // externalReference: None
        Buffer.from([0]), // agentWallet: None
        Buffer.from([agent.status === 'Revoked' ? 1 : 0]),
        u64le(agent.registeredAtMs),
        Buffer.from([0]), // revokedAt: None
        Buffer.from([0]), // revocationReason: None
        u32le(0), // onChainMetadata
    ]);
}

function encodeGetMetadataReturn(val) {
    if (val === null || val === undefined) return Buffer.from([0]);
    const b = Buffer.from(val, 'utf8');
    return Buffer.concat([Buffer.from([1]), u32le(b.length), b]);
}

const evMint = (tokenId, owner) =>
    Buffer.concat([Buffer.from([0xfe]), encodeTokenId(tokenId), Buffer.from([1, 0]), acctBytes(owner)]);

const evTransfer = (tokenId, from, to) =>
    Buffer.concat([Buffer.from([0xff]), encodeTokenId(tokenId), Buffer.from([1, 0]), acctBytes(from), Buffer.from([0]), acctBytes(to)]);

const evUpdateOperator = (update, owner, operator) =>
    Buffer.concat([Buffer.from([0xfc, update === 'Add' ? 1 : 0, 0]), acctBytes(owner), Buffer.from([0]), acctBytes(operator)]);

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
            recorded_at: `2026-11-01T00:00:0${i}.000000Z`,
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

/**
 * In-memory mock Concordium gRPC client supporting height/time interpolation,
 * account nonces, block transaction events, instance state/info, registerData, and invokeContract.
 */
function createMockNode({
    genesisBlock = TESTNET_GENESIS,
    tipHeight = 60000n,
    baseTimeMs = 1700000000000,
    msPerBlock = (h) => 2000 + (Number(h) % 3) * 10, // slightly non-linear to exercise interpolation + binary search
    agent,
    metadata = {},
    txs = [], // { height, hash, sender, registerData?: Buffer, contractEvents?: Buffer[] }
    moduleRefAt = () => MOD_REF_A,
    initialOperators = new Map(), // ownerHex -> { submapHex, keys: string[] }
    beforeRpc = null,
} = {}) {
    const txsByHeight = new Map();
    const registerDataByHash = new Map();
    const nonceChangesByOwner = new Map();

    for (const tx of txs) {
        const h = BigInt(tx.height);
        if (!txsByHeight.has(h)) txsByHeight.set(h, []);
        txsByHeight.get(h).push(tx);

        if (tx.sender) {
            if (!nonceChangesByOwner.has(tx.sender)) nonceChangesByOwner.set(tx.sender, []);
            nonceChangesByOwner.get(tx.sender).push(h);
        }
        if (tx.registerData) {
            registerDataByHash.set(tx.hash, tx);
        }
    }
    for (const arr of nonceChangesByOwner.values()) {
        arr.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    }

    const timeForHeight = (h) => {
        const hn = Number(h);
        // Strictly increasing timestamps with mild drift.
        return baseTimeMs + hn * 2000 + Math.floor(Math.sin(hn / 1000) * 50) + (msPerBlock ? Number(msPerBlock(h)) - 2000 : 0);
    };

    const heightFromBlockHash = (bh) => {
        if (typeof bh?.height === 'bigint') return bh.height;
        const m = /^block-(\d+)$/.exec(String(bh));
        if (!m) throw new Error(`unknown mock blockHash ${bh}`);
        return BigInt(m[1]);
    };

    const callRpc = async (method, fn) => {
        if (beforeRpc) await beforeRpc(method);
        return fn();
    };

    return {
        timeForHeight,
        async getConsensusStatus() {
            return callRpc('getConsensusStatus', () => ({
                genesisBlock: { toString: () => genesisBlock },
                lastFinalizedBlock: blockHashFor(tipHeight),
                lastFinalizedBlockHeight: BigInt(tipHeight),
            }));
        },
        async getBlocksAtHeight(h) {
            return callRpc('getBlocksAtHeight', () => [blockHashFor(BigInt(h))]);
        },
        async getBlockInfo(bh) {
            return callRpc('getBlockInfo', () => {
                const h = heightFromBlockHash(bh);
                return {
                    blockHeight: h,
                    blockSlotTime: new Date(timeForHeight(h)),
                };
            });
        },
        async getAccountInfo(acct, bh) {
            return callRpc('getAccountInfo', () => {
                const h = heightFromBlockHash(bh);
                const list = nonceChangesByOwner.get(acct.address) ?? [];
                let count = 1n;
                for (const th of list) {
                    if (th <= h) count += 1n;
                }
                return { accountNonce: { value: count } };
            });
        },
        async getInstanceInfo(_addr, bh) {
            return callRpc('getInstanceInfo', () => {
                const h = heightFromBlockHash(bh);
                return { sourceModule: { moduleRef: moduleRefAt(h) } };
            });
        },
        async instanceStateLookup(_addr, keyHex, _bh) {
            return callRpc('instanceStateLookup', () => {
                if (keyHex.startsWith('0500000000000000')) {
                    const ownerHex = keyHex.slice(16);
                    const entry = initialOperators.get(ownerHex);
                    if (entry) return entry.submapHex;
                }
                const err = new Error('Key not found.');
                err.code = 'NOT_FOUND';
                throw err;
            });
        },
        async *getInstanceState(_addr, _bh) {
            await callRpc('getInstanceState', () => {});
            for (const entry of initialOperators.values()) {
                for (const k of entry.keys) {
                    yield { key: k, value: '' };
                }
            }
        },
        async *getBlockTransactionEvents(bh) {
            await callRpc('getBlockTransactionEvents', () => {});
            const h = heightFromBlockHash(bh);
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
            return callRpc('getBlockItemStatus', () => {
                const hHex = txHash.toString();
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
            });
        },
        async invokeContract(ctx, _bh) {
            return callRpc('invokeContract', () => {
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
                return { tag: 'failure', usedEnergy: { value: 500n }, reason: { tag: 'InvalidReceive' } };
            });
        },
    };
}

function buildScenario({
    tipHeight = 60000n,
    regHeight = 1000n,
    mintOwner = OWNER_A,
    agentOwner = OWNER_A,
    anchorHeights = [1050n, 55000n],
    anchorToSeqs = [2, 4],
    extraTxs = [],
    moduleRefAt = () => MOD_REF_A,
    initialOperators = new Map(),
    overrideCurrentPointer = null,
    overrideCardHash = null,
    beforeRpc = null,
} = {}) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'countersign-node-test-'));
    const { header, records } = makeTrailFixtures(4);
    const trailFile = path.join(dir, 'trail.jsonl');
    writeTrail(trailFile, header, records);

    const { bytes: cardBytes, hashHex } = makeCardBytes({ ownerAccount: agentOwner });
    const cardFile = path.join(dir, 'card.json');
    fs.writeFileSync(cardFile, cardBytes);

    const { at } = commitments(header, records, new Set(anchorToSeqs));

    // Compute realistic timestamp at regHeight using temporary mock node clock.
    const dummyNode = createMockNode({ tipHeight });
    const regMs = dummyNode.timeForHeight(regHeight);

    const txs = [
        {
            height: regHeight,
            hash: txHashFor('mint'),
            sender: mintOwner,
            contractEvents: [evMint(TOKEN_ID, mintOwner)],
        },
    ];

    let prevAnchorTx = null;
    for (let i = 0; i < anchorHeights.length; i++) {
        const ah = anchorHeights[i];
        const toSeq = anchorToSeqs[i];
        const aHash = txHashFor(`anchor-${i}`);
        const aData = encodeAnchor({
            tokenId: TOKEN_ID,
            toSeq,
            commitment: at.get(toSeq),
            prevAnchorTx,
        });
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

    const agent = {
        tokenId: TOKEN_ID,
        ownerAccount: agentOwner,
        agentUri: 'https://example.com/card.json',
        metadataHashHex: overrideCardHash ?? hashHex,
        status: 'Active',
        registeredAtMs: regMs,
    };

    const node = createMockNode({
        tipHeight,
        agent,
        metadata: {
            'unitares.agent_uuid': AGENT_UUID,
            'countersign.anchor': overrideCurrentPointer ?? prevAnchorTx,
        },
        txs,
        moduleRefAt,
        initialOperators,
        beforeRpc,
    });

    return { dir, trailFile, cardFile, node, agent, anchorHashes: anchorHeights.map((_, i) => txHashFor(`anchor-${i}`)), lastAnchor: prevAnchorTx };
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

afterEach(() => {
    configureNode(null);
    delete process.env.COUNTERSIGN_NODE;
    process.exitCode = 0;
});

test('verifies normal multi-anchor history end-to-end against mock Concordium node', async () => {
    const s = buildScenario({ anchorHeights: [1050n, 3000n, 55000n], anchorToSeqs: [1, 2, 4] });
    try {
        const { ok, output } = await runVerifyQuiet({ badge: BADGE, trail: s.trailFile, card: s.cardFile, nodeClient: s.node });
        assert.equal(ok, true, output);
        assert.match(output, /VERIFIED: records 1\.\.4 match what was anchored\./);
        assert.match(output, /3 pointer updates/);
    } finally {
        fs.rmSync(s.dir, { recursive: true });
    }
});

test('catches adversarial A -> B -> A pointer hijack hidden inside a 50k-block gap', async () => {
    // Anchor 0 (seq 2) at 1050, evil pointer B (to an anchor for tampered records) at 26000,
    // then repoint back to Anchor 0 at 26005 — hidden inside a 50,000-block gap!
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
        assert.match(output, /FAIL\s+each anchor covers more records/);
        assert.match(output, /FAIL\s+records 1\.\.3 match/);
    } finally {
        fs.rmSync(s.dir, { recursive: true });
    }
});

test('rejects transfer-and-return (Owner -> Other -> Owner) hidden in 50k-block gap', async () => {
    const s = buildScenario({
        tipHeight: 60000n,
        regHeight: 1000n,
        anchorHeights: [1050n, 55000n],
        anchorToSeqs: [2, 4],
        extraTxs: [
            {
                height: 27123n,
                hash: txHashFor('xfer-out'),
                sender: OWNER_A,
                contractEvents: [evTransfer(TOKEN_ID, OWNER_A, OWNER_B)],
            },
            {
                height: 27125n,
                hash: txHashFor('xfer-back'),
                sender: OWNER_B,
                contractEvents: [evTransfer(TOKEN_ID, OWNER_B, OWNER_A)],
            },
        ],
    });
    try {
        const { ok, output } = await runVerifyQuiet({ badge: BADGE, trail: s.trailFile, card: s.cardFile, nodeClient: s.node });
        assert.equal(ok, false);
        assert.match(output, /FAIL\s+on-chain ownership and event history are intact.*transferred/);
    } finally {
        fs.rmSync(s.dir, { recursive: true });
    }
});

test('rejects Mint to a different owner than current agentOf owner', async () => {
    const s = buildScenario({
        mintOwner: OWNER_B,
        agentOwner: OWNER_A,
        anchorHeights: [1050n],
        anchorToSeqs: [2],
    });
    try {
        const { ok, output } = await runVerifyQuiet({ badge: BADGE, trail: s.trailFile, card: s.cardFile, nodeClient: s.node });
        assert.equal(ok, false);
        assert.match(output, /minted to .* not current owner/);
    } finally {
        fs.rmSync(s.dir, { recursive: true });
    }
});

test('rejects pre-existing CIS-2 operator at registration block and later UpdateOperator(Add)', async () => {
    const preOps = new Map([[acctHex(OWNER_A), { submapHex: '0700000000000000', keys: ['070000000000000000' + acctHex(OPERATOR_C)] }]]);
    const sPre = buildScenario({
        anchorHeights: [1050n],
        anchorToSeqs: [2],
        initialOperators: preOps,
    });
    try {
        const { ok, output } = await runVerifyQuiet({ badge: BADGE, trail: sPre.trailFile, card: sPre.cardFile, nodeClient: sPre.node });
        assert.equal(ok, false);
        assert.match(output, /pre-existing CIS-2 operator/);
    } finally {
        fs.rmSync(sPre.dir, { recursive: true });
    }

    // Empty submap in 05... (previously removed operator, 0 active operators) must pass!
    const emptySubmap = new Map([[acctHex(OWNER_A), { submapHex: '0600000000000000', keys: [] }]]);
    const sEmpty = buildScenario({
        anchorHeights: [1050n],
        anchorToSeqs: [2],
        initialOperators: emptySubmap,
    });
    try {
        const { ok } = await runVerifyQuiet({ badge: BADGE, trail: sEmpty.trailFile, card: sEmpty.cardFile, nodeClient: sEmpty.node });
        assert.equal(ok, true);
    } finally {
        fs.rmSync(sEmpty.dir, { recursive: true });
    }

    // Later UpdateOperator(Add) followed by UpdateOperator(Remove) in 50k gap must reject!
    const sAdd = buildScenario({
        tipHeight: 60000n,
        regHeight: 1000n,
        anchorHeights: [1050n, 55000n],
        anchorToSeqs: [2, 4],
        extraTxs: [
            {
                height: 30000n,
                hash: txHashFor('op-add'),
                sender: OWNER_A,
                contractEvents: [evUpdateOperator('Add', OWNER_A, OPERATOR_C)],
            },
            {
                height: 30005n,
                hash: txHashFor('op-rem'),
                sender: OWNER_A,
                contractEvents: [evUpdateOperator('Remove', OWNER_A, OPERATOR_C)],
            },
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

test('rejects registry contract module upgrade between registration and tip', async () => {
    const s = buildScenario({
        anchorHeights: [1050n],
        anchorToSeqs: [2],
        moduleRefAt: (h) => (h >= 30000n ? MOD_REF_B : MOD_REF_A),
    });
    try {
        const { ok, output } = await runVerifyQuiet({ badge: BADGE, trail: s.trailFile, card: s.cardFile, nodeClient: s.node });
        assert.equal(ok, false);
        assert.match(output, /sourceModule changed/);
    } finally {
        fs.rmSync(s.dir, { recursive: true });
    }
});

test('rejects when owner transaction span exceeds maxOwnerTxs cap', async () => {
    const s = buildScenario({ anchorHeights: [1050n, 2000n], anchorToSeqs: [2, 4] });
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
    } finally {
        fs.rmSync(s.dir, { recursive: true });
    }
});

test('handles cyclic prevAnchorTx hint links without infinite loop', async () => {
    const s = buildScenario({ anchorHeights: [1050n], anchorToSeqs: [2] });
    // Add two cyclic registerData anchor hints and pass one into readRegistryHistory.
    const hA = txHashFor('cyc-a');
    const hB = txHashFor('cyc-b');
    const cycNode = createMockNode({
        tipHeight: 60000n,
        agent: s.agent,
        txs: [
            { height: 1000n, hash: txHashFor('mint'), sender: OWNER_A, contractEvents: [evMint(TOKEN_ID, OWNER_A)] },
            {
                height: 1100n,
                hash: hA,
                sender: OWNER_A,
                registerData: encodeAnchor({ tokenId: TOKEN_ID, toSeq: 1, commitment: Buffer.alloc(32, 1), prevAnchorTx: hB }),
            },
            {
                height: 1110n,
                hash: hB,
                sender: OWNER_A,
                registerData: encodeAnchor({ tokenId: TOKEN_ID, toSeq: 2, commitment: Buffer.alloc(32, 2), prevAnchorTx: hA }),
            },
        ],
    });
    try {
        const hist = await readRegistryHistory(TOKEN_ID, {
            tipBlockHash: blockHashFor(60000n),
            tipBlockHeight: 60000n,
            agent: s.agent,
            hintAnchorTxHashes: [hA],
            nodeClient: cycNode,
        });
        assert.equal(hist.regHeight, 1000);
    } finally {
        fs.rmSync(s.dir, { recursive: true });
    }
});

test('createRpcPool and readRegistryHistory retry on transient 429 / UNAVAILABLE / RESOURCE_EXHAUSTED', async () => {
    const pool = createRpcPool(5, { maxRetries: 4, baseDelayMs: 5 });
    let attempts429 = 0;
    const res = await pool.run(async () => {
        attempts429 += 1;
        if (attempts429 === 1) {
            const e = new Error('Received HTTP status code 429');
            e.code = 'UNAVAILABLE';
            throw e;
        }
        if (attempts429 === 2) {
            const e = new Error('rate limited');
            e.code = 'RESOURCE_EXHAUSTED';
            throw e;
        }
        return 'ok';
    });
    assert.equal(res, 'ok');
    assert.equal(attempts429, 3);

    // Exhausting retries propagates error, and non-transient errors do not retry.
    let nonTransientCalls = 0;
    await assert.rejects(
        () =>
            pool.run(async () => {
                nonTransientCalls += 1;
                const e = new Error('Key not found.');
                e.code = 'NOT_FOUND';
                throw e;
            }),
        /Key not found/,
    );
    assert.equal(nonTransientCalls, 1);

    // Integration retry inside readRegistryHistory using fast custom pool.
    let rpcCalls = 0;
    const s = buildScenario({
        anchorHeights: [1050n],
        anchorToSeqs: [2],
        beforeRpc: () => {
            rpcCalls += 1;
            if (rpcCalls === 3 || rpcCalls === 7) {
                const e = new Error('Received HTTP status code 429');
                e.code = 'UNAVAILABLE';
                throw e;
            }
        },
    });
    try {
        const hist = await readRegistryHistory(TOKEN_ID, {
            tipBlockHash: blockHashFor(60000n),
            tipBlockHeight: 60000n,
            agent: s.agent,
            hintAnchorTxHashes: [s.lastAnchor],
            nodeClient: s.node,
            pool: createRpcPool(5, { maxRetries: 4, baseDelayMs: 5 }),
        });
        assert.equal(hist.events.length, 1);
    } finally {
        fs.rmSync(s.dir, { recursive: true });
    }
});

test('refuses non-testnet genesis and supports configureNode / COUNTERSIGN_NODE configuration', async () => {
    const mainnetGenesis = '9dd9ca4d19e9393877d2c44b70f89acbfc0883c2243e5eeaecc0d1cd0503f478';
    const badNode = createMockNode({ genesisBlock: mainnetGenesis });
    await assert.rejects(() => assertTestnet(badNode), /not Concordium testnet/);

    const s = buildScenario({ anchorHeights: [1050n], anchorToSeqs: [2] });
    const badVerifyNode = createMockNode({ genesisBlock: mainnetGenesis });
    try {
        await assert.rejects(
            () => runVerifyQuiet({ badge: BADGE, trail: s.trailFile, card: s.cardFile, nodeClient: badVerifyNode }),
            /not Concordium testnet/,
        );
    } finally {
        fs.rmSync(s.dir, { recursive: true });
    }

    assert.deepEqual(configureNode({ host: '127.0.0.1', port: 20001, tls: false }), {
        host: '127.0.0.1',
        port: 20001,
        tls: false,
    });
    configureNode(null);
    process.env.COUNTERSIGN_NODE = 'node.example.invalid:20010';
    assert.deepEqual(configureNode(null), { host: 'node.example.invalid', port: 20010, tls: true });
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
