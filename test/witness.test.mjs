import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { after, afterEach, test } from 'node:test';
import {
    AccountAddress,
    AccountTransactionType,
    CcdAmount,
    ContractAddress,
    Energy,
    Parameter,
    ReceiveName,
    ReturnValue,
    SequenceNumber,
    Transaction,
    TransactionExpiry,
    TransactionHash,
    buildBasicAccountSigner,
} from '@concordium/web-sdk';
import * as ed from '@concordium/web-sdk/shims/ed25519';
import {
    ANCHOR_KEY,
    TESTNET_GENESIS,
    WITNESS_KEY,
    buildSignedSponsoredSetMetadata,
    configureNode,
    extractWitnessState,
    loadAnchorsFromHistory,
    loadSignerFromFile,
    readAccountTransfer,
    readRegistryHistory,
    sendTransferWithMemo,
    validateAndSponsorSetMetadata,
    verifyExistingAnchors,
} from '../src/chain.mjs';
import { encodeBadge, encodeTokenId, safeHttpsRequest, safeJsonFetch } from '../src/cis8004.mjs';
import { commands } from '../src/cli.mjs';
import { REGISTRY, REGISTRY_MODULE_REF } from '../src/registry.mjs';
import { commitments, decodeAnchor, encodeAnchor, writeTrail } from '../src/trail.mjs';
import { createWitnessServer, startWitnessServer } from '../src/witness.mjs';
import { AnchorWorker } from '../src/worker.mjs';
import {
    CONCORDIUM_TESTNET_CAIP2,
    HEADER_PAYMENT_REQUIRED,
    HEADER_PAYMENT_RESPONSE,
    HEADER_PAYMENT_SIGNATURE,
    PaymentLedger,
    X402_VERSION,
    computePaymentMemo,
    createConcordiumTransferVerifier,
    createFacilitatorVerifier,
    createPaymentRequirements,
    decodeX402Header,
    encodeX402Header,
    fetchWitnessHealth,
    requestSponsoredPointer,
    requestWitnessAnchor,
} from '../src/x402.mjs';

const GENESIS_PREFIX = TESTNET_GENESIS.slice(0, 32);
const OWNER_A = '4NAnnhZUSYiyJLM9k6H7dVPn1uuPGStu2LZEety7zmp1LBYw41';
const OWNER_A_ALIAS = AccountAddress.getAlias(AccountAddress.fromBase58(OWNER_A), 1).address;
const WITNESS_1 = '3dt3UMPzRASZndjmKpSWgCP2HhmoxZrgs8FDPtZjNHZzj13hhB';
const WITNESS_2 = '3qYSik7b8w9NsgeAk91Mrpapq9T5S7EGvmsa3Ecf4449xiJ8cX';
const PAYER_3 = AccountAddress.fromBuffer(Buffer.alloc(32, 0x22)).address;

const AGENT_UUID = '907e3195-c649-49db-b753-1edc1a105f33';
const TOKEN_ID = '1315';
const BADGE = encodeBadge(TOKEN_ID);

// Test-only self-signed certificate reused from test/cis8004.test.mjs for loopback HTTPS tests.
const TEST_KEY_PEM = [
    '-----BEGIN PRIVATE KEY-----',
    'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgF56XJ48FMRYsOHWC',
    'NqDoL0loPvvngib80k1KXAEJQWOhRANCAASq8DjbtP/qJrkzCqiwKBXnr2GAhdDU',
    'HaiT68RNTyJmeg+I/lovawjxEKKpd0r3H9/kRWZAMfXMcpxAmfn4NNNM',
    '-----END PRIVATE KEY-----',
].join('\n');

const TEST_CERT_PEM = [
    '-----BEGIN CERTIFICATE-----',
    'MIIBbzCCARWgAwIBAgIUXJzlUtgO20ilH++PuBHv7koafY0wCgYIKoZIzj0EAwIw',
    'FDESMBAGA1UEAwwJMTI3LjAuMC4xMCAXDTI2MTEyMTE0MzYyMVoYDzIxMjYxMDI4',
    'MTQzNjIxWjAUMRIwEAYDVQQDDAkxMjcuMC4wLjEwWTATBgcqhkjOPQIBBggqhkjO',
    'PQMBBwNCAASq8DjbtP/qJrkzCqiwKBXnr2GAhdDUHaiT68RNTyJmeg+I/lovawjx',
    'EKKpd0r3H9/kRWZAMfXMcpxAmfn4NNNMo0MwQTAdBgNVHQ4EFgQUBdYptiuVtIxf',
    '4oc8EqRMIRb/eK8wDwYDVR0TAQH/BAUwAwEB/zAPBgNVHREECDAGhwR/AAABMAoG',
    'CCqGSM49BAMCA0gAMEUCIBOhPq01U+jAOVCq+oRdlAxuQkMymwVNS3rz8G6v9N66',
    'AiEAi6IDMAT7eEHRhRJq2ApJSuVK7BzY9SH+QdqlMoaJURg=',
    '-----END CERTIFICATE-----',
].join('\n');

const ISOLATED_LOCK_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'countersign-witness-locks-'));
const ORIG_LOCK_DIR = process.env.COUNTERSIGN_LOCK_DIR;
process.env.COUNTERSIGN_LOCK_DIR = ISOLATED_LOCK_DIR;

const tempDirs = [];
const cleanups = [];

afterEach(async () => {
    configureNode(null);
    delete process.env.COUNTERSIGN_KEYFILE;
    delete process.env.COUNTERSIGN_WITNESS_KEYFILE;
    process.exitCode = 0;
    while (cleanups.length > 0) {
        await cleanups.pop()();
    }
    while (tempDirs.length > 0) {
        fs.rmSync(tempDirs.pop(), { recursive: true, force: true });
    }
});

after(() => {
    if (ORIG_LOCK_DIR === undefined) delete process.env.COUNTERSIGN_LOCK_DIR;
    else process.env.COUNTERSIGN_LOCK_DIR = ORIG_LOCK_DIR;
    fs.rmSync(ISOLATED_LOCK_DIR, { recursive: true, force: true });
});

function makeTempDir() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'countersign-witness-test-'));
    tempDirs.push(dir);
    return dir;
}

async function makeRealSigner(address = OWNER_A) {
    const priv = crypto.randomBytes(32);
    const pub = await ed.getPublicKeyAsync(priv);
    return {
        address,
        sender: AccountAddress.fromBase58(address),
        signer: buildBasicAccountSigner(priv.toString('hex')),
        signKey: priv.toString('hex'),
        verifyKey: Buffer.from(pub).toString('hex'),
    };
}

function writeKeyfile(dir, name, signerObj, mode = 0o600) {
    const p = path.join(dir, name);
    fs.writeFileSync(p, JSON.stringify({ accountAddress: signerObj.address, signKey: signerObj.signKey }), { mode });
    fs.chmodSync(p, mode);
    return p;
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

function decodeSetMetadataParamBytes(buf) {
    const b = Buffer.from(buf);
    const tidLen = b[0];
    const tokenId = b.readBigUInt64LE(1).toString();
    let off = 1 + tidLen;
    const kLen = b.readUInt32LE(off);
    off += 4;
    const key = b.subarray(off, off + kLen).toString('utf8');
    off += kLen;
    const vLen = b.readUInt32LE(off);
    off += 4;
    const value = b.subarray(off, off + vLen).toString('utf8');
    return { tokenId, key, value };
}

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
        name: 'WitnessTestAgent',
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
        provenance: { producer: 'witness_test', seq },
    };
}

function makeTrailFixtures(count = 4, { tokenId = TOKEN_ID, uuid = AGENT_UUID } = {}) {
    const header = {
        schema: 'countersign.trail.v1',
        source: 'test',
        agent_uuid: uuid,
        token_id: tokenId,
        registry: { network: 'testnet', ...REGISTRY },
    };
    const records = [];
    for (let i = 1; i <= count; i++) {
        records.push(makeRecord(i));
    }
    return { header, records };
}

function blockHashFor(h) {
    return {
        height: BigInt(h),
        toString() {
            return `block-${h}`;
        },
    };
}

function createWitnessMockNode({
    genesisBlock = TESTNET_GENESIS,
    tipHeight = 2000n,
    regHeight = 1000n,
    owner = OWNER_A,
    status = 'Active',
    agentRegistered = true,
    uuid = AGENT_UUID,
    agentUri = 'https://agent.example/card.json',
    initialMetadata = null,
    accountVerifyKeys = new Map(), // address -> verifyKeyHex
    allFinal = true,
    tipSlotTimeMs = null,
    onInvokeContract = null,
    onSendTransaction = null,
    pollSequenceForHash = null,
} = {}) {
    const baseTimeMs = 1700000000000;
    const card = makeCardBytes({ ownerAccount: owner });
    const timeForHeight = (h) => baseTimeMs + Number(h) * 2000;
    const agent = agentRegistered
        ? {
              tokenId: TOKEN_ID,
              ownerAccount: owner,
              agentUri,
              metadataHashHex: card.hashHex,
              status,
              registeredAtMs: timeForHeight(regHeight),
          }
        : null;

    const state = {
        tipHeight,
        allFinal,
        tipSlotTimeMs,
        metadata: initialMetadata ? { ...initialMetadata } : { 'unitares.agent_uuid': uuid },
        txsByHeight: new Map(),
        registerDataByHash: new Map(),
        transferByHash: new Map(),
        statusByHash: new Map(),
        nonceChanges: [],
        submitted: [],
        submitSeq: 0,
        pollCounts: new Map(),
    };

    const addTx = (tx) => {
        const h = BigInt(tx.height);
        if (!state.txsByHeight.has(h)) state.txsByHeight.set(h, []);
        state.txsByHeight.get(h).push(tx);
        if (tx.sender) state.nonceChanges.push({ sender: tx.sender, height: h });
        if (tx.registerData) state.registerDataByHash.set(tx.hash, tx);
        if (tx.transfer) state.transferByHash.set(tx.hash, tx);
        if (h > state.tipHeight) state.tipHeight = h;
    };

    if (agentRegistered) {
        addTx({ height: regHeight, hash: txHashFor('mint'), sender: owner, contractEvents: [evMint(TOKEN_ID, owner)] });
    }

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
        timeForHeight,
        setTipSlotTimeMs(ms) {
            state.tipSlotTimeMs = ms;
        },
        addRegisterData({ sender = owner, data, txHash, height }) {
            const h = BigInt(height ?? state.tipHeight + 1n);
            const hash = txHash ?? txHashFor(`rd-${++state.submitSeq}`);
            const buf = Buffer.from(data);
            addTx({ height: h, hash, sender, registerData: buf });
            return { txHash: hash, sender, height: h };
        },
        addSetMetadata({ sender = owner, key = ANCHOR_KEY, value, txHash, height }) {
            const h = BigInt(height ?? state.tipHeight + 1n);
            const hash = txHash ?? txHashFor(`meta-${++state.submitSeq}`);
            state.metadata[key] = value;
            addTx({ height: h, hash, sender, contractEvents: [evMetadataSet(TOKEN_ID, key, value)] });
            return { hash, height: h };
        },
        addTransfer({ sender = owner, to, amountMicroCcd, memoHex = null, txHash, height, rejectReason = null }) {
            const h = BigInt(height ?? state.tipHeight + 1n);
            const hash = txHash ?? txHashFor(`xfer-${++state.submitSeq}`);
            addTx({
                height: h,
                hash,
                sender,
                rejectReason,
                transfer: { to, amountMicroCcd: BigInt(amountMicroCcd), memoHex },
            });
            return { txHash: hash, height: h };
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
            const ms = h === state.tipHeight && state.tipSlotTimeMs !== null ? state.tipSlotTimeMs : timeForHeight(h);
            return { blockHeight: h, blockSlotTime: new Date(ms) };
        },
        async getAccountInfo(acct, bh) {
            const h = heightFromBlockHash(bh);
            let count = 1n;
            for (const nc of state.nonceChanges) {
                if (nc.height <= h && nc.sender === acct.address) count += 1n;
            }
            const verifyKey = accountVerifyKeys.get(acct.address);
            const base = {
                accountAddress: acct,
                accountNonce: { value: count },
            };
            if (verifyKey) {
                base.accountThreshold = 1;
                base.accountCredentials = {
                    0: {
                        v: 0,
                        value: {
                            contents: {
                                credentialPublicKeys: {
                                    threshold: 1,
                                    keys: { 0: { schemeId: 'Ed25519', verifyKey } },
                                },
                            },
                        },
                    },
                };
            }
            return base;
        },
        async getNextAccountNonce(acct) {
            let count = 1n;
            for (const nc of state.nonceChanges) {
                if (nc.sender === acct.address) count += 1n;
            }
            return { nonce: { value: count }, allFinal: state.allFinal };
        },
        async getInstanceInfo() {
            return { sourceModule: { moduleRef: REGISTRY_MODULE_REF } };
        },
        async instanceStateLookup() {
            const err = new Error('Key not found');
            err.code = 'NOT_FOUND';
            throw err;
        },
        async *getBlockTransactionEvents(bh) {
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
                } else if (tx.transfer) {
                    yield {
                        type: 'accountTransaction',
                        transactionType: tx.transfer.memoHex !== null ? 'transferWithMemo' : 'transfer',
                        hash: { toString: () => tx.hash },
                        sender: { address: tx.sender },
                    };
                } else {
                    yield {
                        type: 'accountTransaction',
                        transactionType: 'update',
                        hash: { toString: () => tx.hash },
                        sender: { address: tx.sender },
                        rejectReason: tx.rejectReason ?? undefined,
                        events: [
                            {
                                tag: 'Updated',
                                address: { index: REGISTRY.index, subindex: REGISTRY.subindex },
                                events: tx.contractEvents ?? [],
                            },
                        ],
                    };
                }
            }
        },
        async getBlockItemStatus(hashObj) {
            const h = hashObj.toString();
            if (pollSequenceForHash) {
                const n = state.pollCounts.get(h) ?? 0;
                state.pollCounts.set(h, n + 1);
                const custom = pollSequenceForHash(h, n);
                if (custom !== undefined) return custom;
            }
            if (state.statusByHash.has(h)) return state.statusByHash.get(h);
            const rd = state.registerDataByHash.get(h);
            if (rd) {
                return {
                    status: 'finalized',
                    outcome: {
                        blockHash: blockHashFor(rd.height),
                        summary: {
                            type: 'accountTransaction',
                            transactionType: 'registerData',
                            sender: { address: rd.sender },
                            dataRegistered: { data: rd.registerData.toString('hex') },
                        },
                    },
                };
            }
            const xfer = state.transferByHash.get(h);
            if (xfer) {
                if (xfer.rejectReason) {
                    return {
                        status: 'finalized',
                        outcome: {
                            blockHash: blockHashFor(xfer.height),
                            summary: {
                                type: 'accountTransaction',
                                transactionType: 'failed',
                                sender: { address: xfer.sender },
                                rejectReason: xfer.rejectReason,
                            },
                        },
                    };
                }
                return {
                    status: 'finalized',
                    outcome: {
                        blockHash: blockHashFor(xfer.height),
                        summary: {
                            type: 'accountTransaction',
                            transactionType: xfer.transfer.memoHex !== null ? 'transferWithMemo' : 'transfer',
                            sender: { address: xfer.sender },
                            transfer: {
                                tag: 'Transferred',
                                amount: { microCcdAmount: xfer.transfer.amountMicroCcd },
                                to: { address: xfer.transfer.to },
                            },
                            ...(xfer.transfer.memoHex !== null
                                ? { memo: { tag: 'TransferMemo', memo: xfer.transfer.memoHex } }
                                : {}),
                        },
                    },
                };
            }
            for (const [bh, list] of state.txsByHeight.entries()) {
                const found = list.find((t) => t.hash === h);
                if (found) {
                    return {
                        status: 'finalized',
                        outcome: {
                            blockHash: blockHashFor(bh),
                            summary: found.rejectReason
                                ? {
                                      type: 'accountTransaction',
                                      transactionType: 'failed',
                                      sender: { address: found.sender },
                                      rejectReason: found.rejectReason,
                                  }
                                : {
                                      type: 'accountTransaction',
                                      transactionType: 'update',
                                      sender: { address: found.sender },
                                      events: found.contractEvents ?? [],
                                  },
                        },
                    };
                }
            }
            return null;
        },
        async invokeContract(ctx, bh) {
            if (onInvokeContract) {
                const custom = await onInvokeContract(ctx, bh);
                if (custom !== undefined) return custom;
            }
            const method = ctx.method.value ?? String(ctx.method);
            if (method === 'CIS-8004.agentOf') {
                const p = Buffer.from(ctx.parameter.buffer);
                const reqTid = p.length >= 9 ? p.readBigUInt64LE(1).toString() : null;
                const matched = agent && reqTid === agent.tokenId ? agent : null;
                return { tag: 'success', usedEnergy: { value: 1000n }, returnValue: ReturnValue.fromBuffer(encodeAgentOfReturn(matched)) };
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
                return { tag: 'success', usedEnergy: { value: 1800n }, returnValue: ReturnValue.empty() };
            }
            return { tag: 'failure', usedEnergy: { value: 500n }, reason: { tag: 'InvalidReceive' } };
        },
        async sendTransaction(finalized) {
            state.submitted.push(finalized);
            if (onSendTransaction) {
                const custom = await onSendTransaction(finalized);
                if (custom !== undefined) return custom;
            }
            const hash = Buffer.from(Transaction.getAccountTransactionHash(finalized)).toString('hex');
            const sender = finalized.header.sender.address;
            const pType = finalized.payload.type;
            if (pType === AccountTransactionType.RegisterData) {
                node.addRegisterData({ sender, data: finalized.payload.data.data, txHash: hash });
            } else if (pType === AccountTransactionType.Transfer || pType === AccountTransactionType.TransferWithMemo) {
                const memoHex = finalized.payload.memo ? Buffer.from(finalized.payload.memo.data).toString('hex') : null;
                node.addTransfer({
                    sender,
                    to: finalized.payload.toAddress.address,
                    amountMicroCcd: finalized.payload.amount.microCcdAmount,
                    memoHex,
                    txHash: hash,
                });
            } else if (pType === AccountTransactionType.Update && finalized.payload.receiveName?.value === 'CIS-8004.setMetadata') {
                const { key, value } = decodeSetMetadataParamBytes(Parameter.toBuffer(finalized.payload.message));
                node.addSetMetadata({ sender, key, value, txHash: hash });
            }
            return TransactionHash.fromHexString(hash);
        },
    };
    return node;
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

async function runQuiet(fn) {
    const origLog = console.log;
    const lines = [];
    console.log = (...a) => lines.push(a.join(' '));
    try {
        const result = await fn();
        return { result, output: lines.join('\n') };
    } finally {
        console.log = origLog;
    }
}

test('x402 v2 codecs, deterministic memo, payment requirements, and SSRF-safe HTTPS fetch', async () => {
    const obj = { x402Version: X402_VERSION, ok: true };
    const enc = encodeX402Header(obj);
    assert.deepEqual(decodeX402Header(enc), obj);
    assert.throws(() => encodeX402Header(['not', 'obj']), TypeError);
    assert.throws(() => decodeX402Header('not!base64!'), /valid base64/);
    assert.throws(() => decodeX402Header(Buffer.from('[]').toString('base64')), /JSON object/);
    assert.throws(() => decodeX402Header(Buffer.from([0xff, 0xfe]).toString('base64')), /valid UTF-8/);

    const c1 = 'a'.repeat(64);
    const c2 = 'b'.repeat(64);
    const mGenesis = computePaymentMemo({ tokenId: TOKEN_ID, toSeq: 4, commitment: c1, prevAnchorTx: null });
    const mGenesis2 = computePaymentMemo({ tokenId: TOKEN_ID, toSeq: 4, commitment: c1, prevAnchorTx: null });
    assert.equal(mGenesis, mGenesis2);
    assert.match(mGenesis, /^[0-9a-f]{64}$/);
    assert.notEqual(mGenesis, computePaymentMemo({ tokenId: TOKEN_ID, toSeq: 5, commitment: c1, prevAnchorTx: null }));
    assert.notEqual(mGenesis, computePaymentMemo({ tokenId: TOKEN_ID, toSeq: 4, commitment: c2, prevAnchorTx: null }));
    assert.notEqual(mGenesis, computePaymentMemo({ tokenId: TOKEN_ID, toSeq: 4, commitment: c1, prevAnchorTx: c2 }));

    const pr = createPaymentRequirements({
        payTo: WITNESS_1,
        amountMicroCcd: '1000000',
        resource: 'https://witness.example/v1/anchor',
        tokenId: TOKEN_ID,
        toSeq: 4,
        commitment: c1,
        prevAnchorTx: null,
        witnessAccount: WITNESS_1,
        sponsorPointer: true,
    });
    assert.equal(pr.x402Version, 2);
    assert.equal(pr.accepts[0].network, CONCORDIUM_TESTNET_CAIP2);
    assert.equal(pr.accepts[0].extra.memoHex, mGenesis);

    // SSRF guards on safeHttpsRequest / safeJsonFetch: http:// blocked when allowPrivate: false, allowed when true
    await assert.rejects(() => safeJsonFetch('http://example.com/health'), /non-HTTPS/);
    await assert.rejects(() => safeHttpsRequest('https://127.0.0.1:8443/health'), /private or non-public IP/);

    // Loopback HTTPS with static test cert works with allowPrivate: true
    const tlsSrv = https.createServer({ key: TEST_KEY_PEM, cert: TEST_CERT_PEM }, (req, res) => {
        if (req.url === '/redir') {
            res.writeHead(302, { location: 'https://127.0.0.1/other' });
            res.end();
            return;
        }
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ hello: 'x402' }));
    });
    await new Promise((r) => tlsSrv.listen(0, '127.0.0.1', r));
    cleanups.push(async () => {
        tlsSrv.closeAllConnections?.();
        await new Promise((r) => tlsSrv.close(r));
    });
    const { port } = tlsSrv.address();
    const res = await safeJsonFetch(`https://127.0.0.1:${port}/ok`, { allowPrivate: true, ca: Buffer.from(TEST_CERT_PEM) });
    assert.deepEqual(res.data, { hello: 'x402' });
    await assert.rejects(
        () => safeJsonFetch(`https://127.0.0.1:${port}/redir`, { allowPrivate: true, ca: Buffer.from(TEST_CERT_PEM) }),
        /redirect/,
    );
});

test('PaymentLedger persists 0600 atomically, enforces state machine, and never releases broadcasted/committed entries', () => {
    const dir = makeTempDir();
    const ledgerPath = path.join(dir, 'ledger.json');
    const ledger = new PaymentLedger(ledgerPath);
    const binding = { tokenId: TOKEN_ID, toSeq: 4, commitment: 'a'.repeat(64), prevAnchorTx: null };

    assert.throws(() => ledger.claim('', binding), /non-empty/);
    assert.equal(ledger.claim('ccd:p1', binding).action, 'proceed');
    assert.equal(fs.statSync(ledgerPath).mode & 0o777, 0o600);

    // Pre-broadcast release works only while status === 'claimed'
    assert.equal(ledger.releasePreBroadcast('ccd:p1'), true);
    assert.equal(ledger.get('ccd:p1'), null);

    // Once broadcasted, releasePreBroadcast MUST fail closed even across reload
    ledger.claim('ccd:p2', binding);
    const txHash = txHashFor('broadcasted-tx');
    ledger.markBroadcast('ccd:p2', { txHash, expiryEpochSeconds: 1900000000 });
    assert.equal(ledger.releasePreBroadcast('ccd:p2'), false);
    assert.equal(ledger.get('ccd:p2').status, 'broadcasted');

    const reloaded = new PaymentLedger(ledgerPath);
    assert.equal(reloaded.get('ccd:p2').status, 'broadcasted');
    assert.equal(reloaded.releasePreBroadcast('ccd:p2'), false);
    assert.throws(() => reloaded.claim('ccd:p2', binding), (e) => e.statusCode === 409);

    // Commit enables identical idempotent retry, but rejects mismatched binding with 409 and never releases
    reloaded.commit('ccd:p2', {
        txHash,
        witnessAccount: WITNESS_1,
        blockTime: '2026-11-21T00:00:00.000Z',
        blockHeight: 2001,
        sponsorAvailable: true,
    });
    assert.equal(reloaded.releasePreBroadcast('ccd:p2'), false);
    const cached = reloaded.claim('ccd:p2', binding);
    assert.equal(cached.action, 'return_cached');
    assert.equal(cached.entry.result.txHash, txHash);
    assert.throws(
        () => reloaded.claim('ccd:p2', { ...binding, toSeq: 5 }),
        (e) => e.statusCode === 409,
    );

    // Sponsor pointer ledger transitions & protections
    const metaHash = txHashFor('meta-1');
    assert.equal(reloaded.claimSponsor(TOKEN_ID, txHash, { requestHash: 'req1' }).action, 'proceed');
    assert.throws(() => reloaded.claimSponsor(TOKEN_ID, txHash, { requestHash: 'req1' }), (e) => e.statusCode === 409);
    reloaded.markSponsorBroadcast(TOKEN_ID, txHash, { metadataTxHash: metaHash, expiryEpochSeconds: 1900000100 });
    assert.equal(reloaded.releasePreBroadcastSponsor(TOKEN_ID, txHash), false);
    reloaded.commitSponsor(TOKEN_ID, txHash, { metadataTxHash: metaHash });
    assert.equal(reloaded.claimSponsor(TOKEN_ID, txHash, { requestHash: 'req1' }).action, 'return_cached');
    assert.throws(
        () => reloaded.claimSponsor(TOKEN_ID, txHash, { requestHash: 'req2' }),
        (e) => e.statusCode === 409,
    );
});

test('ConcordiumTransferVerifier and SSRF-hardened FacilitatorVerifier validate payments strictly', async () => {
    const node = createWitnessMockNode();
    const expectedMemo = computePaymentMemo({ tokenId: TOKEN_ID, toSeq: 4, commitment: 'c'.repeat(64), prevAnchorTx: null });

    const goodTx = node.addTransfer({
        sender: PAYER_3,
        to: WITNESS_1,
        amountMicroCcd: 1000000n,
        memoHex: expectedMemo,
    }).txHash;
    const wrongMemoTx = node.addTransfer({
        sender: PAYER_3,
        to: WITNESS_1,
        amountMicroCcd: 1000000n,
        memoHex: 'd'.repeat(64),
    }).txHash;
    const underpaidTx = node.addTransfer({
        sender: PAYER_3,
        to: WITNESS_1,
        amountMicroCcd: 999999n,
        memoHex: expectedMemo,
    }).txHash;
    const wrongToTx = node.addTransfer({
        sender: PAYER_3,
        to: WITNESS_2,
        amountMicroCcd: 1000000n,
        memoHex: expectedMemo,
    }).txHash;
    const plainNoMemoTx = node.addTransfer({
        sender: PAYER_3,
        to: WITNESS_1,
        amountMicroCcd: 1000000n,
        memoHex: null,
    }).txHash;

    const readOk = await readAccountTransfer(goodTx, node);
    assert.equal(readOk.amountMicroCcd, 1000000n);
    assert.equal(readOk.memoHex, expectedMemo);

    const verifier = createConcordiumTransferVerifier({ nodeClient: node, payTo: WITNESS_1, minAmountMicroCcd: '1000000' });
    const reqs = createPaymentRequirements({
        payTo: WITNESS_1,
        amountMicroCcd: '1000000',
        resource: 'https://witness.example/v1/anchor',
        tokenId: TOKEN_ID,
        toSeq: 4,
        commitment: 'c'.repeat(64),
        prevAnchorTx: null,
    }).accepts[0];

    const hdrFor = (txHash) => encodeX402Header({ x402Version: 2, accepted: reqs, payload: { txHash } });
    const ok = await verifier.verify({ header: hdrFor(goodTx), requirements: reqs, expectedMemoHex: expectedMemo });
    assert.equal(ok.paymentId, `ccd:${goodTx}`);
    assert.equal(ok.payer, PAYER_3);

    await assert.rejects(() => verifier.verify({ header: hdrFor(wrongMemoTx), requirements: reqs, expectedMemoHex: expectedMemo }), /memo/);
    await assert.rejects(() => verifier.verify({ header: hdrFor(underpaidTx), requirements: reqs, expectedMemoHex: expectedMemo }), /below required/);
    await assert.rejects(() => verifier.verify({ header: hdrFor(wrongToTx), requirements: reqs, expectedMemoHex: expectedMemo }), /expected/);
    await assert.rejects(() => verifier.verify({ header: hdrFor(plainNoMemoTx), requirements: reqs, expectedMemoHex: expectedMemo }), /missing 32-byte/);

    // FacilitatorVerifier blocks private IP when allowPrivate: false and verifies/settles over HTTPS when allowPrivate: true
    const ssrfFac = createFacilitatorVerifier({ facilitatorUrl: 'https://127.0.0.1:9999', allowPrivate: false });
    await assert.rejects(() => ssrfFac.verify({ header: hdrFor(goodTx), requirements: reqs, expectedMemoHex: expectedMemo }), /private or non-public IP/);

    let mode = 'ok';
    const facSrv = https.createServer({ key: TEST_KEY_PEM, cert: TEST_CERT_PEM }, (req, res) => {
        if (req.url === '/verify') {
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify(mode === 'bad_verify' ? { isValid: false, invalidReason: 'bad sig' } : { isValid: true, payer: PAYER_3 }));
        } else if (req.url === '/settle') {
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify(mode === 'bad_settle' ? { success: false, errorReason: 'reverted' } : { success: true, transaction: 'fac-tx-1', network: CONCORDIUM_TESTNET_CAIP2 }));
        }
    });
    await new Promise((r) => facSrv.listen(0, '127.0.0.1', r));
    cleanups.push(async () => {
        facSrv.closeAllConnections?.();
        await new Promise((r) => facSrv.close(r));
    });
    const fac = createFacilitatorVerifier({
        facilitatorUrl: `https://127.0.0.1:${facSrv.address().port}`,
        allowPrivate: true,
        ca: Buffer.from(TEST_CERT_PEM),
    });
    const facRes = await fac.verify({ header: hdrFor(goodTx), requirements: reqs, expectedMemoHex: expectedMemo });
    assert.equal(facRes.paymentId, `facilitator:${CONCORDIUM_TESTNET_CAIP2}:fac-tx-1`);
    mode = 'bad_verify';
    await assert.rejects(() => fac.verify({ header: hdrFor(goodTx), requirements: reqs, expectedMemoHex: expectedMemo }), /bad sig/);
    mode = 'bad_settle';
    await assert.rejects(() => fac.verify({ header: hdrFor(goodTx), requirements: reqs, expectedMemoHex: expectedMemo }), /reverted/);
});

test('loadSignerFromFile enforces 0600 permissions and never falls back to owner keyfile', async () => {
    const dir = makeTempDir();
    const owner = await makeRealSigner(OWNER_A);
    const witness = await makeRealSigner(WITNESS_1);
    const ownerFile = writeKeyfile(dir, 'owner.json', owner, 0o600);
    const witnessFile = writeKeyfile(dir, 'witness.json', witness, 0o600);
    const looseFile = writeKeyfile(dir, 'loose.json', witness, 0o644);

    process.env.COUNTERSIGN_KEYFILE = ownerFile;
    assert.throws(() => loadSignerFromFile(undefined, { envVar: 'COUNTERSIGN_WITNESS_KEYFILE' }), /COUNTERSIGN_WITNESS_KEYFILE/);
    assert.throws(() => loadSignerFromFile(looseFile), /chmod 600/);

    process.env.COUNTERSIGN_WITNESS_KEYFILE = witnessFile;
    const loaded = loadSignerFromFile(undefined, { envVar: 'COUNTERSIGN_WITNESS_KEYFILE' });
    assert.equal(loaded.address, WITNESS_1);
});

test('Witness HTTP service enforces testnet startup, body/header limits, pre-payment 4xx checks, x402 flow, and mutex serialization', async () => {
    const dir = makeTempDir();
    const witnessSigner = await makeRealSigner(WITNESS_1);
    const ownerSigner = await makeRealSigner(OWNER_A);
    const witnessKeyfile = writeKeyfile(dir, 'witness.json', witnessSigner, 0o600);
    const ledgerPath = path.join(dir, 'witness-ledger.json');

    // Non-testnet node must fail BEFORE listening
    const mainnetNode = createWitnessMockNode({ genesisBlock: '0'.repeat(64) });
    await assert.rejects(
        () => createWitnessServer({ signer: witnessSigner, ledgerPath, nodeClient: mainnetNode, port: 0 }),
        /not Concordium testnet/,
    );

    const node = createWitnessMockNode({
        owner: OWNER_A,
        accountVerifyKeys: new Map([[OWNER_A, ownerSigner.verifyKey]]),
    });
    // Authorize WITNESS_1 on chain
    node.addSetMetadata({ sender: OWNER_A, key: WITNESS_KEY, value: WITNESS_1 });

    let cardBytesOverride = node.card.bytes;
    const srv = await startWitnessServer({
        host: '127.0.0.1',
        port: 0,
        priceMicroCcd: '1000000',
        witnessKeyfile,
        ledgerPath,
        nodeClient: node,
        fetchCard: async () => cardBytesOverride,
        log: () => {},
    });
    cleanups.push(() => srv.close());

    // /health check
    const health = await fetchWitnessHealth({ witnessUrl: srv.url, allowPrivate: true });
    assert.equal(health.witnessAccount, WITNESS_1);
    assert.equal(health.priceMicroCcd, '1000000');
    assert.equal(health.sponsorPointer, true);

    // 415 non-JSON
    const res415 = await fetch(`${srv.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'text/plain' },
        body: '{}',
    });
    assert.equal(res415.status, 415);

    // 413 oversized payload (both Content-Length and chunked stream without Content-Length)
    const bigBody = JSON.stringify({ tokenId: TOKEN_ID, toSeq: 1, commitment: 'a'.repeat(70000), prevAnchorTx: null });
    const res413 = await fetch(`${srv.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: bigBody,
    });
    assert.equal(res413.status, 413);

    const chunked413Status = await new Promise((resolve, reject) => {
        const u = new URL(`${srv.url}/v1/anchor`);
        const req = http.request(
            {
                hostname: u.hostname,
                port: u.port,
                path: u.pathname,
                method: 'POST',
                headers: { 'content-type': 'application/json', 'transfer-encoding': 'chunked' },
            },
            (res) => {
                res.resume();
                resolve(res.statusCode);
            },
        );
        req.on('error', (err) => {
            if (err.code === 'ECONNRESET' || err.code === 'EPIPE') return;
            reject(err);
        });
        req.write('{"tokenId":"1315","commitment":"' + 'a'.repeat(40000));
        req.write('b'.repeat(40000) + '"}');
        req.end();
    });
    assert.equal(chunked413Status, 413);

    const { header, records } = makeTrailFixtures(4);
    const { last: commit4 } = commitments(header, records);
    const c4Hex = commit4.toString('hex');

    // 402 Payment Required with exact memo binding
    const res402 = await fetch(`${srv.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 4, commitment: c4Hex, prevAnchorTx: null }),
    });
    assert.equal(res402.status, 402);
    const prHdr = decodeX402Header(res402.headers.get(HEADER_PAYMENT_REQUIRED));
    assert.equal(prHdr.x402Version, 2);
    assert.equal(prHdr.accepts[0].extra.memoHex, computePaymentMemo({ tokenId: TOKEN_ID, toSeq: 4, commitment: c4Hex, prevAnchorTx: null }));

    // Pre-payment 403/404/409 checks (even BEFORE payment signature is checked)
    // Bad Agent Card -> 403
    cardBytesOverride = Buffer.from('{"bad":true}');
    const resBadCard = await fetch(`${srv.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 4, commitment: c4Hex, prevAnchorTx: null }),
    });
    assert.equal(resBadCard.status, 403);
    cardBytesOverride = node.card.bytes;

    // Unregistered token -> 404
    const res404 = await fetch(`${srv.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ tokenId: '999999', toSeq: 4, commitment: c4Hex, prevAnchorTx: null }),
    });
    assert.equal(res404.status, 404);

    // Wrong prevAnchorTx -> 409
    const res409Prev = await fetch(`${srv.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 4, commitment: c4Hex, prevAnchorTx: 'f'.repeat(64) }),
    });
    assert.equal(res409Prev.status, 409);

    // Self-witnessing refusal -> 403
    const selfSrv = await startWitnessServer({
        host: '127.0.0.1',
        port: 0,
        signer: ownerSigner,
        ledgerPath: path.join(dir, 'self-ledger.json'),
        nodeClient: node,
        fetchCard: async () => node.card.bytes,
        log: () => {},
    });
    cleanups.push(() => selfSrv.close());
    const resSelf = await fetch(`${selfSrv.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 4, commitment: c4Hex, prevAnchorTx: null }),
    });
    assert.equal(resSelf.status, 403);

    // End-to-end witnessed anchor + Protocol 10 sponsored CIS-8004.setMetadata + verify!
    const payer = await makeRealSigner(PAYER_3);
    const anchored = await requestWitnessAnchor({
        witnessUrl: srv.url,
        tokenId: TOKEN_ID,
        toSeq: 4,
        commitment: c4Hex,
        prevAnchorTx: null,
        allowPrivate: true,
        payFn: async (reqs) => {
            const xfer = await sendTransferWithMemo({
                to: reqs.payTo,
                microCcd: BigInt(reqs.amount),
                memoBytes: Buffer.from(reqs.extra.memoHex, 'hex'),
                who: payer,
                nodeClient: node,
            });
            return { x402Version: 2, accepted: reqs, payload: { txHash: xfer.hash } };
        },
    });
    assert.equal(anchored.witnessAccount, WITNESS_1);
    assert.equal(anchored.paymentResponse.success, true);

    // Idempotent retry with same PAYMENT-SIGNATURE returns cached 200 without submitting duplicate registerData!
    const submittedBeforeRetry = node.submitted.length;
    const paidSigHdr = encodeX402Header({
        x402Version: 2,
        accepted: prHdr.accepts[0],
        payload: { txHash: anchored.paymentResponse ? node.submitted.find((t) => t.payload.type === AccountTransactionType.TransferWithMemo && t.payload.toAddress.address === WITNESS_1) ? Buffer.from(Transaction.getAccountTransactionHash(node.submitted.find((t) => t.payload.type === AccountTransactionType.TransferWithMemo))).toString('hex') : '' : '' },
    });
    const cachedRetry = await requestWitnessAnchor({
        witnessUrl: srv.url,
        tokenId: TOKEN_ID,
        toSeq: 4,
        commitment: c4Hex,
        prevAnchorTx: null,
        paymentSignature: paidSigHdr,
        allowPrivate: true,
    });
    assert.equal(cachedRetry.txHash, anchored.txHash);
    assert.equal(node.submitted.length, submittedBeforeRetry);

    // Build and sponsor Protocol 10 setMetadata
    const built = await buildSignedSponsoredSetMetadata({
        tokenId: TOKEN_ID,
        key: ANCHOR_KEY,
        valueUtf8: anchored.txHash,
        who: ownerSigner,
        sponsorAddress: WITNESS_1,
        nodeClient: node,
    });
    const sponsored = await requestSponsoredPointer({
        witnessUrl: srv.url,
        tokenId: TOKEN_ID,
        anchorTxHash: anchored.txHash,
        transactionJson: built.transactionJson,
        allowPrivate: true,
    });
    assert.equal(sponsored.anchorTxHash, anchored.txHash);
    assert.equal(sponsored.witnessAccount, WITNESS_1);

    // Retry same sponsor-pointer returns cached 200 without re-submitting
    const countBeforeSponsorRetry = node.submitted.length;
    const sponsorRetry = await requestSponsoredPointer({
        witnessUrl: srv.url,
        tokenId: TOKEN_ID,
        anchorTxHash: anchored.txHash,
        transactionJson: built.transactionJson,
        allowPrivate: true,
    });
    assert.equal(sponsorRetry.metadataTxHash, sponsored.metadataTxHash);
    assert.equal(node.submitted.length, countBeforeSponsorRetry);

    // Verify end-to-end with cli.mjs verify --require-witness --witness WITNESS_1!
    const trailFile = path.join(dir, 'trail.jsonl');
    const cardFile = path.join(dir, 'card.json');
    writeTrail(trailFile, header, records);
    fs.writeFileSync(cardFile, node.card.bytes);
    const vRes = await runVerifyQuiet({
        badge: BADGE,
        trail: trailFile,
        card: cardFile,
        requireWitness: true,
        witness: WITNESS_1,
        nodeClient: node,
    });
    assert.equal(vRes.ok, true, vRes.output);
    assert.match(vRes.output, /authorized signer \(owner or active witness\)/);
    assert.match(vRes.output, /VERIFIED: records 1\.\.4 match what was anchored\./);

    // Concurrent per-token mutex test with IDENTICAL payment: only 1 registerData tx is broadcast while 2nd returns cached 200!
    const recs5 = [...records, makeRecord(5)];
    const { last: commit5 } = commitments(header, recs5);
    const c5Hex = commit5.toString('hex');
    const memo5 = computePaymentMemo({ tokenId: TOKEN_ID, toSeq: 5, commitment: c5Hex, prevAnchorTx: anchored.txHash });
    const pay5 = await sendTransferWithMemo({ to: WITNESS_1, microCcd: 1000000n, memoBytes: Buffer.from(memo5, 'hex'), who: payer, nodeClient: node });
    const sig5 = encodeX402Header({ x402Version: 2, payload: { txHash: pay5.hash } });
    const body5 = JSON.stringify({ tokenId: TOKEN_ID, toSeq: 5, commitment: c5Hex, prevAnchorTx: anchored.txHash });
    const beforeMutexSubmits = node.submitted.length;
    const [rA, rB] = await Promise.all([
        fetch(`${srv.url}/v1/anchor`, {
            method: 'POST',
            headers: { 'content-type': 'application/json', [HEADER_PAYMENT_SIGNATURE]: sig5 },
            body: body5,
        }),
        fetch(`${srv.url}/v1/anchor`, {
            method: 'POST',
            headers: { 'content-type': 'application/json', [HEADER_PAYMENT_SIGNATURE]: sig5 },
            body: body5,
        }),
    ]);
    assert.equal(rA.status, 200);
    assert.equal(rB.status, 200);
    assert.equal(node.submitted.length - beforeMutexSubmits, 1, 'mutex must serialize identical concurrent payments into 1 registerData');

    // Replay of pay5 for a DIFFERENT commitment/seq is rejected with 402 by memo verification, and 409 by PaymentLedger if verifier didn't bind memo
    const resReplayMismatch = await fetch(`${srv.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', [HEADER_PAYMENT_SIGNATURE]: sig5 },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 6, commitment: c5Hex, prevAnchorTx: anchored.txHash }),
    });
    assert.equal(resReplayMismatch.status, 402);

    const ledgerConflictSrv = await startWitnessServer({
        host: '127.0.0.1',
        port: 0,
        signer: witnessSigner,
        ledger: srv.ledger,
        nodeClient: node,
        verifier: { verify: async () => ({ paymentId: `ccd:${pay5.hash}`, payer: payer.address }) },
        fetchCard: async () => node.card.bytes,
        log: () => {},
    });
    cleanups.push(() => ledgerConflictSrv.close());
    const res409Binding = await fetch(`${ledgerConflictSrv.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', [HEADER_PAYMENT_SIGNATURE]: sig5 },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 6, commitment: c5Hex, prevAnchorTx: anchored.txHash }),
    });
    assert.equal(res409Binding.status, 409);

    // Wrong memo payment rejected with 402
    const wrongMemoPay = await sendTransferWithMemo({ to: WITNESS_1, microCcd: 1000000n, memoBytes: Buffer.alloc(32, 0x99), who: payer, nodeClient: node });
    const resWrongMemo = await fetch(`${srv.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', [HEADER_PAYMENT_SIGNATURE]: encodeX402Header({ x402Version: 2, payload: { txHash: wrongMemoPay.hash } }) },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 6, commitment: 'e'.repeat(64), prevAnchorTx: anchored.txHash }),
    });
    assert.equal(resWrongMemo.status, 402);

    // Non-monotonic toSeq (toSeq <= prev.toSeq = 4) -> 409
    const resNonMono = await fetch(`${srv.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 4, commitment: c4Hex, prevAnchorTx: anchored.txHash }),
    });
    assert.equal(resNonMono.status, 409);

    // Revoked token -> 403
    node.agent.status = 'Revoked';
    const resRevoked = await fetch(`${srv.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 6, commitment: c5Hex, prevAnchorTx: anchored.txHash }),
    });
    assert.equal(resRevoked.status, 403);
    node.agent.status = 'Active';

    // Disabled sponsorPointer returns 403 on /v1/sponsor-pointer
    const noSponsorSrv = await startWitnessServer({
        host: '127.0.0.1',
        port: 0,
        signer: witnessSigner,
        sponsorPointer: false,
        ledgerPath: path.join(dir, 'nosponsor-ledger.json'),
        nodeClient: node,
        fetchCard: async () => node.card.bytes,
        log: () => {},
    });
    cleanups.push(() => noSponsorSrv.close());
    const resNoSponsor = await fetch(`${noSponsorSrv.url}/v1/sponsor-pointer`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ tokenId: TOKEN_ID, anchorTxHash: anchored.txHash, transactionJson: '{}' }),
    });
    assert.equal(resNoSponsor.status, 403);
});

test('validateAndSponsorSetMetadata rejects every tampered, unauthorized, oversized, or expired Protocol 10 payload', async () => {
    const ownerSigner = await makeRealSigner(OWNER_A);
    const witnessSigner = await makeRealSigner(WITNESS_1);
    const attackerSigner = await makeRealSigner(WITNESS_2);
    const node = createWitnessMockNode({
        owner: OWNER_A,
        accountVerifyKeys: new Map([
            [OWNER_A, ownerSigner.verifyKey],
            [WITNESS_1, witnessSigner.verifyKey],
        ]),
    });
    const anchorHash = txHashFor('anchor-for-sponsor');
    const tipEpochSec = Math.floor(node.timeForHeight(2000n) / 1000);

    const makeTxJson = async ({
        who = ownerSigner,
        sponsorAddress = WITNESS_1,
        contractIndex = REGISTRY.index,
        contractSubindex = REGISTRY.subindex,
        receiveName = 'CIS-8004.setMetadata',
        amountMicroCcd = 0n,
        tokenId = TOKEN_ID,
        key = ANCHOR_KEY,
        value = anchorHash,
        energy = 3000,
        expirySec = tipEpochSec + 300,
        numSigs = 1,
        mutateAfterSign = null,
    } = {}) => {
        const param = encodeTokenId(tokenId);
        const kBuf = Buffer.from(key, 'utf8');
        const vBuf = Buffer.from(value, 'utf8');
        const fullParam = Buffer.concat([param, u32le(kBuf.length), kBuf, u32le(vBuf.length), vBuf]);
        const builder = Transaction.updateContract(
            {
                amount: CcdAmount.fromMicroCcd(amountMicroCcd),
                address: ContractAddress.create(BigInt(contractIndex), BigInt(contractSubindex)),
                receiveName: ReceiveName.fromString(receiveName),
                message: Parameter.fromBuffer(fullParam),
            },
            Energy.create(energy),
        ).addMetadata({
            sender: who.sender,
            nonce: SequenceNumber.create(1n),
            expiry: TransactionExpiry.fromEpochSeconds(BigInt(expirySec)),
        });
        if (numSigs > 1) builder.addMultiSig(numSigs);
        if (sponsorAddress) builder.addSponsor(AccountAddress.fromBase58(sponsorAddress));
        const signed = await Transaction.sign(builder.build(), who.signer);
        const obj = JSON.parse(Transaction.toJSONString(signed));
        if (mutateAfterSign) mutateAfterSign(obj);
        return JSON.stringify(obj);
    };

    const callSponsor = async (txPromiseOrStr, extraOpts = {}) =>
        validateAndSponsorSetMetadata({
            transactionJson: await txPromiseOrStr,
            expectedOwner: OWNER_A,
            expectedSponsor: WITNESS_1,
            expectedTokenId: TOKEN_ID,
            expectedKey: ANCHOR_KEY,
            expectedValueUtf8: anchorHash,
            sponsorSigner: witnessSigner,
            nodeClient: node,
            ...extraOpts,
        });

    // 1. Wrong contract
    await assert.rejects(() => callSponsor(makeTxJson({ contractIndex: 9999 })), /pinned registry/);
    // 2. Wrong entrypoint
    await assert.rejects(() => callSponsor(makeTxJson({ receiveName: 'CIS-8004.setAgentURI' })), /CIS-8004\.setMetadata/);
    // 3. Non-zero CCD attached
    await assert.rejects(() => callSponsor(makeTxJson({ amountMicroCcd: 1n })), /non-zero CCD/);
    // 4. Changed metadata value
    await assert.rejects(() => callSponsor(makeTxJson({ value: 'f'.repeat(64) })), /parameter bytes/);
    // 5. Changed metadata key
    await assert.rejects(() => callSponsor(makeTxJson({ key: 'other.key' })), /parameter bytes/);
    // 6. Alias sender instead of exact owner
    const aliasSigner = { ...ownerSigner, address: OWNER_A_ALIAS, sender: AccountAddress.fromBase58(OWNER_A_ALIAS) };
    await assert.rejects(() => callSponsor(makeTxJson({ who: aliasSigner })), /must exactly match owner/);
    // 7. Wrong sponsor
    await assert.rejects(() => callSponsor(makeTxJson({ sponsorAddress: WITNESS_2 })), /expected sponsor/);
    // 8. Not sponsorable (V0)
    await assert.rejects(() => callSponsor(makeTxJson({ sponsorAddress: null })), /v1 signable sponsorable/);
    // 9. Energy > maxEnergy
    await assert.rejects(() => callSponsor(makeTxJson({ energy: 100001 })), /exceeds allowed cap/);
    // 10. Excessive numSignatures > 10
    await assert.rejects(() => callSponsor(makeTxJson({ numSigs: 11 })), /numSignatures 11 outside/);
    // 11. Already sponsored
    await assert.rejects(
        () =>
            callSponsor(
                makeTxJson({
                    mutateAfterSign: (o) => {
                        o.signatures.sponsor = { 0: { 0: 'aa'.repeat(64) } };
                    },
                }),
            ),
        /already contains a sponsor signature/,
    );
    // 12. Expired / too far future
    await assert.rejects(() => callSponsor(makeTxJson({ expirySec: tipEpochSec })), /outside valid window/);
    await assert.rejects(() => callSponsor(makeTxJson({ expirySec: tipEpochSec + 4000 })), /outside valid window/);
    // 13. Bad Ed25519 signature (signed by attacker's key pretending to be OWNER_A)
    const forgedOwnerSigner = { ...attackerSigner, address: OWNER_A, sender: AccountAddress.fromBase58(OWNER_A) };
    await assert.rejects(() => callSponsor(makeTxJson({ who: forgedOwnerSigner })), /invalid owner signature/);
    // 14. Dry-run usedEnergy exceeds tx executionEnergyAmount
    await assert.rejects(
        () =>
            callSponsor(makeTxJson({ energy: 500 }), {
                nodeClient: Object.assign(Object.create(node), {
                    invokeContract: async () => ({ tag: 'success', usedEnergy: { value: 900n }, returnValue: ReturnValue.empty() }),
                }),
            }),
        /exceeds transaction executionEnergyAmount/,
    );
});

test('cli.mjs verify enforces witness timeline across owner -> W1 -> W2 -> clear and rejects mismatches', async () => {
    const dir = makeTempDir();
    const { header, records } = makeTrailFixtures(5);
    const trailFile = path.join(dir, 'trail.jsonl');
    writeTrail(trailFile, header, records);
    const { at } = commitments(header, records, new Set([1, 2, 3, 4, 5]));

    const buildTimelineNode = ({
        signers, // array of { toSeq, sender }
        witnessEvents, // array of { height, value }
        tipWitnessMeta,
    }) => {
        const node = createWitnessMockNode({ owner: OWNER_A, initialMetadata: { 'unitares.agent_uuid': AGENT_UUID } });
        let prevTx = null;
        let height = 1050n;
        const wEvents = [...witnessEvents].sort((a, b) => Number(a.height - b.height));
        let wIdx = 0;

        for (const s of signers) {
            while (wIdx < wEvents.length && wEvents[wIdx].height <= height) {
                node.addSetMetadata({ sender: OWNER_A, key: WITNESS_KEY, value: wEvents[wIdx].value, height: wEvents[wIdx].height });
                wIdx += 1;
            }
            const rd = node.addRegisterData({
                sender: s.sender,
                height,
                data: encodeAnchor({ tokenId: TOKEN_ID, toSeq: s.toSeq, commitment: at.get(s.toSeq), prevAnchorTx: prevTx }),
            });
            node.addSetMetadata({ sender: OWNER_A, key: ANCHOR_KEY, value: rd.txHash, height: height + 1n });
            prevTx = rd.txHash;
            height += 20n;
        }
        while (wIdx < wEvents.length) {
            node.addSetMetadata({ sender: OWNER_A, key: WITNESS_KEY, value: wEvents[wIdx].value, height: wEvents[wIdx].height });
            wIdx += 1;
        }
        if (tipWitnessMeta !== undefined) {
            node.state.metadata[WITNESS_KEY] = tipWitnessMeta;
        }
        return node;
    };

    const cardFile = path.join(dir, 'card.json');
    fs.writeFileSync(cardFile, makeCardBytes({ ownerAccount: OWNER_A }).bytes);

    // 1. Owner-only trail preserves exact original check label
    const ownerNode = buildTimelineNode({ signers: [{ toSeq: 2, sender: OWNER_A }], witnessEvents: [] });
    const resOwner = await runVerifyQuiet({ badge: BADGE, trail: trailFile, card: cardFile, nodeClient: ownerNode });
    assert.equal(resOwner.ok, true, resOwner.output);
    assert.match(resOwner.output, /every anchor was sent by the registry entry owner/);
    // --require-witness must fail on owner-only trail
    const resReqFail = await runVerifyQuiet({ badge: BADGE, trail: trailFile, card: cardFile, requireWitness: true, nodeClient: ownerNode });
    assert.equal(resReqFail.ok, false);

    // 2. Mixed timeline: owner(1) -> W1(2) -> W2(3) -> cleared -> owner(4)
    const mixedNode = buildTimelineNode({
        signers: [
            { toSeq: 1, sender: OWNER_A },
            { toSeq: 2, sender: WITNESS_1 },
            { toSeq: 3, sender: WITNESS_2 },
            { toSeq: 4, sender: OWNER_A },
        ],
        witnessEvents: [
            { height: 1060n, value: WITNESS_1 },
            { height: 1080n, value: WITNESS_2 },
            { height: 1100n, value: '' },
        ],
    });
    const resMixed = await runVerifyQuiet({ badge: BADGE, trail: trailFile, card: cardFile, nodeClient: mixedNode });
    assert.equal(resMixed.ok, true, resMixed.output);
    assert.match(resMixed.output, /authorized signer \(owner or active witness\)/);
    // --require-witness fails after clearing back to owner
    assert.equal((await runVerifyQuiet({ badge: BADGE, trail: trailFile, card: cardFile, requireWitness: true, nodeClient: mixedNode })).ok, false);

    // 3. Rotation to W2 passes with --require-witness and --witness W2, fails with --witness W1
    const rotNode = buildTimelineNode({
        signers: [
            { toSeq: 1, sender: OWNER_A },
            { toSeq: 2, sender: WITNESS_1 },
            { toSeq: 3, sender: WITNESS_2 },
        ],
        witnessEvents: [
            { height: 1060n, value: WITNESS_1 },
            { height: 1080n, value: WITNESS_2 },
        ],
    });
    assert.equal((await runVerifyQuiet({ badge: BADGE, trail: trailFile, card: cardFile, requireWitness: true, witness: WITNESS_2, nodeClient: rotNode })).ok, true);
    assert.equal((await runVerifyQuiet({ badge: BADGE, trail: trailFile, card: cardFile, witness: WITNESS_1, nodeClient: rotNode })).ok, false);

    // 4. Rejects anchor signed by old witness W1 AFTER rotation to W2
    const staleSignerNode = buildTimelineNode({
        signers: [
            { toSeq: 2, sender: WITNESS_1 },
            { toSeq: 3, sender: WITNESS_1 }, // invalid after W2 became active!
        ],
        witnessEvents: [
            { height: 1040n, value: WITNESS_1 },
            { height: 1060n, value: WITNESS_2 },
        ],
    });
    assert.equal((await runVerifyQuiet({ badge: BADGE, trail: trailFile, card: cardFile, nodeClient: staleSignerNode })).ok, false);

    // 5. Rejects out-of-history initial_metadata countersign.witness
    const initialInjectedNode = buildTimelineNode({
        signers: [{ toSeq: 2, sender: OWNER_A }],
        witnessEvents: [],
        tipWitnessMeta: WITNESS_1,
    });
    const resInj = await runVerifyQuiet({ badge: BADGE, trail: trailFile, card: cardFile, nodeClient: initialInjectedNode });
    assert.equal(resInj.ok, false);
    assert.match(resInj.output, /reconstructed witness history/);

    // 6. Rejects setting witness equal to owner or invalid Base58Check in history
    const selfHist = {
        owner: OWNER_A,
        events: [{ key: WITNESS_KEY, value: Buffer.from(OWNER_A, 'utf8'), txHash: txHashFor('sw') }],
    };
    assert.throws(() => extractWitnessState(selfHist), /cannot equal owner/);
    assert.throws(() => extractWitnessState({ owner: OWNER_A, events: [{ key: WITNESS_KEY, value: Buffer.from('bad-addr'), txHash: txHashFor('bw') }] }), /invalid Base58Check/);
    const badWitnessFlag = await runVerifyQuiet({ badge: BADGE, trail: trailFile, card: cardFile, witness: 'not-valid', nodeClient: rotNode });
    assert.equal(badWitnessFlag.ok, false);
});

test('cli.mjs set-witness, cli.mjs anchor --witness-url, and AnchorWorker witness + crash recovery', async () => {
    const dir = makeTempDir();
    const ownerSigner = await makeRealSigner(OWNER_A);
    const witnessSigner = await makeRealSigner(WITNESS_1);
    const payerSigner = await makeRealSigner(PAYER_3);
    const ownerKeyfile = writeKeyfile(dir, 'owner.json', ownerSigner, 0o600);
    const witnessKeyfile = writeKeyfile(dir, 'witness.json', witnessSigner, 0o600);
    const payerKeyfile = writeKeyfile(dir, 'payer.json', payerSigner, 0o600);

    const node = createWitnessMockNode({
        owner: OWNER_A,
        accountVerifyKeys: new Map([
            [OWNER_A, ownerSigner.verifyKey],
            [WITNESS_1, witnessSigner.verifyKey],
        ]),
    });

    // 1. set-witness rejects self-witnessing and sets/clears cleanly
    await assert.rejects(
        () => commands['set-witness']({ token: TOKEN_ID, witness: OWNER_A, who: ownerSigner, nodeClient: node }),
        /cannot be the same as token owner/,
    );
    await runQuiet(() => commands['set-witness']({ token: TOKEN_ID, witness: WITNESS_1, who: ownerSigner, nodeClient: node }));
    assert.equal(node.state.metadata[WITNESS_KEY], WITNESS_1);

    // Start witness server via cli.mjs witness command
    const srv = await commands.witness({
        host: '127.0.0.1',
        port: 0,
        witnessKeyfile,
        ledger: path.join(dir, 'cli-witness-ledger.json'),
        nodeClient: node,
        fetchCard: async () => node.card.bytes,
        log: () => {},
    });
    cleanups.push(() => srv.close());

    // 2. cli.mjs anchor --witness-url with --payer-keyfile + sponsored pointer
    const { header, records } = makeTrailFixtures(4);
    const cliTrail = path.join(dir, 'cli-anchor.jsonl');
    writeTrail(cliTrail, header, records.slice(0, 2));
    await runQuiet(() =>
        commands.anchor({
            trail: cliTrail,
            who: ownerSigner,
            nodeClient: node,
            witnessUrl: srv.url,
            allowPrivateWitness: true,
            payerKeyfile,
        }),
    );
    const ptr1 = node.state.metadata[ANCHOR_KEY];
    assert.ok(ptr1);
    const hist1 = await readRegistryHistory(TOKEN_ID, {
        tipBlockHash: blockHashFor(node.state.tipHeight),
        tipBlockHeight: node.state.tipHeight,
        agent: node.agent,
        hintAnchorTxHashes: [ptr1],
        nodeClient: node,
    });
    const anchors1 = await loadAnchorsFromHistory(hist1, node, node.state.tipHeight);
    assert.equal(anchors1.length, 1);
    assert.equal(anchors1[0].sender, WITNESS_1);
    assert.equal(anchors1[0].authorizedWitness, WITNESS_1);

    // 3. AnchorWorker with witnessUrl + sponsored pointer: succeeds at remainingOwnerBudget === 1 (where self-anchoring requires 2)
    const workerTrail = path.join(dir, 'worker.jsonl');
    const workerState = path.join(dir, 'worker.state.json');
    writeTrail(workerTrail, header, records.slice(0, 3));
    const currentHist = await readRegistryHistory(TOKEN_ID, {
        tipBlockHash: blockHashFor(node.state.tipHeight),
        tipBlockHeight: node.state.tipHeight,
        agent: node.agent,
        nodeClient: node,
    });
    // Set remainingOwnerBudget = 1 by mocking readRegistryHistory maxOwnerTxs? Let's test via worker constructor with real trail & witnessUrl:
    // Also check when owner pays directly vs third-party payer: owner nonce refreshes accurately before setMetadata!
    const worker = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath: workerTrail,
        statePath: workerState,
        everyRecords: 1,
        once: true,
        nodeClient: node,
        signer: ownerSigner,
        witnessUrl: srv.url,
        allowPrivateWitness: true,
        // Notice no payerKeyfile -> ownerSigner pays on chain (+1 nonce), then worker refreshes nonce before sponsored setMetadata!
        source: () => [],
        log: () => {},
    });
    const wRes = await worker.tick();
    assert.equal(wRes.anchored, true);
    assert.equal(wRes.anchoredSeq, 3);
    assert.equal(JSON.parse(fs.readFileSync(workerState, 'utf8')).pendingAnchor, null);

    // 4. AnchorWorker crash recovery when pendingAnchor.metadataTx has mode: 'sponsored' & txHash: null
    writeTrail(workerTrail, header, records);
    const { at } = commitments(header, records, new Set([4]));
    const preAnchor = await requestWitnessAnchor({
        witnessUrl: srv.url,
        tokenId: TOKEN_ID,
        toSeq: 4,
        commitment: at.get(4).toString('hex'),
        prevAnchorTx: wRes.txHash,
        allowPrivate: true,
        payFn: async (reqs) => {
            const x = await sendTransferWithMemo({
                to: reqs.payTo,
                microCcd: BigInt(reqs.amount),
                memoBytes: Buffer.from(reqs.extra.memoHex, 'hex'),
                who: payerSigner,
                nodeClient: node,
            });
            return { x402Version: 2, accepted: reqs, payload: { txHash: x.hash } };
        },
    });
    const tipSec = Math.floor(node.timeForHeight(node.state.tipHeight) / 1000);
    // Simulate crash right after building sponsored setMetadata before requestSponsoredPointer returned
    fs.writeFileSync(
        workerState,
        JSON.stringify({
            version: 1,
            agentUuid: AGENT_UUID,
            tokenId: TOKEN_ID,
            lastAnchoredSeq: 3,
            lastAnchoredTxHash: wRes.txHash,
            lastAnchoredCommitment: commitments(header, records.slice(0, 3)).last.toString('hex'),
            lastAnchoredAt: '2026-11-21T00:00:00.000Z',
            pendingAnchor: {
                txHash: preAnchor.txHash,
                status: 'finalized',
                expiryEpochSeconds: null,
                tokenId: TOKEN_ID,
                toSeq: 4,
                commitment: at.get(4).toString('hex'),
                prevAnchorTx: wRes.txHash,
                sender: WITNESS_1,
                metadataTx: {
                    mode: 'sponsored',
                    sponsorUrl: srv.url,
                    txHash: null,
                    expiryEpochSeconds: tipSec + 100,
                    nonce: 99,
                },
            },
        }),
        { mode: 0o600 },
    );

    const recoveryWorker = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath: workerTrail,
        statePath: workerState,
        everyRecords: 1,
        once: true,
        nodeClient: node,
        signer: ownerSigner,
        witnessUrl: srv.url,
        allowPrivateWitness: true,
        source: () => [],
        log: () => {},
    });

    // Before expiry -> must refuse to double-submit!
    await assert.rejects(() => recoveryWorker.tick(), /in-flight\/ambiguous until finalized chain time passes expiry/);

    // Advance chain time past expiry -> clears metadataTx and completes sponsored pointer recovery cleanly!
    node.setTipSlotTimeMs((tipSec + 101) * 1000);
    const recRes = await recoveryWorker.tick();
    assert.equal(recRes.anchoredSeq, 4);
    assert.equal(node.state.metadata[ANCHOR_KEY], preAnchor.txHash);
    assert.equal(JSON.parse(fs.readFileSync(workerState, 'utf8')).pendingAnchor, null);

    // Verify clear witness via cli.mjs set-witness --clear and guard against non-finalized nonce / alias
    node.state.allFinal = false;
    await assert.rejects(
        () => commands['set-witness']({ token: TOKEN_ID, clear: true, who: ownerSigner, nodeClient: node }),
        /unfinalized/,
    );
    node.state.allFinal = true;
    await assert.rejects(
        () => commands['set-witness']({ token: TOKEN_ID, clear: true, who: { ...ownerSigner, address: OWNER_A_ALIAS }, nodeClient: node }),
        /must exactly match registered owner/,
    );
    await runQuiet(() => commands['set-witness']({ token: TOKEN_ID, clear: true, who: ownerSigner, nodeClient: node }));
    assert.equal(node.state.metadata[WITNESS_KEY], '');
    assert.equal(currentHist.owner, OWNER_A);

    // Silence unused ownerKeyfile lint if any
    assert.ok(fs.existsSync(ownerKeyfile));
});

test('cli.mjs anchor --witness-url --no-sponsor-pointer falls back to direct setMetadata and AnchorWorker recovers witness-signed pendingAnchor', async () => {
    const dir = makeTempDir();
    const ownerSigner = await makeRealSigner(OWNER_A);
    const witnessSigner = await makeRealSigner(WITNESS_1);
    const payerSigner = await makeRealSigner(PAYER_3);
    const witnessKeyfile = writeKeyfile(dir, 'witness.json', witnessSigner, 0o600);
    const payerKeyfile = writeKeyfile(dir, 'payer.json', payerSigner, 0o600);

    const node = createWitnessMockNode({
        owner: OWNER_A,
        accountVerifyKeys: new Map([
            [OWNER_A, ownerSigner.verifyKey],
            [WITNESS_1, witnessSigner.verifyKey],
        ]),
    });
    node.addSetMetadata({ sender: OWNER_A, key: WITNESS_KEY, value: WITNESS_1 });

    const srv = await startWitnessServer({
        host: '127.0.0.1',
        port: 0,
        witnessKeyfile,
        ledgerPath: path.join(dir, 'nosponsor-cli-ledger.json'),
        nodeClient: node,
        fetchCard: async () => node.card.bytes,
        log: () => {},
    });
    cleanups.push(() => srv.close());

    const { header, records } = makeTrailFixtures(4);
    const trailPath = path.join(dir, 'cli-direct-meta.jsonl');
    const statePath = path.join(dir, 'cli-direct-meta.state.json');
    writeTrail(trailPath, header, records.slice(0, 2));

    await runQuiet(() =>
        commands.anchor({
            trail: trailPath,
            who: ownerSigner,
            nodeClient: node,
            witnessUrl: srv.url,
            allowPrivateWitness: true,
            noSponsorPointer: true,
            payerKeyfile,
        }),
    );
    const lastMetaTx = node.submitted.at(-1);
    assert.equal(lastMetaTx.version, 0, 'with --no-sponsor-pointer, setMetadata must be direct V0 tx');
    const ptr2 = node.state.metadata[ANCHOR_KEY];
    assert.ok(ptr2);

    // AnchorWorker recovers from crash AFTER witness signed/finalized registerData (metadataTx: null)
    writeTrail(trailPath, header, records);
    const { at } = commitments(header, records, new Set([4]));
    const wAnchor = await requestWitnessAnchor({
        witnessUrl: srv.url,
        tokenId: TOKEN_ID,
        toSeq: 4,
        commitment: at.get(4).toString('hex'),
        prevAnchorTx: ptr2,
        allowPrivate: true,
        payFn: async (reqs) => {
            const x = await sendTransferWithMemo({
                to: reqs.payTo,
                microCcd: BigInt(reqs.amount),
                memoBytes: Buffer.from(reqs.extra.memoHex, 'hex'),
                who: payerSigner,
                nodeClient: node,
            });
            return { x402Version: 2, accepted: reqs, payload: { txHash: x.hash } };
        },
    });
    fs.writeFileSync(
        statePath,
        JSON.stringify({
            version: 1,
            agentUuid: AGENT_UUID,
            tokenId: TOKEN_ID,
            lastAnchoredSeq: 2,
            lastAnchoredTxHash: ptr2,
            lastAnchoredCommitment: commitments(header, records.slice(0, 2)).last.toString('hex'),
            lastAnchoredAt: '2026-11-21T00:00:00.000Z',
            pendingAnchor: {
                txHash: wAnchor.txHash,
                status: 'finalized',
                expiryEpochSeconds: null,
                tokenId: TOKEN_ID,
                toSeq: 4,
                commitment: at.get(4).toString('hex'),
                prevAnchorTx: ptr2,
                sender: WITNESS_1,
                metadataTx: null,
            },
        }),
        { mode: 0o600 },
    );

    const worker = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath,
        statePath,
        everyRecords: 1,
        once: true,
        nodeClient: node,
        signer: ownerSigner,
        witnessUrl: srv.url,
        allowPrivateWitness: true,
        source: () => [],
        log: () => {},
    });
    const res = await worker.tick();
    assert.equal(res.anchoredSeq, 4);
    assert.equal(node.state.metadata[ANCHOR_KEY], wAnchor.txHash);
    assert.equal(JSON.parse(fs.readFileSync(statePath, 'utf8')).pendingAnchor, null);
});

test('AnchorWorker allows witnessUrl anchoring at remainingOwnerBudget === 1 (vs 2 for self-anchoring)', async () => {
    const dir = makeTempDir();
    const ownerSigner = await makeRealSigner(OWNER_A);
    const witnessSigner = await makeRealSigner(WITNESS_1);
    const payerSigner = await makeRealSigner(PAYER_3);

    const node = createWitnessMockNode({
        owner: OWNER_A,
        accountVerifyKeys: new Map([
            [OWNER_A, ownerSigner.verifyKey],
            [WITNESS_1, witnessSigner.verifyKey],
        ]),
    });
    // Burn 1999 owner nonces before witness setup? Simpler: authorize witness (1 tx) and stub maxOwnerTxs=2 on history?
    // Wait: AnchorWorker calls readRegistryHistory with default maxOwnerTxs=2000; add 1998 owner nonce bumps + 1 set-witness = 1999!
    node.addSetMetadata({ sender: OWNER_A, key: WITNESS_KEY, value: WITNESS_1, height: 1001n });
    for (let i = 0; i < 1998; i += 1) {
        node.state.nonceChanges.push({ sender: OWNER_A, height: 1002n + BigInt(Math.floor(i / 50)) });
    }
    node.state.tipHeight = 2000n;

    const srv = await startWitnessServer({
        host: '127.0.0.1',
        port: 0,
        signer: witnessSigner,
        ledgerPath: path.join(dir, 'budget-ledger.json'),
        nodeClient: node,
        fetchCard: async () => node.card.bytes,
        log: () => {},
    });
    cleanups.push(() => srv.close());

    const { header, records } = makeTrailFixtures(2);
    const trailPath = path.join(dir, 'budget.jsonl');
    const statePath = path.join(dir, 'budget.state.json');
    writeTrail(trailPath, header, records);

    // Self-anchoring worker at remainingOwnerBudget === 1 MUST refuse (+2 required)
    const selfWorker = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath,
        statePath,
        everyRecords: 1,
        once: true,
        nodeClient: node,
        signer: ownerSigner,
        source: () => [],
        log: () => {},
    });
    await assert.rejects(() => selfWorker.tick(), /\+ 2 exceeds maxOwnerTxs=2000/);

    // Witnessed worker at remainingOwnerBudget === 1 MUST succeed (+1 required when payer != owner)
    const witnessWorker = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath,
        statePath,
        everyRecords: 1,
        once: true,
        nodeClient: node,
        signer: ownerSigner,
        witnessUrl: srv.url,
        allowPrivateWitness: true,
        payerSigner,
        source: () => [],
        log: () => {},
    });
    const res = await witnessWorker.tick();
    assert.equal(res.anchored, true);
    assert.equal(res.anchoredSeq, 2);
});
