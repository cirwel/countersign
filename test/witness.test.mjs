import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
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
    sendRegisterData,
    sendTransferWithMemo,
    validateAndSponsorSetMetadata,
    verifyExistingAnchors,
} from '../src/chain.mjs';
import { encodeBadge, encodeTokenId, safeHttpsRequest, safeJsonFetch } from '../src/cis8004.mjs';
import { commands } from '../src/cli.mjs';
import { REGISTRY, REGISTRY_MODULE_REF } from '../src/registry.mjs';
import { commitments, decodeAnchor, encodeAnchor, writeTrail } from '../src/trail.mjs';
import { createWitnessServer, startWitnessServer } from '../src/witness.mjs';
import { AnchorWorker, tokenLockPath, withFileLock } from '../src/worker.mjs';
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
    assert.match(facRes.paymentId, /^facilitator:sha256:[0-9a-f]{64}$/);
    const facSettle = await fac.settle({ header: hdrFor(goodTx), requirements: reqs, expectedMemoHex: expectedMemo });
    assert.equal(facSettle.transaction, 'fac-tx-1');
    assert.equal(facSettle.network, CONCORDIUM_TESTNET_CAIP2);
    mode = 'bad_verify';
    await assert.rejects(() => fac.verify({ header: hdrFor(goodTx), requirements: reqs, expectedMemoHex: expectedMemo }), /bad sig/);
    mode = 'bad_settle';
    const okVerify = await fac.verify({ header: hdrFor(goodTx), requirements: reqs, expectedMemoHex: expectedMemo });
    assert.equal(okVerify.paymentId, facRes.paymentId);
    await assert.rejects(() => fac.settle({ header: hdrFor(goodTx), requirements: reqs, expectedMemoHex: expectedMemo }), /reverted/);
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

    // Replay of committed pay5 for a DIFFERENT commitment/seq is rejected with 409 by PaymentLedger before verification/settlement
    const resReplayMismatch = await fetch(`${srv.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', [HEADER_PAYMENT_SIGNATURE]: sig5 },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 6, commitment: c5Hex, prevAnchorTx: anchored.txHash }),
    });
    assert.equal(resReplayMismatch.status, 409);

    const r5Data = await rA.json();
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

    // Advance on-chain pointer to seq 5's anchor so seq 6 tests non-equivocating memo / seq guards
    node.addSetMetadata({ sender: OWNER_A, key: ANCHOR_KEY, value: r5Data.txHash });

    // An unused valid payment whose memo matches seq 5 is rejected with 402 if sent for seq 6
    const freshMemo5Pay = await sendTransferWithMemo({ to: WITNESS_1, microCcd: 1000000n, memoBytes: Buffer.from(memo5, 'hex'), who: payer, nodeClient: node });
    const resFreshMemoMismatch = await fetch(`${srv.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', [HEADER_PAYMENT_SIGNATURE]: encodeX402Header({ x402Version: 2, payload: { txHash: freshMemo5Pay.hash } }) },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 6, commitment: c5Hex, prevAnchorTx: r5Data.txHash }),
    });
    assert.equal(resFreshMemoMismatch.status, 402);

    // Wrong memo payment rejected with 402
    const wrongMemoPay = await sendTransferWithMemo({ to: WITNESS_1, microCcd: 1000000n, memoBytes: Buffer.alloc(32, 0x99), who: payer, nodeClient: node });
    const resWrongMemo = await fetch(`${srv.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', [HEADER_PAYMENT_SIGNATURE]: encodeX402Header({ x402Version: 2, payload: { txHash: wrongMemoPay.hash } }) },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 6, commitment: 'e'.repeat(64), prevAnchorTx: r5Data.txHash }),
    });
    assert.equal(resWrongMemo.status, 402);

    // Non-monotonic toSeq (toSeq <= prev.toSeq = 5) -> 409
    const resNonMono = await fetch(`${srv.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 5, commitment: c5Hex, prevAnchorTx: r5Data.txHash }),
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
            maxPriceMicroCcd: '1000000',
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
        maxPriceMicroCcd: '1000000',
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
            maxPriceMicroCcd: '1000000',
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

    // Self-anchoring worker when active witness exists MUST refuse immediately BEFORE broadcast/budget
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
    await assert.rejects(() => selfWorker.tick(), /--witness-url is required and self-anchoring is disabled/);

    // Owner-pays witness worker at remainingOwnerBudget === 1 MUST refuse BEFORE paying (+2 required: payment + pointer)
    const ownerPayerWorker = new AnchorWorker({
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
        maxPriceMicroCcd: '1000000',
        source: () => [],
        log: () => {},
    });
    const beforeBudgetSubmits = node.submitted.length;
    await assert.rejects(() => ownerPayerWorker.tick(), /\+ 2 exceeds maxOwnerTxs=2000/);
    assert.equal(node.submitted.length, beforeBudgetSubmits, 'owner must not send CCD payment when budget < 2');

    // Witnessed worker at remainingOwnerBudget === 1 MUST succeed (+1 required when 3rd-party payer != owner)
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
        maxPriceMicroCcd: '1000000',
        payerSigner,
        source: () => [],
        log: () => {},
    });
    const res = await witnessWorker.tick();
    assert.equal(res.anchored, true);
    assert.equal(res.anchoredSeq, 2);
});

test('enforces active witness on all anchor/--tx paths, verifies /v1/anchor on-chain via readRegisterData, and re-checks at setTipHash', async () => {
    const dir = makeTempDir();
    const ownerSigner = await makeRealSigner(OWNER_A);
    const witnessSigner = await makeRealSigner(WITNESS_1);

    const node = createWitnessMockNode({
        owner: OWNER_A,
        accountVerifyKeys: new Map([
            [OWNER_A, ownerSigner.verifyKey],
            [WITNESS_1, witnessSigner.verifyKey],
        ]),
    });
    node.addSetMetadata({ sender: OWNER_A, key: WITNESS_KEY, value: WITNESS_1 });

    const { header, records } = makeTrailFixtures(3);
    const trailPath = path.join(dir, 'enforce-witness.jsonl');
    writeTrail(trailPath, header, records.slice(0, 1));
    const c1 = commitments(header, records.slice(0, 1)).last;
    const ownerRd1 = await sendRegisterData(
        encodeAnchor({ tokenId: TOKEN_ID, toSeq: 1, commitment: c1, prevAnchorTx: null }),
        ownerSigner,
        node,
    );
    const witnessRd1 = await sendRegisterData(
        encodeAnchor({ tokenId: TOKEN_ID, toSeq: 1, commitment: c1, prevAnchorTx: null }),
        witnessSigner,
        node,
    );

    const submitsBeforeRefusals = node.submitted.length;
    await assert.rejects(
        () => commands.anchor({ trail: trailPath, who: ownerSigner, nodeClient: node }),
        /--witness-url is required and owner self-anchoring is disabled/,
    );
    assert.equal(node.submitted.length, submitsBeforeRefusals, 'must refuse before broadcasting any tx');

    await assert.rejects(
        () => commands.anchor({ trail: trailPath, tx: ownerRd1.hash, who: ownerSigner, nodeClient: node }),
        /not the next anchor for this trail/,
    );
    assert.equal(node.submitted.length, submitsBeforeRefusals);

    // Witness-signed --tx succeeds while WITNESS_1 is active
    await runQuiet(() =>
        commands.anchor({ trail: trailPath, tx: witnessRd1.hash, who: ownerSigner, nodeClient: node }),
    );
    assert.equal(node.state.metadata[ANCHOR_KEY], witnessRd1.hash);

    // Clear countersign.witness to "" -> witness-signed --tx is now refused, owner-signed --tx succeeds
    node.addSetMetadata({ sender: OWNER_A, key: WITNESS_KEY, value: '' });
    writeTrail(trailPath, header, records.slice(0, 2));
    const c2 = commitments(header, records.slice(0, 2)).last;
    const witnessRd2 = await sendRegisterData(
        encodeAnchor({ tokenId: TOKEN_ID, toSeq: 2, commitment: c2, prevAnchorTx: witnessRd1.hash }),
        witnessSigner,
        node,
    );
    const ownerRd2 = await sendRegisterData(
        encodeAnchor({ tokenId: TOKEN_ID, toSeq: 2, commitment: c2, prevAnchorTx: witnessRd1.hash }),
        ownerSigner,
        node,
    );
    await assert.rejects(
        () => commands.anchor({ trail: trailPath, tx: witnessRd2.hash, who: ownerSigner, nodeClient: node }),
        /not the next anchor for this trail/,
    );
    await runQuiet(() =>
        commands.anchor({ trail: trailPath, tx: ownerRd2.hash, who: ownerSigner, nodeClient: node }),
    );
    assert.equal(node.state.metadata[ANCHOR_KEY], ownerRd2.hash);

    // Re-enable WITNESS_1 for seq 3 and test tampered /v1/anchor node-direct verification + setTipHash rotation abort
    node.addSetMetadata({ sender: OWNER_A, key: WITNESS_KEY, value: WITNESS_1 });
    writeTrail(trailPath, header, records.slice(0, 3));
    const c3 = commitments(header, records.slice(0, 3)).last;
    const wrongSenderRd3 = await sendRegisterData(
        encodeAnchor({ tokenId: TOKEN_ID, toSeq: 3, commitment: c3, prevAnchorTx: ownerRd2.hash }),
        ownerSigner,
        node,
    );
    const wrongCommitmentRd3 = await sendRegisterData(
        encodeAnchor({ tokenId: TOKEN_ID, toSeq: 3, commitment: Buffer.alloc(32, 0xaa), prevAnchorTx: ownerRd2.hash }),
        witnessSigner,
        node,
    );
    const goodWitnessRd3 = await sendRegisterData(
        encodeAnchor({ tokenId: TOKEN_ID, toSeq: 3, commitment: c3, prevAnchorTx: ownerRd2.hash }),
        witnessSigner,
        node,
    );

    const fakeHealthFn = async () => ({
        ok: true,
        network: 'testnet',
        genesis: TESTNET_GENESIS,
        registry: { ...REGISTRY },
        witnessAccount: WITNESS_1,
        payTo: WITNESS_1,
        priceMicroCcd: '0',
        sponsorPointer: false,
    });

    const statePathTamper = path.join(dir, 'tamper.state.json');
    const submitsBeforeTamper = node.submitted.length;
    await assert.rejects(
        () =>
            commands.anchor({
                trail: trailPath,
                state: statePathTamper,
                who: ownerSigner,
                nodeClient: node,
                witnessUrl: 'https://witness.example',
                fetchWitnessHealthFn: fakeHealthFn,
                requestWitnessAnchorFn: async () => ({ txHash: wrongSenderRd3.hash, witnessAccount: WITNESS_1 }),
            }),
        /does not match active countersign\.witness/,
    );
    assert.equal(node.submitted.length, submitsBeforeTamper);

    const workerTamper = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath,
        statePath: statePathTamper,
        everyRecords: 1,
        once: true,
        nodeClient: node,
        signer: ownerSigner,
        witnessUrl: 'https://witness.example',
        fetchWitnessHealthFn: fakeHealthFn,
        requestWitnessAnchorFn: async () => ({ txHash: wrongCommitmentRd3.hash, witnessAccount: WITNESS_1 }),
        source: () => [],
        log: () => {},
    });
    await assert.rejects(() => workerTamper.tick(), /does not match expected anchor/);
    assert.equal(fs.existsSync(statePathTamper) && JSON.parse(fs.readFileSync(statePathTamper, 'utf8')).pendingAnchor, false);

    // setTipHash rotation abort: simulate witness changing on-chain right after witness returns rd3
    let rotated = false;
    const rotatingNode = Object.assign(Object.create(node), {
        async invokeContract(ctx, bh) {
            const method = ctx.method.value ?? String(ctx.method);
            const p = Buffer.from(ctx.parameter.buffer);
            if (rotated && method === 'CIS-8004.getMetadata' && p.includes(Buffer.from(WITNESS_KEY))) {
                return {
                    tag: 'success',
                    usedEnergy: { value: 1000n },
                    returnValue: ReturnValue.fromBuffer(encodeGetMetadataReturn(WITNESS_2)),
                };
            }
            return node.invokeContract(ctx, bh);
        },
    });
    const submitsBeforeRotate = node.submitted.length;
    await assert.rejects(
        () =>
            commands.anchor({
                trail: trailPath,
                state: path.join(dir, 'rotate-cli.state.json'),
                who: ownerSigner,
                nodeClient: rotatingNode,
                witnessUrl: 'https://witness.example',
                fetchWitnessHealthFn: fakeHealthFn,
                requestWitnessAnchorFn: async () => {
                    rotated = true;
                    return { txHash: goodWitnessRd3.hash, witnessAccount: WITNESS_1 };
                },
            }),
        /countersign\.witness changed concurrently/,
    );
    assert.equal(node.submitted.length, submitsBeforeRotate, 'must not submit setMetadata after setTipHash rotation');

    rotated = false;
    const workerRotate = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath,
        statePath: path.join(dir, 'rotate-worker.state.json'),
        everyRecords: 1,
        once: true,
        nodeClient: rotatingNode,
        signer: ownerSigner,
        witnessUrl: 'https://witness.example',
        fetchWitnessHealthFn: fakeHealthFn,
        requestWitnessAnchorFn: async () => {
            rotated = true;
            return { txHash: goodWitnessRd3.hash, witnessAccount: WITNESS_1 };
        },
        source: () => [],
        log: () => {},
    });
    await assert.rejects(() => workerRotate.tick(), /countersign\.witness changed concurrently/);
    assert.equal(node.submitted.length, submitsBeforeRotate);
});

test('client maxPriceMicroCcd, payTo/witness pinning, 210s default timeout, pendingPayment persistence & recovery', async (t) => {
    const dir = makeTempDir();
    const ownerSigner = await makeRealSigner(OWNER_A);
    const witnessSigner = await makeRealSigner(WITNESS_1);
    const payerSigner = await makeRealSigner(PAYER_3);
    const witnessKeyfile = writeKeyfile(dir, 'witness.json', witnessSigner, 0o600);

    const node = createWitnessMockNode({
        owner: OWNER_A,
        accountVerifyKeys: new Map([
            [OWNER_A, ownerSigner.verifyKey],
            [WITNESS_1, witnessSigner.verifyKey],
        ]),
    });
    node.addSetMetadata({ sender: OWNER_A, key: WITNESS_KEY, value: WITNESS_1 });

    // Check default 210s timeout on requestWitnessAnchor via setTimeout capture in safeHttpsRequest
    let capturedTimeoutMs = null;
    const origSetTimeout = globalThis.setTimeout;
    const timeoutMock = t.mock.method(globalThis, 'setTimeout', (fn, ms, ...args) => {
        if (typeof ms === 'number' && ms >= 100000) capturedTimeoutMs = ms;
        return origSetTimeout(fn, ms, ...args);
    });
    try {
        await assert.rejects(
            () =>
                requestWitnessAnchor({
                    witnessUrl: 'https://witness.example',
                    tokenId: TOKEN_ID,
                    toSeq: 1,
                    commitment: 'a'.repeat(64),
                    requestFn: () => {
                        const err = new Error('probe done');
                        const fakeReq = {
                            on(ev, cb) {
                                if (ev === 'error') queueMicrotask(() => cb(err));
                                return fakeReq;
                            },
                            write() {},
                            end() {},
                            destroy() {},
                        };
                        return fakeReq;
                    },
                }),
            /probe done/,
        );
    } finally {
        timeoutMock.mock.restore();
    }
    assert.ok(capturedTimeoutMs >= 210000, `expected timeout >= 210000ms, got ${capturedTimeoutMs}`);

    const srv = await startWitnessServer({
        host: '127.0.0.1',
        port: 0,
        witnessKeyfile,
        priceMicroCcd: '1000000',
        ledgerPath: path.join(dir, 'pay-pin-ledger.json'),
        nodeClient: node,
        fetchCard: async () => node.card.bytes,
        log: () => {},
    });
    cleanups.push(() => srv.close());

    // Pinning checks before calling payFn
    let payFnCalls = 0;
    await assert.rejects(
        () =>
            requestWitnessAnchor({
                witnessUrl: srv.url,
                tokenId: TOKEN_ID,
                toSeq: 1,
                commitment: 'a'.repeat(64),
                expectedPayTo: PAYER_3,
                allowPrivate: true,
                payFn: async () => {
                    payFnCalls += 1;
                    return '';
                },
            }),
        /does not match expected/,
    );
    await assert.rejects(
        () =>
            requestWitnessAnchor({
                witnessUrl: srv.url,
                tokenId: TOKEN_ID,
                toSeq: 1,
                commitment: 'a'.repeat(64),
                expectedWitnessAccount: WITNESS_2,
                allowPrivate: true,
                payFn: async () => {
                    payFnCalls += 1;
                    return '';
                },
            }),
        /extra\.witnessAccount.*does not match/,
    );
    await assert.rejects(
        () =>
            requestWitnessAnchor({
                witnessUrl: srv.url,
                tokenId: TOKEN_ID,
                toSeq: 1,
                commitment: 'a'.repeat(64),
                maxPriceMicroCcd: '999999',
                allowPrivate: true,
                payFn: async () => {
                    payFnCalls += 1;
                    return '';
                },
            }),
        /exceeds maxPriceMicroCcd/,
    );
    assert.equal(payFnCalls, 0);

    const { header, records } = makeTrailFixtures(3);
    const cliTrail = path.join(dir, 'cli-pay.jsonl');
    const cliState = path.join(dir, 'cli-pay.state.json');
    writeTrail(cliTrail, header, records.slice(0, 2));

    // cli.mjs anchor refuses if 402 exceeds /health advertised price
    const submitsBeforeQuoteMismatch = node.submitted.length;
    await assert.rejects(
        () =>
            commands.anchor({
                trail: cliTrail,
                state: cliState,
                who: ownerSigner,
                payerSigner,
                nodeClient: node,
                witnessUrl: srv.url,
                allowPrivateWitness: true,
                maxPriceMicroCcd: '2000000',
                fetchWitnessHealthFn: async () => ({
                    ok: true,
                    network: 'testnet',
                    genesis: TESTNET_GENESIS,
                    registry: { ...REGISTRY },
                    witnessAccount: WITNESS_1,
                    payTo: WITNESS_1,
                    priceMicroCcd: '500000',
                    sponsorPointer: true,
                }),
            }),
        /exceeds \/health priceMicroCcd/,
    );
    assert.equal(node.submitted.length, submitsBeforeQuoteMismatch);

    // cli.mjs anchor prints --payment-signature recovery hint if /v1/anchor fails AFTER payment finalizes
    const origErr = console.error;
    const errs = [];
    console.error = (...a) => errs.push(a.join(' '));
    try {
        await assert.rejects(
            () =>
                commands.anchor({
                    trail: cliTrail,
                    state: path.join(dir, 'cli-hint.state.json'),
                    who: ownerSigner,
                    payerSigner,
                    nodeClient: node,
                    witnessUrl: srv.url,
                    allowPrivateWitness: true,
                    maxPriceMicroCcd: '1000000',
                    requestWitnessAnchorFn: async (arg) => {
                        await arg.payFn(
                            createPaymentRequirements({
                                payTo: WITNESS_1,
                                amountMicroCcd: '1000000',
                                resource: `${srv.url}/v1/anchor`,
                                tokenId: TOKEN_ID,
                                toSeq: arg.toSeq,
                                commitment: arg.commitment,
                                prevAnchorTx: arg.prevAnchorTx,
                                witnessAccount: WITNESS_1,
                            }).accepts[0],
                        );
                        throw new Error('simulated 503 after payment');
                    },
                }),
            /simulated 503 after payment/,
        );
    } finally {
        console.error = origErr;
    }
    assert.match(errs.join('\n'), /retry with --payment-signature /);

    // AnchorWorker built-in payer persists pendingPayment, survives crash, blocks cli.mjs anchor, and reuses paymentSignature even after localSeq grows
    const workerTrail = path.join(dir, 'worker-pp.jsonl');
    const workerState = path.join(dir, 'worker-pp.state.json');
    writeTrail(workerTrail, header, records.slice(0, 2));
    const countPayments = () =>
        node.submitted.filter((tx) => tx.payload.type === AccountTransactionType.TransferWithMemo).length;
    const beforePayCount = countPayments();

    const workerPayFail = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath: workerTrail,
        statePath: workerState,
        everyRecords: 1,
        once: true,
        nodeClient: node,
        signer: ownerSigner,
        payerSigner,
        witnessUrl: srv.url,
        allowPrivateWitness: true,
        maxPriceMicroCcd: '1000000',
        requestWitnessAnchorFn: async (arg) => {
            await arg.payFn(
                createPaymentRequirements({
                    payTo: WITNESS_1,
                    amountMicroCcd: '1000000',
                    resource: `${srv.url}/v1/anchor`,
                    tokenId: TOKEN_ID,
                    toSeq: arg.toSeq,
                    commitment: arg.commitment,
                    prevAnchorTx: arg.prevAnchorTx,
                    witnessAccount: WITNESS_1,
                }).accepts[0],
            );
            throw new Error('witness down after payment finalized');
        },
        source: () => [],
        log: () => {},
    });
    await assert.rejects(() => workerPayFail.tick(), /witness down after payment finalized/);
    assert.equal(countPayments() - beforePayCount, 1);

    const savedState = JSON.parse(fs.readFileSync(workerState, 'utf8'));
    assert.equal(savedState.pendingPayment?.status, 'finalized');
    assert.equal(savedState.pendingPayment?.toSeq, 2);

    // cli.mjs anchor refuses while pendingPayment exists
    await assert.rejects(
        () =>
            commands.anchor({
                trail: workerTrail,
                state: workerState,
                who: ownerSigner,
                nodeClient: node,
                witnessUrl: srv.url,
                allowPrivateWitness: true,
                maxPriceMicroCcd: '1000000',
            }),
        (err) => /pending payment/.test(err.message) && /countersign watch --once --witness-url/.test(err.message),
    );

    // Append seq 3 before restart: AnchorWorker MUST resume pendingPayment for toSeq=2 without paying again, then anchor seq 3 cleanly
    writeTrail(workerTrail, header, records.slice(0, 3));
    const workerResume = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath: workerTrail,
        statePath: workerState,
        everyRecords: 1,
        once: true,
        nodeClient: node,
        signer: ownerSigner,
        payerSigner,
        witnessUrl: srv.url,
        allowPrivateWitness: true,
        maxPriceMicroCcd: '1000000',
        source: () => [],
        log: () => {},
    });
    const resResume = await workerResume.tick();
    assert.equal(resResume.anchored, true);
    assert.equal(resResume.anchoredSeq, 3);
    assert.equal(countPayments() - beforePayCount, 2, 'one payment for resumed seq 2 + one for new seq 3; no double-pay for seq 2');
    assert.equal(JSON.parse(fs.readFileSync(workerState, 'utf8')).pendingPayment, null);

    // pendingPayment absent before vs after expiry
    const expTrail = path.join(dir, 'exp-pp.jsonl');
    const expState = path.join(dir, 'exp-pp.state.json');
    const f4 = makeTrailFixtures(4);
    writeTrail(expTrail, f4.header, f4.records.slice(0, 4));
    const c4Hex = commitments(f4.header, f4.records.slice(0, 4)).last.toString('hex');
    const curPtr = node.state.metadata[ANCHOR_KEY];
    const tipSlotSec = Math.floor(node.timeForHeight(node.state.tipHeight) / 1000);
    fs.writeFileSync(
        expState,
        JSON.stringify({
            version: 1,
            agentUuid: AGENT_UUID,
            tokenId: TOKEN_ID,
            pendingPayment: {
                witnessUrl: srv.url,
                tokenId: TOKEN_ID,
                toSeq: 4,
                commitment: c4Hex,
                prevAnchorTx: curPtr,
                memoHex: computePaymentMemo({ tokenId: TOKEN_ID, toSeq: 4, commitment: c4Hex, prevAnchorTx: curPtr }),
                paymentTxHash: txHashFor('absent-payment'),
                expiryEpochSeconds: tipSlotSec + 60,
                paymentSignature: encodeX402Header({ x402Version: 2, payload: { txHash: txHashFor('absent-payment') } }),
                payer: payerSigner.address,
                amountMicroCcd: '1000000',
                status: 'signed',
            },
        }),
    );
    const workerExp = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath: expTrail,
        statePath: expState,
        everyRecords: 1,
        once: true,
        nodeClient: node,
        signer: ownerSigner,
        payerSigner,
        witnessUrl: srv.url,
        allowPrivateWitness: true,
        maxPriceMicroCcd: '1000000',
        source: () => [],
        log: () => {},
    });
    const paysBeforeExp = countPayments();
    await assert.rejects(() => workerExp.tick(), /in-flight\/ambiguous/);
    assert.equal(countPayments(), paysBeforeExp);

    node.setTipSlotTimeMs((tipSlotSec + 120) * 1000);
    const resAfterExp = await workerExp.tick();
    assert.equal(resAfterExp.anchored, true);
    assert.equal(resAfterExp.anchoredSeq, 4);
    assert.equal(countPayments(), paysBeforeExp + 1);
});

test('witness ledger file lock, cross-token signer nonce mutex, maxQueuedPerToken 429, and publicBaseUrl resource pinning', async () => {
    const dir = makeTempDir();
    const ownerSigner = await makeRealSigner(OWNER_A);
    const witnessSigner = await makeRealSigner(WITNESS_1);
    const payerSigner = await makeRealSigner(PAYER_3);
    const ledgerPath = path.join(dir, 'shared-ledger.json');

    const TOKEN_2 = '1316';
    const baseNode = createWitnessMockNode({
        owner: OWNER_A,
        accountVerifyKeys: new Map([
            [OWNER_A, ownerSigner.verifyKey],
            [WITNESS_1, witnessSigner.verifyKey],
        ]),
    });
    baseNode.addSetMetadata({ sender: OWNER_A, key: WITNESS_KEY, value: WITNESS_1 });
    const card2 = makeCardBytes({ badge: encodeBadge(TOKEN_2), ownerAccount: OWNER_A });
    const agent2 = {
        tokenId: TOKEN_2,
        ownerAccount: OWNER_A,
        agentUri: 'https://agent2.example/card.json',
        metadataHashHex: card2.hashHex,
        status: 'Active',
        registeredAtMs: baseNode.timeForHeight(1000n),
    };
    const meta2 = { 'unitares.agent_uuid': AGENT_UUID, [WITNESS_KEY]: WITNESS_1 };
    baseNode.state.txsByHeight.get(1000n).push({
        height: 1000n,
        hash: txHashFor('mint-2'),
        sender: OWNER_A,
        contractEvents: [evMint(TOKEN_2, OWNER_A), evMetadataSet(TOKEN_2, WITNESS_KEY, WITNESS_1)],
    });

    let activeRdBroadcasts = 0;
    let maxConcurrentRdBroadcasts = 0;
    let rdBroadcastCounter = 0;
    const multiNode = Object.assign(Object.create(baseNode), {
        async invokeContract(ctx, bh) {
            const method = ctx.method.value ?? String(ctx.method);
            const p = Buffer.from(ctx.parameter.buffer);
            const reqTid = p.length >= 9 ? p.readBigUInt64LE(1).toString() : null;
            if (reqTid === TOKEN_2) {
                if (method === 'CIS-8004.agentOf') {
                    return {
                        tag: 'success',
                        usedEnergy: { value: 1000n },
                        returnValue: ReturnValue.fromBuffer(encodeAgentOfReturn(agent2)),
                    };
                }
                if (method === 'CIS-8004.getMetadata') {
                    const klen = p.readUInt32LE(9);
                    const key = p.subarray(13, 13 + klen).toString('utf8');
                    return {
                        tag: 'success',
                        usedEnergy: { value: 1000n },
                        returnValue: ReturnValue.fromBuffer(encodeGetMetadataReturn(meta2[key] ?? null)),
                    };
                }
            }
            return baseNode.invokeContract(ctx, bh);
        },
        async sendTransaction(finalized) {
            if (finalized.payload.type === AccountTransactionType.RegisterData) {
                activeRdBroadcasts += 1;
                maxConcurrentRdBroadcasts = Math.max(maxConcurrentRdBroadcasts, activeRdBroadcasts);
                try {
                    rdBroadcastCounter += 1;
                    await new Promise((r) => setTimeout(r, 25));
                    return await baseNode.sendTransaction(finalized);
                } finally {
                    activeRdBroadcasts -= 1;
                }
            }
            return baseNode.sendTransaction(finalized);
        },
    });

    // Ledger file lock excludes a second witness server on the same ledgerPath until first closes
    const srv1 = await startWitnessServer({
        host: '127.0.0.1',
        port: 0,
        publicBaseUrl: 'https://witness.public.example:8443/ignored-path',
        maxQueuedPerToken: 2,
        signer: witnessSigner,
        ledgerPath,
        nodeClient: multiNode,
        fetchCard: async (uri) => (uri.includes('agent2') ? card2.bytes : baseNode.card.bytes),
        log: () => {},
    });
    cleanups.push(() => srv1.close());
    await assert.rejects(
        () =>
            startWitnessServer({
                host: '127.0.0.1',
                port: 0,
                signer: witnessSigner,
                ledgerPath,
                nodeClient: multiNode,
                log: () => {},
            }),
        /already held/,
    );

    // Safe resource pinning ignores spoofed Host header
    const spoofedRes = await fetch(`${srv1.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', host: 'evil.attacker:9999' },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 1, commitment: 'a'.repeat(64), prevAnchorTx: null }),
    });
    assert.equal(spoofedRes.status, 402);
    const pr = decodeX402Header(spoofedRes.headers.get(HEADER_PAYMENT_REQUIRED));
    assert.equal(pr.resource.url, 'https://witness.public.example:8443/v1/anchor');

    // Cross-token concurrency serialized cleanly by withSignerLock + consecutive witness nonces
    const c1 = '1'.repeat(64);
    const c2 = '2'.repeat(64);
    const memo1 = computePaymentMemo({ tokenId: TOKEN_ID, toSeq: 1, commitment: c1, prevAnchorTx: null });
    const memo2 = computePaymentMemo({ tokenId: TOKEN_2, toSeq: 1, commitment: c2, prevAnchorTx: null });
    const pay1 = await sendTransferWithMemo({
        to: WITNESS_1,
        microCcd: 1000000n,
        memoBytes: Buffer.from(memo1, 'hex'),
        who: payerSigner,
        nodeClient: multiNode,
    });
    const pay2 = await sendTransferWithMemo({
        to: WITNESS_1,
        microCcd: 1000000n,
        memoBytes: Buffer.from(memo2, 'hex'),
        who: payerSigner,
        nodeClient: multiNode,
    });
    const beforeSub = multiNode.submitted.length;
    const [resT1, resT2] = await Promise.all([
        fetch(`${srv1.url}/v1/anchor`, {
            method: 'POST',
            headers: {
                'content-type': 'application/json',
                [HEADER_PAYMENT_SIGNATURE]: encodeX402Header({ x402Version: 2, payload: { txHash: pay1.hash } }),
            },
            body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 1, commitment: c1, prevAnchorTx: null }),
        }),
        fetch(`${srv1.url}/v1/anchor`, {
            method: 'POST',
            headers: {
                'content-type': 'application/json',
                [HEADER_PAYMENT_SIGNATURE]: encodeX402Header({ x402Version: 2, payload: { txHash: pay2.hash } }),
            },
            body: JSON.stringify({ tokenId: TOKEN_2, toSeq: 1, commitment: c2, prevAnchorTx: null }),
        }),
    ]);
    assert.equal(resT1.status, 200);
    assert.equal(resT2.status, 200);
    const bodyT1 = await resT1.json();
    multiNode.addSetMetadata({ sender: OWNER_A, key: ANCHOR_KEY, value: bodyT1.txHash });
    assert.equal(rdBroadcastCounter, 2);
    assert.equal(maxConcurrentRdBroadcasts, 1, 'withSignerLock must prevent concurrent witness broadcasts');
    const rdTxs = multiNode.submitted.slice(beforeSub).filter((tx) => tx.payload.type === AccountTransactionType.RegisterData);
    assert.equal(rdTxs.length, 2);
    assert.equal(rdTxs[1].header.nonce.value, rdTxs[0].header.nonce.value + 1n);

    // maxQueuedPerToken: 2 rejects 3rd concurrent same-token request with 429
    const c2Next = '3'.repeat(64);
    const slowPay = await sendTransferWithMemo({
        to: WITNESS_1,
        microCcd: 1000000n,
        memoBytes: Buffer.from(computePaymentMemo({ tokenId: TOKEN_ID, toSeq: 2, commitment: c2Next, prevAnchorTx: bodyT1.txHash }), 'hex'),
        who: payerSigner,
        nodeClient: multiNode,
    });
    const bodySlow = JSON.stringify({ tokenId: TOKEN_ID, toSeq: 2, commitment: c2Next, prevAnchorTx: bodyT1.txHash });
    const sigSlow = encodeX402Header({ x402Version: 2, payload: { txHash: slowPay.hash } });
    const qReqs = await Promise.all([
        fetch(`${srv1.url}/v1/anchor`, { method: 'POST', headers: { 'content-type': 'application/json', [HEADER_PAYMENT_SIGNATURE]: sigSlow }, body: bodySlow }),
        fetch(`${srv1.url}/v1/anchor`, { method: 'POST', headers: { 'content-type': 'application/json', [HEADER_PAYMENT_SIGNATURE]: sigSlow }, body: bodySlow }),
        fetch(`${srv1.url}/v1/anchor`, { method: 'POST', headers: { 'content-type': 'application/json', [HEADER_PAYMENT_SIGNATURE]: sigSlow }, body: bodySlow }),
    ]);
    const statuses = qReqs.map((r) => r.status).sort((a, b) => a - b);
    assert.deepEqual(statuses, [200, 200, 429]);

    // Symlinked --ledger canonicalizes lock path, stays a symlink, and close() drains in-flight handlers before releasing lock
    const closeDrainLedger = path.join(dir, 'drain-ledger.json');
    const symDrainLedger = path.join(dir, 'drain-ledger-link.json');
    fs.writeFileSync(closeDrainLedger, JSON.stringify({ version: 1, payments: {}, sponsorPointers: {} }) + '\n', { mode: 0o600 });
    fs.symlinkSync(closeDrainLedger, symDrainLedger);

    let enterSlowSend;
    const enteredSlowSend = new Promise((r) => {
        enterSlowSend = r;
    });
    let releaseSlowSend;
    const holdSlowSend = new Promise((r) => {
        releaseSlowSend = r;
    });
    const slowDrainNode = Object.assign(Object.create(multiNode), {
        async sendTransaction(finalized) {
            if (finalized.payload.type === AccountTransactionType.RegisterData) {
                enterSlowSend();
                await holdSlowSend;
            }
            return multiNode.sendTransaction(finalized);
        },
    });
    const drainSrv = await startWitnessServer({
        host: '127.0.0.1',
        port: 0,
        priceMicroCcd: '0',
        signer: witnessSigner,
        ledgerPath: symDrainLedger,
        nodeClient: slowDrainNode,
        verifier: { async verify() { return { paymentId: 'drain-pay-1', payer: PAYER_3 }; } },
        fetchCard: async () => baseNode.card.bytes,
        log: () => {},
    });
    cleanups.push(() => drainSrv.close());
    // Second server pointing at the canonical target of symDrainLedger MUST be blocked while drainSrv holds lock
    await assert.rejects(
        () =>
            startWitnessServer({
                host: '127.0.0.1',
                port: 0,
                priceMicroCcd: '0',
                signer: witnessSigner,
                ledgerPath: closeDrainLedger,
                nodeClient: slowDrainNode,
                log: () => {},
            }),
        /already held/,
    );

    const drainCommit = '4'.repeat(64);
    const drainReqPromise = fetch(`${drainSrv.url}/v1/anchor`, {
        method: 'POST',
        headers: {
            'content-type': 'application/json',
            [HEADER_PAYMENT_SIGNATURE]: encodeX402Header({ x402Version: 2, payload: { drain: 1 } }),
        },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 3, commitment: drainCommit, prevAnchorTx: bodyT1.txHash }),
    });
    await enteredSlowSend;

    let closeSettled = false;
    const closeP = drainSrv.close().then(() => {
        closeSettled = true;
    });
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(closeSettled, false, 'close() must wait for in-flight witness request to finish');
    await assert.rejects(
        () =>
            startWitnessServer({
                host: '127.0.0.1',
                port: 0,
                priceMicroCcd: '0',
                signer: witnessSigner,
                ledgerPath: closeDrainLedger,
                nodeClient: slowDrainNode,
                log: () => {},
            }),
        /already held/,
        'ledger lock must remain held while close() drains in-flight request',
    );

    releaseSlowSend();
    const drainRes = await drainReqPromise;
    assert.equal(drainRes.status, 200);
    await closeP;
    assert.equal(closeSettled, true);
    assert.equal(JSON.parse(fs.readFileSync(closeDrainLedger, 'utf8')).payments['drain-pay-1']?.status, 'committed');
    assert.equal(fs.lstatSync(symDrainLedger).isSymbolicLink(), true, 'symlinked --ledger must stay a symlink');

    const drainSrvReopen = await startWitnessServer({
        host: '127.0.0.1',
        port: 0,
        priceMicroCcd: '0',
        signer: witnessSigner,
        ledgerPath: closeDrainLedger,
        nodeClient: multiNode,
        fetchCard: async () => baseNode.card.bytes,
        log: () => {},
    });
    cleanups.push(() => drainSrvReopen.close());
    await drainSrvReopen.close();

    await srv1.close();
    // Re-opening after close succeeds cleanly
    const srv2 = await startWitnessServer({
        host: '127.0.0.1',
        port: 0,
        signer: witnessSigner,
        ledgerPath,
        nodeClient: multiNode,
        fetchCard: async () => baseNode.card.bytes,
        log: () => {},
    });
    cleanups.push(() => srv2.close());
    await srv2.close();
});

test('FacilitatorVerifier verify->claim->settle order, settled resume, broadcasted reconciliation, equivocation 409, and claimed sponsor cleanup', async () => {
    const dir = makeTempDir();
    const ownerSigner = await makeRealSigner(OWNER_A);
    const witnessSigner = await makeRealSigner(WITNESS_1);

    const node = createWitnessMockNode({
        owner: OWNER_A,
        accountVerifyKeys: new Map([
            [OWNER_A, ownerSigner.verifyKey],
            [WITNESS_1, witnessSigner.verifyKey],
        ]),
    });
    node.addSetMetadata({ sender: OWNER_A, key: WITNESS_KEY, value: WITNESS_1 });

    let verifyCalls = 0;
    let settleCalls = 0;
    const facSrv = https.createServer({ key: TEST_KEY_PEM, cert: TEST_CERT_PEM }, (req, res) => {
        if (req.url === '/verify') {
            verifyCalls += 1;
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ isValid: true, payer: PAYER_3 }));
        } else if (req.url === '/settle') {
            settleCalls += 1;
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ success: true, transaction: `fac-${settleCalls}`, network: CONCORDIUM_TESTNET_CAIP2 }));
        }
    });
    await new Promise((r) => facSrv.listen(0, '127.0.0.1', r));
    cleanups.push(async () => {
        facSrv.closeAllConnections?.();
        await new Promise((r) => facSrv.close(r));
    });

    const facVerifier = createFacilitatorVerifier({
        facilitatorUrl: `https://127.0.0.1:${facSrv.address().port}`,
        allowPrivate: true,
        ca: Buffer.from(TEST_CERT_PEM),
    });

    let failBeforeSignOnce = false;
    let simulateConcurrentAnchorBeforeSettle = false;
    let getMetaCount = 0;
    const racingNode = Object.assign(Object.create(node), {
        async invokeContract(ctx, bh) {
            const p = Buffer.from(ctx.parameter.buffer);
            if (simulateConcurrentAnchorBeforeSettle && ctx.method.value === 'CIS-8004.getMetadata' && p.includes(Buffer.from(ANCHOR_KEY))) {
                getMetaCount += 1;
                if (getMetaCount === 2) {
                    return {
                        tag: 'success',
                        usedEnergy: { value: 1000n },
                        returnValue: ReturnValue.fromBuffer(encodeGetMetadataReturn(txHashFor('other-race'))),
                    };
                }
            }
            return node.invokeContract(ctx, bh);
        },
        async getNextAccountNonce(acct) {
            if (failBeforeSignOnce) {
                failBeforeSignOnce = false;
                throw new Error('transient grpc error before signing/broadcast');
            }
            return node.getNextAccountNonce(acct);
        },
    });

    const srv = await startWitnessServer({
        host: '127.0.0.1',
        port: 0,
        signer: witnessSigner,
        ledgerPath: path.join(dir, 'fac-ledger.json'),
        nodeClient: racingNode,
        verifier: facVerifier,
        fetchCard: async () => node.card.bytes,
        log: () => {},
    });
    cleanups.push(() => srv.close());

    // 1. Concurrent pointer move before /settle -> 409 and /settle is NOT called
    simulateConcurrentAnchorBeforeSettle = true;
    const sig1 = encodeX402Header({ x402Version: 2, payload: { auth: 'token-1' } });
    const req1 = await fetch(`${srv.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', [HEADER_PAYMENT_SIGNATURE]: sig1 },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 1, commitment: 'a'.repeat(64), prevAnchorTx: null }),
    });
    assert.equal(req1.status, 409);
    assert.equal(settleCalls, 0, '/settle must not run when anchor race fails before settlement');
    simulateConcurrentAnchorBeforeSettle = false;

    // 2. Pre-broadcast failure AFTER /settle (before onSigned) leaves ledger status === 'settled',
    //    and retry succeeds with verifyCalls === 1, settleCalls === 1
    verifyCalls = 0;
    settleCalls = 0;
    failBeforeSignOnce = true;
    const req2Fail = await fetch(`${srv.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', [HEADER_PAYMENT_SIGNATURE]: sig1 },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 1, commitment: 'a'.repeat(64), prevAnchorTx: null }),
    });
    assert.equal(req2Fail.status, 500);
    const pid1 = facVerifier.derivePaymentId(sig1);
    assert.equal(srv.ledger.get(pid1)?.status, 'settled');

    const req2Ok = await fetch(`${srv.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', [HEADER_PAYMENT_SIGNATURE]: sig1 },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 1, commitment: 'a'.repeat(64), prevAnchorTx: null }),
    });
    assert.equal(req2Ok.status, 200);
    assert.equal(verifyCalls, 1, 'retry after settled must not re-call /verify');
    assert.equal(settleCalls, 1, 'retry after settled must not re-call /settle');
    const a1 = await req2Ok.json();

    // 3. Equivocation 409 on same (tokenId, prevAnchorTx) with different (toSeq, commitment) BEFORE /verify or /settle
    const sigEquiv = encodeX402Header({ x402Version: 2, payload: { auth: 'token-equiv' } });
    const reqEquiv = await fetch(`${srv.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', [HEADER_PAYMENT_SIGNATURE]: sigEquiv },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 2, commitment: 'b'.repeat(64), prevAnchorTx: null }),
    });
    assert.equal(reqEquiv.status, 409);
    assert.equal(verifyCalls, 1, 'equivocation must fail before /verify');
    assert.equal(settleCalls, 1);

    // Advance chain pointer to a1.txHash
    node.addSetMetadata({ sender: OWNER_A, key: ANCHOR_KEY, value: a1.txHash });

    // 4. Broadcasted entry reconciliation: finalized & succeeded -> promotes to committed without re-broadcast
    const c2 = 'c'.repeat(64);
    const preLandedRd = node.addRegisterData({
        sender: WITNESS_1,
        data: encodeAnchor({ tokenId: TOKEN_ID, toSeq: 2, commitment: Buffer.from(c2, 'hex'), prevAnchorTx: a1.txHash }),
    });
    const sigBcastOk = encodeX402Header({ x402Version: 2, payload: { auth: 'token-bcast-ok' } });
    const pidBcastOk = facVerifier.derivePaymentId(sigBcastOk);
    srv.ledger.claim(pidBcastOk, { tokenId: TOKEN_ID, toSeq: 2, commitment: c2, prevAnchorTx: a1.txHash });
    srv.ledger.markSettled(pidBcastOk, { payer: PAYER_3 });
    srv.ledger.markBroadcast(pidBcastOk, { txHash: preLandedRd.txHash, expiryEpochSeconds: 9999999999 });
    const subsBeforeBcastOk = node.submitted.length;
    const resBcastOk = await fetch(`${srv.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', [HEADER_PAYMENT_SIGNATURE]: sigBcastOk },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 2, commitment: c2, prevAnchorTx: a1.txHash }),
    });
    assert.equal(resBcastOk.status, 200);
    assert.equal(srv.ledger.get(pidBcastOk)?.status, 'committed');
    assert.equal(node.submitted.length, subsBeforeBcastOk);
    node.addSetMetadata({ sender: OWNER_A, key: ANCHOR_KEY, value: preLandedRd.txHash });

    // 5. Broadcasted entry absent before vs after expiry -> 409 then downgrades & re-broadcasts
    const c3 = 'd'.repeat(64);
    const sigAbsent = encodeX402Header({ x402Version: 2, payload: { auth: 'token-absent' } });
    const pidAbsent = facVerifier.derivePaymentId(sigAbsent);
    srv.ledger.claim(pidAbsent, { tokenId: TOKEN_ID, toSeq: 3, commitment: c3, prevAnchorTx: preLandedRd.txHash });
    srv.ledger.markSettled(pidAbsent, { payer: PAYER_3 });
    const curEpochSec = Math.floor(node.timeForHeight(node.state.tipHeight) / 1000);
    srv.ledger.markBroadcast(pidAbsent, { txHash: txHashFor('dropped-rd'), expiryEpochSeconds: curEpochSec + 60 });

    const resInFlight = await fetch(`${srv.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', [HEADER_PAYMENT_SIGNATURE]: sigAbsent },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 3, commitment: c3, prevAnchorTx: preLandedRd.txHash }),
    });
    assert.equal(resInFlight.status, 409);

    node.setTipSlotTimeMs((curEpochSec + 120) * 1000);
    const resRebroadcast = await fetch(`${srv.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', [HEADER_PAYMENT_SIGNATURE]: sigAbsent },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 3, commitment: c3, prevAnchorTx: preLandedRd.txHash }),
    });
    assert.equal(resRebroadcast.status, 200);
    const a3 = await resRebroadcast.json();
    assert.equal(settleCalls, 1, 'expired broadcasted recovery must not re-settle');

    // 6. Orphaned 'claimed' entry in sponsorPointers cleaned up under lock and completes cleanly
    srv.ledger.claimSponsor(TOKEN_ID, a3.txHash, { requestHash: 'stale-hash' });
    const accForSp = await node.getAccountInfo(ownerSigner.sender, blockHashFor(node.state.tipHeight));
    const builtSp = await buildSignedSponsoredSetMetadata({
        tokenId: TOKEN_ID,
        key: ANCHOR_KEY,
        valueUtf8: a3.txHash,
        who: ownerSigner,
        sponsorAddress: WITNESS_1,
        expectedNonce: BigInt(accForSp.accountNonce.value),
        nodeClient: node,
    });
    const spOut = await requestSponsoredPointer({
        witnessUrl: srv.url,
        tokenId: TOKEN_ID,
        anchorTxHash: a3.txHash,
        transactionJson: builtSp.transactionJson,
        allowPrivate: true,
    });
    assert.ok(spOut.metadataTxHash);
    assert.equal(node.state.metadata[ANCHOR_KEY], a3.txHash);
});

test('validateAndSponsorSetMetadata enforces accountCredentials unconditionally and idle fast path invalidates on cleared "" witness', async () => {
    const dir = makeTempDir();
    const ownerSigner = await makeRealSigner(OWNER_A);
    const witnessSigner = await makeRealSigner(WITNESS_1);

    // 1. Unconditional verifySignature: missing accountCredentials rejects even with valid node mock
    const bareNode = createWitnessMockNode({
        owner: OWNER_A,
        accountVerifyKeys: new Map(), // intentionally empty -> no accountCredentials/accountThreshold!
    });
    const tipEpochSec = Math.floor(bareNode.timeForHeight(bareNode.state.tipHeight) / 1000);
    const bareAcc = await bareNode.getNextAccountNonce(ownerSigner.sender);
    const built = await buildSignedSponsoredSetMetadata({
        tokenId: TOKEN_ID,
        key: ANCHOR_KEY,
        valueUtf8: txHashFor('anchor-bare'),
        who: ownerSigner,
        sponsorAddress: WITNESS_1,
        expectedNonce: BigInt(bareAcc.nonce.value),
        expiryEpochSeconds: tipEpochSec + 300,
        nodeClient: bareNode,
    });
    await assert.rejects(
        () =>
            validateAndSponsorSetMetadata({
                transactionJson: built.transactionJson,
                expectedOwner: OWNER_A,
                expectedSponsor: WITNESS_1,
                expectedTokenId: TOKEN_ID,
                expectedKey: ANCHOR_KEY,
                expectedValueUtf8: txHashFor('anchor-bare'),
                sponsorSigner: witnessSigner,
                nodeClient: bareNode,
            }),
        /missing credential keys/i,
    );

    // 2. Idle fast path invalidation across WITNESS_1 -> cleared "" -> cached -> WITNESS_2
    let historyScans = 0;
    const node = createWitnessMockNode({
        owner: OWNER_A,
        accountVerifyKeys: new Map([
            [OWNER_A, ownerSigner.verifyKey],
            [WITNESS_1, witnessSigner.verifyKey],
        ]),
    });
    node.addSetMetadata({ sender: OWNER_A, key: WITNESS_KEY, value: WITNESS_1 });
    const baseGetEvents = node.getBlockTransactionEvents.bind(node);
    node.getBlockTransactionEvents = async function* (bh) {
        historyScans += 1;
        yield* baseGetEvents(bh);
    };

    const srv = await startWitnessServer({
        host: '127.0.0.1',
        port: 0,
        priceMicroCcd: '0',
        signer: witnessSigner,
        ledgerPath: path.join(dir, 'idle-ledger.json'),
        nodeClient: node,
        fetchCard: async () => node.card.bytes,
        log: () => {},
    });
    cleanups.push(() => srv.close());

    const { header, records } = makeTrailFixtures(1);
    const trailPath = path.join(dir, 'idle.jsonl');
    const statePath = path.join(dir, 'idle.state.json');
    writeTrail(trailPath, header, records);

    const worker = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath,
        statePath,
        everyRecords: 100, // won't trigger after seq 1 anchors with --once=false style; use once:true on tick 1
        once: true,
        nodeClient: node,
        signer: ownerSigner,
        witnessUrl: srv.url,
        allowPrivateWitness: true,
        source: () => [],
        log: () => {},
    });
    // Anchor seq 1 while WITNESS_1 active
    worker.everyRecords = 1;
    await worker.tick();
    worker.everyRecords = 100;
    const scansAfterFirst = historyScans;

    // Idle poll -> hits fast path (0 additional history scans)
    await worker.tick();
    assert.equal(historyScans, scansAfterFirst, 'idle poll should use cached _verifiedTip');

    // Clear witness on-chain to "" -> idle fast path MUST invalidate and rescan history!
    node.addSetMetadata({ sender: OWNER_A, key: WITNESS_KEY, value: '' });
    worker.witnessUrl = null;
    await worker.tick();
    assert.ok(historyScans > scansAfterFirst, 'clearing witness to "" must invalidate idle fast path cache');
    const scansAfterClear = historyScans;

    // Subsequent idle poll while cleared "" -> caches cleared witness and skips history scans again
    await worker.tick();
    assert.equal(historyScans, scansAfterClear, 'cleared witness "" should be safely cached on subsequent idle poll');

    // Externally setting WITNESS_2 invalidates idle fast path cache even when witnessUrl is null!
    node.addSetMetadata({ sender: OWNER_A, key: WITNESS_KEY, value: WITNESS_2 });
    await worker.tick();
    assert.ok(historyScans > scansAfterClear, 'external witness activation must invalidate idle fast path even when witnessUrl is null');
});

test('unsigned 402 equivocation 409, facilitator settlement-tx & legacy dedup, withSignerLock revocation 409, and CLI payment recovery hint', async () => {
    const dir = makeTempDir();
    const ownerSigner = await makeRealSigner(OWNER_A);
    const witnessSigner = await makeRealSigner(WITNESS_1);

    // 1. Unsigned 402 equivocation + facilitator settlement-tx dedup (including conflicting binding rejection)
    const node = createWitnessMockNode({
        owner: OWNER_A,
        accountVerifyKeys: new Map([
            [OWNER_A, ownerSigner.verifyKey],
            [WITNESS_1, witnessSigner.verifyKey],
        ]),
    });
    node.addSetMetadata({ sender: OWNER_A, key: WITNESS_KEY, value: WITNESS_1 });

    let currentSettleTx = 'fac-settled-tx-1';
    let facVerifyCalls = 0;
    let facSettleCalls = 0;
    const facSrv = https.createServer({ key: TEST_KEY_PEM, cert: TEST_CERT_PEM }, (req, res) => {
        if (req.url === '/verify') {
            facVerifyCalls += 1;
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ isValid: true, payer: PAYER_3 }));
        } else if (req.url === '/settle') {
            facSettleCalls += 1;
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(
                JSON.stringify({
                    success: true,
                    transaction: currentSettleTx,
                    network: CONCORDIUM_TESTNET_CAIP2,
                    payer: PAYER_3,
                }),
            );
        }
    });
    await new Promise((r) => facSrv.listen(0, '127.0.0.1', r));
    cleanups.push(async () => {
        facSrv.closeAllConnections?.();
        await new Promise((r) => facSrv.close(r));
    });

    const facVerifier = createFacilitatorVerifier({
        facilitatorUrl: `https://127.0.0.1:${facSrv.address().port}`,
        allowPrivate: true,
        ca: Buffer.from(TEST_CERT_PEM),
    });
    const facLedgerPath = path.join(dir, 'fac-dedup-ledger.json');
    const srv = await startWitnessServer({
        host: '127.0.0.1',
        port: 0,
        signer: witnessSigner,
        ledgerPath: facLedgerPath,
        nodeClient: node,
        verifier: facVerifier,
        fetchCard: async () => node.card.bytes,
        log: () => {},
    });
    cleanups.push(() => srv.close());

    const commitA = 'a'.repeat(64);
    const commitB = 'b'.repeat(64);
    const sigA1 = encodeX402Header({ x402Version: 2, payload: { envelope: 'A1' } });
    const sigA2 = encodeX402Header({ x402Version: 2, payload: { envelope: 'A2' } });
    const sigConflict = encodeX402Header({ x402Version: 2, payload: { envelope: 'A3' } });

    const r1 = await fetch(`${srv.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', [HEADER_PAYMENT_SIGNATURE]: sigA1 },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 1, commitment: commitA, prevAnchorTx: null }),
    });
    assert.equal(r1.status, 200);
    const b1 = await r1.json();
    const rdAfterR1 = node.submitted.filter((t) => t.payload.type === AccountTransactionType.RegisterData).length;
    assert.equal(rdAfterR1, 1);

    // Distinct envelope settling to same transaction MUST return cached 200 without second RegisterData broadcast
    const r2 = await fetch(`${srv.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', [HEADER_PAYMENT_SIGNATURE]: sigA2 },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 1, commitment: commitA, prevAnchorTx: null }),
    });
    assert.equal(r2.status, 200);
    const b2 = await r2.json();
    assert.equal(b2.txHash, b1.txHash);
    assert.equal(decodeX402Header(r2.headers.get(HEADER_PAYMENT_RESPONSE)).cached, true);
    assert.equal(node.submitted.filter((t) => t.payload.type === AccountTransactionType.RegisterData).length, 1);

    // Unsigned POST for a conflicting commitment at the same predecessor MUST reject 409 BEFORE issuing 402
    const unsignedEq = await fetch(`${srv.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 1, commitment: commitB, prevAnchorTx: null }),
    });
    assert.equal(unsignedEq.status, 409);
    const unsignedEqBody = await unsignedEq.json();
    assert.match(unsignedEqBody.error, /equivocating anchor request/i);
    await srv.close();

    // Restart witness server on the same ledger and retry sigA2 -> recovers cached 200 via persisted alias with 0 facilitator calls
    const srvRestarted = await startWitnessServer({
        host: '127.0.0.1',
        port: 0,
        signer: witnessSigner,
        ledgerPath: facLedgerPath,
        nodeClient: node,
        verifier: facVerifier,
        fetchCard: async () => node.card.bytes,
        log: () => {},
    });
    cleanups.push(() => srvRestarted.close());
    facVerifyCalls = 0;
    facSettleCalls = 0;
    const r2Retry = await fetch(`${srvRestarted.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', [HEADER_PAYMENT_SIGNATURE]: sigA2 },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 1, commitment: commitA, prevAnchorTx: null }),
    });
    assert.equal(r2Retry.status, 200);
    const b2Retry = await r2Retry.json();
    assert.equal(b2Retry.txHash, b1.txHash);
    assert.equal(decodeX402Header(r2Retry.headers.get(HEADER_PAYMENT_RESPONSE)).cached, true);
    assert.equal(facVerifyCalls, 0, 'persisted payment alias must recover locally without /verify');
    assert.equal(facSettleCalls, 0, 'persisted payment alias must recover locally without /settle');

    // Move ANCHOR_KEY forward and send a different binding whose /settle returns the same settled transaction -> 409,
    // without releasing the original committed entry or persisting a conflicting alias
    node.addSetMetadata({ sender: OWNER_A, key: ANCHOR_KEY, value: b1.txHash });
    const rConflict = await fetch(`${srvRestarted.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', [HEADER_PAYMENT_SIGNATURE]: sigConflict },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 2, commitment: commitB, prevAnchorTx: b1.txHash }),
    });
    assert.equal(rConflict.status, 409);
    assert.equal(node.submitted.filter((t) => t.payload.type === AccountTransactionType.RegisterData).length, 1);
    const persistedFacLedger = JSON.parse(fs.readFileSync(facLedgerPath, 'utf8'));
    assert.equal(Object.keys(persistedFacLedger.paymentAliases).length, 1, 'only matching alias sigA2->sigA1 should be persisted');
    await srvRestarted.close();

    // 2. Legacy facilitator:<network>:<transaction> ledger key dedup on retry after upgrade
    const legacyNode = createWitnessMockNode({
        owner: OWNER_A,
        accountVerifyKeys: new Map([
            [OWNER_A, ownerSigner.verifyKey],
            [WITNESS_1, witnessSigner.verifyKey],
        ]),
    });
    legacyNode.addSetMetadata({ sender: OWNER_A, key: WITNESS_KEY, value: WITNESS_1 });
    const legacyTxHash = txHashFor('legacy-anchor-rd');
    const legacyKey = `facilitator:${CONCORDIUM_TESTNET_CAIP2}:fac-legacy-99`;
    const legacyLedgerPath = path.join(dir, 'legacy-ledger.json');
    fs.writeFileSync(
        legacyLedgerPath,
        JSON.stringify({
            version: 1,
            payments: {
                [legacyKey]: {
                    paymentId: legacyKey,
                    status: 'committed',
                    binding: { tokenId: TOKEN_ID, toSeq: 1, commitment: commitA, prevAnchorTx: null },
                    settled: { payer: PAYER_3, transaction: 'fac-legacy-99', network: CONCORDIUM_TESTNET_CAIP2 },
                    txHash: legacyTxHash,
                    expiryEpochSeconds: null,
                    result: {
                        txHash: legacyTxHash,
                        witnessAccount: WITNESS_1,
                        blockTime: '2023-11-14T22:13:20.000Z',
                        blockHeight: 1500,
                        sponsorAvailable: true,
                    },
                    createdAt: new Date().toISOString(),
                    updatedAt: new Date().toISOString(),
                },
            },
            sponsorPointers: {},
        }) + '\n',
        { mode: 0o600 },
    );
    currentSettleTx = 'fac-legacy-99';
    const legacySrv = await startWitnessServer({
        host: '127.0.0.1',
        port: 0,
        signer: witnessSigner,
        ledgerPath: legacyLedgerPath,
        nodeClient: legacyNode,
        verifier: facVerifier,
        fetchCard: async () => legacyNode.card.bytes,
        log: () => {},
    });
    cleanups.push(() => legacySrv.close());

    const rLegacy = await fetch(`${legacySrv.url}/v1/anchor`, {
        method: 'POST',
        headers: {
            'content-type': 'application/json',
            [HEADER_PAYMENT_SIGNATURE]: encodeX402Header({ x402Version: 2, payload: { upgrade: 1 } }),
        },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 1, commitment: commitA, prevAnchorTx: null }),
    });
    assert.equal(rLegacy.status, 200);
    const bLegacy = await rLegacy.json();
    assert.equal(bLegacy.txHash, legacyTxHash);
    assert.equal(decodeX402Header(rLegacy.headers.get(HEADER_PAYMENT_RESPONSE)).cached, true);
    assert.equal(legacyNode.submitted.filter((t) => t.payload.type === AccountTransactionType.RegisterData).length, 0);
    await legacySrv.close();

    // 3. Witness cleared while second token waits in withSignerLock -> 409 and 0 RegisterData broadcasts for revoked token
    const TOKEN_2 = '1316';
    const baseRevNode = createWitnessMockNode({
        owner: OWNER_A,
        accountVerifyKeys: new Map([
            [OWNER_A, ownerSigner.verifyKey],
            [WITNESS_1, witnessSigner.verifyKey],
        ]),
    });
    baseRevNode.addSetMetadata({ sender: OWNER_A, key: WITNESS_KEY, value: WITNESS_1 });
    const card2 = makeCardBytes({ badge: encodeBadge(TOKEN_2), ownerAccount: OWNER_A });
    const agent2 = {
        tokenId: TOKEN_2,
        ownerAccount: OWNER_A,
        agentUri: 'https://agent2.example/card.json',
        metadataHashHex: card2.hashHex,
        status: 'Active',
        registeredAtMs: baseRevNode.timeForHeight(1000n),
    };
    const meta2 = { 'unitares.agent_uuid': AGENT_UUID, [WITNESS_KEY]: WITNESS_1 };
    baseRevNode.state.txsByHeight.get(1000n).push({
        height: 1000n,
        hash: txHashFor('mint-rev-2'),
        sender: OWNER_A,
        contractEvents: [evMint(TOKEN_2, OWNER_A), evMetadataSet(TOKEN_2, WITNESS_KEY, WITNESS_1)],
    });

    let enterFirstRd;
    const enteredFirstRd = new Promise((r) => {
        enterFirstRd = r;
    });
    let releaseFirstRd;
    const holdFirstRd = new Promise((r) => {
        releaseFirstRd = r;
    });
    let holdOnce = true;
    const revNode = Object.assign(Object.create(baseRevNode), {
        async invokeContract(ctx, bh) {
            const method = ctx.method.value ?? String(ctx.method);
            const p = Buffer.from(ctx.parameter.buffer);
            const reqTid = p.length >= 9 ? p.readBigUInt64LE(1).toString() : null;
            if (reqTid === TOKEN_2) {
                if (method === 'CIS-8004.agentOf') {
                    return {
                        tag: 'success',
                        usedEnergy: { value: 1000n },
                        returnValue: ReturnValue.fromBuffer(encodeAgentOfReturn(agent2)),
                    };
                }
                if (method === 'CIS-8004.getMetadata') {
                    const klen = p.readUInt32LE(9);
                    const key = p.subarray(13, 13 + klen).toString('utf8');
                    return {
                        tag: 'success',
                        usedEnergy: { value: 1000n },
                        returnValue: ReturnValue.fromBuffer(encodeGetMetadataReturn(meta2[key] ?? null)),
                    };
                }
            }
            return baseRevNode.invokeContract(ctx, bh);
        },
        async sendTransaction(finalized) {
            if (finalized.payload.type === AccountTransactionType.RegisterData && holdOnce) {
                holdOnce = false;
                enterFirstRd();
                await holdFirstRd;
            }
            return baseRevNode.sendTransaction(finalized);
        },
    });

    let t1Verified;
    const t1VerifiedPromise = new Promise((r) => {
        t1Verified = r;
    });
    const revSrv = await startWitnessServer({
        host: '127.0.0.1',
        port: 0,
        priceMicroCcd: '0',
        signer: witnessSigner,
        ledgerPath: path.join(dir, 'rev-ledger.json'),
        nodeClient: revNode,
        verifier: {
            async verify({ header }) {
                const env = decodeX402Header(header);
                if (env.payload.id === 'pay-t1') t1Verified();
                return { paymentId: env.payload.id, payer: PAYER_3 };
            },
        },
        fetchCard: async (uri) => (uri.includes('agent2') ? card2.bytes : baseRevNode.card.bytes),
        log: () => {},
    });
    cleanups.push(() => revSrv.close());

    const pT2 = fetch(`${revSrv.url}/v1/anchor`, {
        method: 'POST',
        headers: {
            'content-type': 'application/json',
            [HEADER_PAYMENT_SIGNATURE]: encodeX402Header({ x402Version: 2, payload: { id: 'pay-t2' } }),
        },
        body: JSON.stringify({ tokenId: TOKEN_2, toSeq: 1, commitment: commitA, prevAnchorTx: null }),
    });
    await enteredFirstRd;

    const pT1 = fetch(`${revSrv.url}/v1/anchor`, {
        method: 'POST',
        headers: {
            'content-type': 'application/json',
            [HEADER_PAYMENT_SIGNATURE]: encodeX402Header({ x402Version: 2, payload: { id: 'pay-t1' } }),
        },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 1, commitment: commitB, prevAnchorTx: null }),
    });
    await t1VerifiedPromise;
    await new Promise((r) => setTimeout(r, 20));
    revNode.addSetMetadata({ sender: OWNER_A, key: WITNESS_KEY, value: '' });
    releaseFirstRd();

    const [resRevT2, resRevT1] = await Promise.all([pT2, pT1]);
    assert.equal(resRevT2.status, 200);
    assert.equal(resRevT1.status, 409);
    assert.match((await resRevT1.json()).error, /witness authorization changed/i);
    assert.equal(baseRevNode.submitted.filter((t) => t.payload.type === AccountTransactionType.RegisterData).length, 1);
    await revSrv.close();

    // 4. cli.mjs anchor preserves retry --payment-signature hint when verifyWitnessAnchorOnChain throws
    const cliNode = createWitnessMockNode({
        owner: OWNER_A,
        accountVerifyKeys: new Map([
            [OWNER_A, ownerSigner.verifyKey],
            [WITNESS_1, witnessSigner.verifyKey],
        ]),
    });
    cliNode.addSetMetadata({ sender: OWNER_A, key: WITNESS_KEY, value: WITNESS_1 });
    const cliFixtures = makeTrailFixtures(1);
    const cliTrail = path.join(dir, 'cli-recovery.jsonl');
    writeTrail(cliTrail, cliFixtures.header, cliFixtures.records);

    const errLogs = [];
    const origConsoleError = console.error;
    console.error = (...args) => errLogs.push(args.map(String).join(' '));
    try {
        await assert.rejects(
            () =>
                commands.anchor({
                    trail: cliTrail,
                    state: path.join(dir, 'cli-recovery.state.json'),
                    who: ownerSigner,
                    nodeClient: cliNode,
                    witnessUrl: 'https://witness.example',
                    maxPriceMicroCcd: '1000000',
                    fetchWitnessHealthFn: async () => ({
                        witnessAccount: WITNESS_1,
                        payTo: WITNESS_1,
                        priceMicroCcd: '1000',
                        sponsorPointer: false,
                    }),
                    requestWitnessAnchorFn: async ({ payFn, tokenId, toSeq, commitment, prevAnchorTx }) => {
                        const prReq = createPaymentRequirements({
                            payTo: WITNESS_1,
                            amountMicroCcd: '1000',
                            resource: 'https://witness.example/v1/anchor',
                            tokenId,
                            toSeq,
                            commitment,
                            prevAnchorTx,
                            witnessAccount: WITNESS_1,
                        }).accepts[0];
                        await payFn(prReq);
                        return { txHash: 'f'.repeat(64) };
                    },
                }),
            /absent|not finalized|not found|registerData/i,
        );
    } finally {
        console.error = origConsoleError;
    }
    assert.equal(cliNode.submitted.length, 1, 'payment transfer must have been sent before verification failure');
    assert.ok(
        errLogs.some((line) => /witness request failed after payment .* finalized; retry with --payment-signature [A-Za-z0-9+/=_-]+/.test(line)),
        `expected recovery hint in stderr, got: ${errLogs.join('\n')}`,
    );

    // 5. close() aborts incomplete body uploads instead of hanging forever while keeping the ledger locked
    const uploadLedgerPath = path.join(dir, 'upload-abort-ledger.json');
    const uploadSrv = await startWitnessServer({
        host: '127.0.0.1',
        port: 0,
        priceMicroCcd: '0',
        signer: witnessSigner,
        ledgerPath: uploadLedgerPath,
        nodeClient: node,
        fetchCard: async () => node.card.bytes,
        log: () => {},
    });
    cleanups.push(() => uploadSrv.close());

    let markUploadSeen;
    const uploadSeen = new Promise((r) => {
        markUploadSeen = r;
    });
    uploadSrv.server.once('request', markUploadSeen);
    const partialReq = http.request(`${uploadSrv.url}/v1/anchor`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'content-length': '120' },
    });
    partialReq.on('error', () => {});
    partialReq.write('{"tokenId":');
    await uploadSeen;
    await new Promise((r) => setTimeout(r, 15));

    let hangTimer;
    try {
        await Promise.race([
            uploadSrv.close(),
            new Promise((_, reject) => {
                hangTimer = setTimeout(() => reject(new Error('close() hung on incomplete upload')), 1000);
            }),
        ]);
    } finally {
        clearTimeout(hangTimer);
        partialReq.destroy();
    }

    const uploadSrvReopen = await startWitnessServer({
        host: '127.0.0.1',
        port: 0,
        priceMicroCcd: '0',
        signer: witnessSigner,
        ledgerPath: uploadLedgerPath,
        nodeClient: node,
        fetchCard: async () => node.card.bytes,
        log: () => {},
    });
    cleanups.push(() => uploadSrvReopen.close());
    await uploadSrvReopen.close();

    // 6. Tip advancement during withSignerLock auth checks triggers fresh-tip recheck -> 409 with 0 broadcasts
    let armedTipRace = false;
    let tipRaced = false;
    const baseTipNode = createWitnessMockNode({
        owner: OWNER_A,
        accountVerifyKeys: new Map([
            [OWNER_A, ownerSigner.verifyKey],
            [WITNESS_1, witnessSigner.verifyKey],
        ]),
    });
    baseTipNode.addSetMetadata({ sender: OWNER_A, key: WITNESS_KEY, value: WITNESS_1 });
    const baseTipHeightStr = `block-${baseTipNode.state.tipHeight}`;
    const racedAnchorHash = txHashFor('raced-anchor-after-bcast-tip');
    const tipRaceNode = Object.assign(Object.create(baseTipNode), {
        async invokeContract(ctx, bh) {
            const method = ctx.method.value ?? String(ctx.method);
            if (method === 'CIS-8004.getMetadata') {
                const p = Buffer.from(ctx.parameter.buffer);
                const klen = p.readUInt32LE(9);
                const key = p.subarray(13, 13 + klen).toString('utf8');
                if (armedTipRace && key === WITNESS_KEY && String(bh) === baseTipHeightStr) {
                    armedTipRace = false;
                    tipRaced = true;
                    baseTipNode.state.tipHeight += 1n;
                }
                if (key === ANCHOR_KEY) {
                    const anchorVal = String(bh) === baseTipHeightStr ? null : tipRaced ? racedAnchorHash : null;
                    return {
                        tag: 'success',
                        usedEnergy: { value: 1000n },
                        returnValue: ReturnValue.fromBuffer(encodeGetMetadataReturn(anchorVal)),
                    };
                }
            }
            return baseTipNode.invokeContract(ctx, bh);
        },
    });

    const tipRaceSrv = await startWitnessServer({
        host: '127.0.0.1',
        port: 0,
        priceMicroCcd: '0',
        signer: witnessSigner,
        ledgerPath: path.join(dir, 'tip-race-ledger.json'),
        nodeClient: tipRaceNode,
        verifier: {
            async verify() {
                armedTipRace = true;
                return { paymentId: 'tip-race-pay-1', payer: PAYER_3 };
            },
        },
        fetchCard: async () => baseTipNode.card.bytes,
        log: () => {},
    });
    cleanups.push(() => tipRaceSrv.close());

    const rTipRace = await fetch(`${tipRaceSrv.url}/v1/anchor`, {
        method: 'POST',
        headers: {
            'content-type': 'application/json',
            [HEADER_PAYMENT_SIGNATURE]: encodeX402Header({ x402Version: 2, payload: { race: 1 } }),
        },
        body: JSON.stringify({ tokenId: TOKEN_ID, toSeq: 1, commitment: commitA, prevAnchorTx: null }),
    });
    assert.equal(rTipRace.status, 409);
    assert.match((await rTipRace.json()).error, /moved concurrently/i);
    assert.equal(tipRaced, true, 'test should have simulated tip advancement during withSignerLock checks');
    assert.equal(baseTipNode.submitted.filter((t) => t.payload.type === AccountTransactionType.RegisterData).length, 0);
    await tipRaceSrv.close();

    // 7. HTTP/1.1 pipelined partial upload behind in-flight Req 1 aborts reader without dropping Req 1's 200 response
    const basePipeNode = createWitnessMockNode({
        owner: OWNER_A,
        accountVerifyKeys: new Map([
            [OWNER_A, ownerSigner.verifyKey],
            [WITNESS_1, witnessSigner.verifyKey],
        ]),
    });
    basePipeNode.addSetMetadata({ sender: OWNER_A, key: WITNESS_KEY, value: WITNESS_1 });

    let enterPipeReq1;
    const enteredPipeReq1 = new Promise((r) => {
        enterPipeReq1 = r;
    });
    let releasePipeReq1;
    const holdPipeReq1 = new Promise((r) => {
        releasePipeReq1 = r;
    });
    const pipeNode = Object.assign(Object.create(basePipeNode), {
        async sendTransaction(finalized) {
            if (finalized.payload.type === AccountTransactionType.RegisterData) {
                enterPipeReq1();
                await holdPipeReq1;
            }
            return basePipeNode.sendTransaction(finalized);
        },
    });
    const pipeLedgerPath = path.join(dir, 'pipe-ledger.json');
    const pipeSrv = await startWitnessServer({
        host: '127.0.0.1',
        port: 0,
        priceMicroCcd: '0',
        signer: witnessSigner,
        ledgerPath: pipeLedgerPath,
        nodeClient: pipeNode,
        verifier: { async verify() { return { paymentId: 'pipe-pay-1', payer: PAYER_3 }; } },
        fetchCard: async () => basePipeNode.card.bytes,
        log: () => {},
    });
    cleanups.push(() => pipeSrv.close());

    let pipeReqCount = 0;
    let markReq2Seen;
    const req2Seen = new Promise((r) => {
        markReq2Seen = r;
    });
    pipeSrv.server.on('request', () => {
        pipeReqCount += 1;
        if (pipeReqCount >= 2) markReq2Seen();
    });

    const pipeSock = net.connect(pipeSrv.port, '127.0.0.1');
    cleanups.push(() => pipeSock.destroy());
    let pipeReceived = '';
    pipeSock.on('data', (chunk) => {
        pipeReceived += chunk.toString('utf8');
    });
    const pipeSockClosed = new Promise((r) => pipeSock.once('close', r));

    const withTimeout = async (promise, ms, label) => {
        let timerId;
        try {
            return await Promise.race([
                promise,
                new Promise((_, reject) => {
                    timerId = setTimeout(() => reject(new Error(`timed out waiting for ${label} after ${ms}ms`)), ms);
                }),
            ]);
        } finally {
            clearTimeout(timerId);
        }
    };

    const bodyPipe1 = JSON.stringify({ tokenId: TOKEN_ID, toSeq: 1, commitment: commitA, prevAnchorTx: null });
    const sigPipe1 = encodeX402Header({ x402Version: 2, payload: { pipe: 1 } });
    let pipeCloseSettled = false;
    try {
        pipeSock.write(
            `POST /v1/anchor HTTP/1.1\r\n` +
                `Host: 127.0.0.1:${pipeSrv.port}\r\n` +
                `Content-Type: application/json\r\n` +
                `${HEADER_PAYMENT_SIGNATURE}: ${sigPipe1}\r\n` +
                `Content-Length: ${Buffer.byteLength(bodyPipe1)}\r\n\r\n` +
                bodyPipe1 +
                `POST /v1/anchor HTTP/1.1\r\n` +
                `Host: 127.0.0.1:${pipeSrv.port}\r\n` +
                `Content-Type: application/json\r\n` +
                `Content-Length: 120\r\n\r\n` +
                `{"tokenId":`,
        );

        await withTimeout(enteredPipeReq1, 1500, 'enteredPipeReq1');
        await withTimeout(req2Seen, 1500, 'req2Seen');
        await new Promise((r) => setTimeout(r, 20));

        const pipeCloseP = pipeSrv.close().then(() => {
            pipeCloseSettled = true;
        });
        await new Promise((r) => setTimeout(r, 20));
        assert.equal(pipeCloseSettled, false, 'close() must still wait for pipelined Req 1 to finish committing');

        releasePipeReq1();
        await withTimeout(pipeCloseP, 1500, 'pipeSrv.close');
        await withTimeout(pipeSockClosed, 1500, 'pipeSockClosed');
    } finally {
        releasePipeReq1();
        pipeSock.destroy();
    }

    const pipeLedgerEntry = JSON.parse(fs.readFileSync(pipeLedgerPath, 'utf8')).payments['pipe-pay-1'];
    assert.equal(pipeLedgerEntry?.status, 'committed');
    assert.ok(pipeReceived.startsWith('HTTP/1.1 200 '), `expected HTTP 200 response for Req 1, got: ${pipeReceived}`);
    assert.ok(pipeReceived.includes(pipeLedgerEntry.txHash), 'pipelined Req 1 client must receive committed txHash before close');

    // 8. PaymentLedger enforces alias claim invariants and rolls back in-memory alias on _persist() failure
    const aliasUnitPath = path.join(dir, 'alias-unit-ledger.json');
    const unitLedger = new PaymentLedger(aliasUnitPath);
    const unitBindingA = { tokenId: TOKEN_ID, toSeq: 1, commitment: commitA, prevAnchorTx: null };
    const unitBindingB = { tokenId: TOKEN_ID, toSeq: 1, commitment: commitB, prevAnchorTx: null };
    const canonTxHash = txHashFor('canon-rd-unit');
    assert.equal(unitLedger.claim('pay-canon', unitBindingA).action, 'proceed');
    unitLedger.markSettled('pay-canon', { payer: PAYER_3, transaction: 'tx-canon', network: CONCORDIUM_TESTNET_CAIP2 });
    unitLedger.commit('pay-canon', { txHash: canonTxHash, witnessAccount: WITNESS_1 });
    unitLedger.recordAlias('pay-alias-1', 'pay-canon');

    const aliasClaimSame = unitLedger.claim('pay-alias-1', unitBindingA);
    assert.equal(aliasClaimSame.action, 'return_cached');
    assert.equal(aliasClaimSame.entry.paymentId, 'pay-canon');
    assert.equal(unitLedger.payments.size, 1, 'claiming aliased ID must not insert a duplicate entry');
    assert.throws(() => unitLedger.claim('pay-alias-1', unitBindingB), { statusCode: 409 });
    assert.equal(unitLedger.payments.size, 1);

    unitLedger._persist = () => {
        throw new Error('simulated disk full');
    };
    assert.throws(() => unitLedger.recordAlias('pay-alias-fail', 'pay-canon'), /simulated disk full/);
    assert.equal(unitLedger.paymentAliases.has('pay-alias-fail'), false, 'failed _persist must roll back in-memory alias');
    assert.equal(unitLedger.resolvePaymentId('pay-alias-fail'), 'pay-alias-fail');
    delete unitLedger._persist;
    unitLedger.recordAlias('pay-alias-fail', 'pay-canon');
    assert.equal(unitLedger.resolvePaymentId('pay-alias-fail'), 'pay-canon');
    assert.equal(JSON.parse(fs.readFileSync(aliasUnitPath, 'utf8')).paymentAliases['pay-alias-fail'], 'pay-canon');

    // 9. Queued async Req 2 entering finally flush-wait during close() unblocks promptly on socket close (real TCP + Node 22/24 detached-socket simulation)
    const basePipe2Node = createWitnessMockNode({
        owner: OWNER_A,
        accountVerifyKeys: new Map([
            [OWNER_A, ownerSigner.verifyKey],
            [WITNESS_1, witnessSigner.verifyKey],
        ]),
    });
    basePipe2Node.addSetMetadata({ sender: OWNER_A, key: WITNESS_KEY, value: WITNESS_1 });
    let enterPipe2Req1;
    const enteredPipe2Req1 = new Promise((r) => {
        enterPipe2Req1 = r;
    });
    let releasePipe2Req1;
    const holdPipe2Req1 = new Promise((r) => {
        releasePipe2Req1 = r;
    });
    let enterPipe2Req2;
    const enteredPipe2Req2 = new Promise((r) => {
        enterPipe2Req2 = r;
    });
    let releasePipe2Req2;
    const holdPipe2Req2 = new Promise((r) => {
        releasePipe2Req2 = r;
    });
    const pipe2Node = Object.assign(Object.create(basePipe2Node), {
        async invokeContract(ctx, bh) {
            const p = Buffer.from(ctx.parameter.buffer);
            const reqTid = p.length >= 9 ? p.readBigUInt64LE(1).toString() : null;
            if (reqTid === '9999') {
                enterPipe2Req2();
                await holdPipe2Req2;
            }
            return basePipe2Node.invokeContract(ctx, bh);
        },
        async sendTransaction(finalized) {
            if (finalized.payload.type === AccountTransactionType.RegisterData) {
                enterPipe2Req1();
                await holdPipe2Req1;
            }
            return basePipe2Node.sendTransaction(finalized);
        },
    });
    const pipe2LedgerPath = path.join(dir, 'pipe2-ledger.json');
    const pipe2Srv = await startWitnessServer({
        host: '127.0.0.1',
        port: 0,
        priceMicroCcd: '0',
        signer: witnessSigner,
        ledgerPath: pipe2LedgerPath,
        nodeClient: pipe2Node,
        verifier: { async verify() { return { paymentId: 'pipe2-pay-1', payer: PAYER_3 }; } },
        fetchCard: async () => basePipe2Node.card.bytes,
        log: () => {},
    });
    cleanups.push(() => pipe2Srv.close());

    const pipe2Req2Body = JSON.stringify({
        tokenId: '9999',
        anchorTxHash: txHashFor('pipe2-req2'),
        transactionJson: '{}',
    });
    let markReq2FlushWait;
    const req2FlushWaitInstalled = new Promise((r) => {
        markReq2FlushWait = r;
    });
    let pipe2Req2Res = null;
    pipe2Srv.server.on('request', (req, res) => {
        if (req.url === '/v1/sponsor-pointer') {
            pipe2Req2Res = res;
            res.on('newListener', (eventName) => {
                if (eventName === 'finish' && res.headersSent && !res.writableFinished) {
                    markReq2FlushWait();
                }
            });
        }
    });
    const pipe2Sock = net.connect(pipe2Srv.port, '127.0.0.1');
    cleanups.push(() => pipe2Sock.destroy());
    try {
        pipe2Sock.write(
            `POST /v1/anchor HTTP/1.1\r\n` +
                `Host: 127.0.0.1:${pipe2Srv.port}\r\n` +
                `Content-Type: application/json\r\n` +
                `${HEADER_PAYMENT_SIGNATURE}: ${encodeX402Header({ x402Version: 2, payload: { pipe2: 1 } })}\r\n` +
                `Content-Length: ${Buffer.byteLength(bodyPipe1)}\r\n\r\n` +
                bodyPipe1 +
                `POST /v1/sponsor-pointer HTTP/1.1\r\n` +
                `Host: 127.0.0.1:${pipe2Srv.port}\r\n` +
                `Content-Type: application/json\r\n` +
                `Content-Length: ${Buffer.byteLength(pipe2Req2Body)}\r\n\r\n` +
                pipe2Req2Body,
        );

        await withTimeout(enteredPipe2Req1, 1500, 'enteredPipe2Req1');
        await withTimeout(enteredPipe2Req2, 1500, 'enteredPipe2Req2');
        const close2P = pipe2Srv.close();
        releasePipe2Req2();
        await withTimeout(req2FlushWaitInstalled, 1500, 'req2FlushWaitInstalled');
        assert.equal(pipe2Req2Res?.headersSent, true);
        assert.equal(pipe2Req2Res?.writableFinished, false);
        pipe2Sock.destroy();
        await new Promise((r) => setTimeout(r, 20));
        releasePipe2Req1();
        await withTimeout(close2P, 1500, 'pipe2Srv.close');
    } finally {
        releasePipe2Req2();
        releasePipe2Req1();
        pipe2Sock.destroy();
    }

    const pipe2Reopen = await startWitnessServer({
        host: '127.0.0.1',
        port: 0,
        priceMicroCcd: '0',
        signer: witnessSigner,
        ledgerPath: pipe2LedgerPath,
        nodeClient: basePipe2Node,
        fetchCard: async () => basePipe2Node.card.bytes,
        log: () => {},
    });
    cleanups.push(() => pipe2Reopen.close());
    await pipe2Reopen.close();

    // Detached-socket simulation (Node 22/24 behavior where queued res lacks socket & never emits finish/close)
    const detachedLedgerPath = path.join(dir, 'detached-ledger.json');
    let enterDetached;
    const enteredDetached = new Promise((r) => {
        enterDetached = r;
    });
    let rejectDetached;
    const holdDetached = new Promise((_, reject) => {
        rejectDetached = reject;
    });
    holdDetached.catch(() => {});
    const detachedSrv = await createWitnessServer({
        host: '127.0.0.1',
        port: 0,
        priceMicroCcd: '0',
        signer: witnessSigner,
        ledgerPath: detachedLedgerPath,
        nodeClient: basePipe2Node,
        fetchCard: async () => {
            enterDetached();
            await holdDetached;
            return basePipe2Node.card.bytes;
        },
        log: () => {},
    });
    cleanups.push(() => detachedSrv.close());

    const fakeSock = Object.assign(new EventEmitter(), {
        destroyed: false,
        closed: false,
        destroy() {
            this.destroyed = true;
        },
    });
    const fakeReq = Object.assign(new EventEmitter(), {
        method: 'POST',
        url: '/v1/anchor',
        headers: { 'content-type': 'application/json' },
        complete: true,
        socket: fakeSock,
        destroy() {},
    });
    const fakeRes = Object.assign(new EventEmitter(), {
        headersSent: false,
        writableEnded: false,
        writableFinished: false,
        destroyed: false,
        socket: null,
        writeHead() {
            this.headersSent = true;
        },
        end() {
            this.writableEnded = true;
        },
    });

    let dCloseSettled = false;
    try {
        detachedSrv.server.emit('request', fakeReq, fakeRes);
        fakeReq.emit('data', Buffer.from(bodyPipe1, 'utf8'));
        fakeReq.emit('end');
        await withTimeout(enteredDetached, 1500, 'enteredDetached');
        const dCloseP = detachedSrv.close().then(() => {
            dCloseSettled = true;
        });
        rejectDetached(new Error('card fetch failed during close'));
        await new Promise((r) => setTimeout(r, 20));
        assert.equal(dCloseSettled, false, 'detached response should still be awaited while original socket is open');
        fakeSock.destroyed = true;
        fakeSock.closed = true;
        fakeSock.emit('close');
        await withTimeout(dCloseP, 1000, 'detachedSrv.close');
        assert.equal(dCloseSettled, true);
    } finally {
        rejectDetached(new Error('cleanup'));
        fakeSock.destroyed = true;
        fakeSock.closed = true;
        fakeSock.emit('close');
    }

    const detachedReopen = await startWitnessServer({
        host: '127.0.0.1',
        port: 0,
        priceMicroCcd: '0',
        signer: witnessSigner,
        ledgerPath: detachedLedgerPath,
        nodeClient: basePipe2Node,
        fetchCard: async () => basePipe2Node.card.bytes,
        log: () => {},
    });
    cleanups.push(() => detachedReopen.close());
    await detachedReopen.close();
});

test('witness rotation clears stale-signer pendingAnchor safely without wedging and set-witness honors token lock & pending state guards', async () => {
    const dir = makeTempDir();
    const tokenLockDir = makeTempDir();
    const ownerSigner = await makeRealSigner(OWNER_A);
    const witnessSigner = await makeRealSigner(WITNESS_1);
    const thirdPartySigner = await makeRealSigner(PAYER_3);

    const node = createWitnessMockNode({
        owner: OWNER_A,
        accountVerifyKeys: new Map([
            [OWNER_A, ownerSigner.verifyKey],
            [WITNESS_1, witnessSigner.verifyKey],
            [PAYER_3, thirdPartySigner.verifyKey],
        ]),
    });

    const srv = await startWitnessServer({
        host: '127.0.0.1',
        port: 0,
        priceMicroCcd: '0',
        signer: witnessSigner,
        ledgerPath: path.join(dir, 'rotate-ledger.json'),
        nodeClient: node,
        fetchCard: async () => node.card.bytes,
        log: () => {},
    });
    cleanups.push(() => srv.close());

    const { header, records } = makeTrailFixtures(3);
    const tPath = path.join(dir, 'rotate.jsonl');
    const sPath = path.join(dir, 'rotate.state.json');
    const ppStatePath = path.join(dir, 'pp-guard.state.json');
    writeTrail(tPath, header, records.slice(0, 1));

    const c1 = commitments(header, records.slice(0, 1)).last;
    const ownerRd1 = await sendRegisterData(
        encodeAnchor({ tokenId: TOKEN_ID, toSeq: 1, commitment: c1, prevAnchorTx: null }),
        ownerSigner,
        node,
    );
    fs.writeFileSync(
        sPath,
        JSON.stringify({
            version: 1,
            tokenId: TOKEN_ID,
            agentUuid: AGENT_UUID,
            lastAnchoredSeq: 0,
            lastAnchoredTxHash: null,
            lastAnchoredCommitment: null,
            lastAnchoredAt: null,
            pendingAnchor: {
                txHash: ownerRd1.hash,
                toSeq: 1,
                commitment: c1.toString('hex'),
                prevAnchorTx: null,
                sender: OWNER_A,
                expiryEpochSeconds: Math.floor(Date.now() / 1000) + 300,
            },
            pendingPayment: null,
        }) + '\n',
        { mode: 0o600 },
    );

    // 1. set-witness rejects when pendingAnchor or pendingPayment exists in guarded state file
    await assert.rejects(
        () =>
            commands['set-witness']({
                token: TOKEN_ID,
                witness: WITNESS_1,
                trail: tPath,
                state: sPath,
                who: ownerSigner,
                nodeClient: node,
                tokenLockDir,
            }),
        /pending anchor .* exists.*countersign set-witness/,
    );
    fs.writeFileSync(
        ppStatePath,
        JSON.stringify({
            version: 1,
            pendingPayment: { paymentTxHash: txHashFor('pp-set-witness'), witnessUrl: srv.url },
        }) + '\n',
        { mode: 0o600 },
    );
    await assert.rejects(
        () =>
            commands['set-witness']({
                token: TOKEN_ID,
                witness: WITNESS_1,
                state: ppStatePath,
                who: ownerSigner,
                nodeClient: node,
                tokenLockDir,
            }),
        /pending payment .* exists.*countersign watch --once --witness-url/,
    );

    // 2. set-witness acquires token lock and rejects concurrent in-process lock holder
    await withFileLock(tokenLockPath(TOKEN_ID, { tokenLockDir }), async () => {
        await assert.rejects(
            () =>
                commands['set-witness']({
                    token: TOKEN_ID,
                    witness: WITNESS_1,
                    who: ownerSigner,
                    nodeClient: node,
                    tokenLockDir,
                }),
            /already held/,
        );
    });

    // 3. Owner pendingAnchor -> witness enabled on chain -> dryRun plans clear, live tick clears & witness-anchors seq 1
    node.addSetMetadata({ sender: OWNER_A, key: WITNESS_KEY, value: WITNESS_1 });
    const dryLogs1 = [];
    const workerDry1 = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath: tPath,
        statePath: sPath,
        tokenLockDir,
        everyRecords: 1,
        once: true,
        dryRun: true,
        nodeClient: node,
        signer: ownerSigner,
        witnessUrl: srv.url,
        allowPrivateWitness: true,
        source: () => [],
        log: (m) => dryLogs1.push(m),
    });
    const dryRes1 = await workerDry1.tick();
    assert.equal(dryRes1.dryRun, true);
    assert.equal(dryRes1.plan?.action, 'clear_orphaned_pending_anchor');
    assert.equal(dryRes1.plan?.reason, 'witness_changed');
    assert.equal(JSON.parse(fs.readFileSync(sPath, 'utf8')).pendingAnchor?.txHash, ownerRd1.hash, 'dryRun must not mutate disk');

    const liveLogs1 = [];
    const workerLive1 = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath: tPath,
        statePath: sPath,
        tokenLockDir,
        everyRecords: 1,
        once: true,
        nodeClient: node,
        signer: ownerSigner,
        witnessUrl: srv.url,
        allowPrivateWitness: true,
        source: () => [],
        log: (m) => liveLogs1.push(m),
    });
    const liveRes1 = await workerLive1.tick();
    assert.equal(liveRes1.anchored, true);
    assert.equal(liveRes1.anchoredSeq, 1);
    assert.ok(liveLogs1.some((m) => /no longer authorized under current signer/.test(m)));
    const ptrAfter1 = node.state.metadata[ANCHOR_KEY];
    assert.ok(ptrAfter1 && ptrAfter1 !== ownerRd1.hash);
    assert.equal(node.state.registerDataByHash.get(ptrAfter1)?.sender, WITNESS_1);
    assert.equal(JSON.parse(fs.readFileSync(sPath, 'utf8')).pendingAnchor, null);

    // 4. Mirror case: witness-signed pendingAnchor -> witness cleared -> live tick clears orphan & owner anchors seq 2
    writeTrail(tPath, header, records.slice(0, 2));
    const c2 = commitments(header, records.slice(0, 2)).last;
    const witnessRd2 = await sendRegisterData(
        encodeAnchor({ tokenId: TOKEN_ID, toSeq: 2, commitment: c2, prevAnchorTx: ptrAfter1 }),
        witnessSigner,
        node,
    );
    const sAfter1 = JSON.parse(fs.readFileSync(sPath, 'utf8'));
    sAfter1.pendingAnchor = {
        txHash: witnessRd2.hash,
        toSeq: 2,
        commitment: c2.toString('hex'),
        prevAnchorTx: ptrAfter1,
        sender: WITNESS_1,
        expiryEpochSeconds: Math.floor(Date.now() / 1000) + 300,
    };
    fs.writeFileSync(sPath, JSON.stringify(sAfter1) + '\n', { mode: 0o600 });

    node.addSetMetadata({ sender: OWNER_A, key: WITNESS_KEY, value: '' });
    const workerLive2 = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath: tPath,
        statePath: sPath,
        tokenLockDir,
        everyRecords: 1,
        once: true,
        nodeClient: node,
        signer: ownerSigner,
        source: () => [],
        log: () => {},
    });
    const liveRes2 = await workerLive2.tick();
    assert.equal(liveRes2.anchored, true);
    assert.equal(liveRes2.anchoredSeq, 2);
    const ptrAfter2 = node.state.metadata[ANCHOR_KEY];
    assert.ok(ptrAfter2 && ptrAfter2 !== witnessRd2.hash);
    assert.equal(node.state.registerDataByHash.get(ptrAfter2)?.sender, OWNER_A);
    assert.equal(JSON.parse(fs.readFileSync(sPath, 'utf8')).pendingAnchor, null);

    // 5. Unrelated third-party sender on pendingAnchor STILL fails closed (never auto-cleared)
    writeTrail(tPath, header, records.slice(0, 3));
    const c3 = commitments(header, records.slice(0, 3)).last;
    const thirdPartyRd3 = await sendRegisterData(
        encodeAnchor({ tokenId: TOKEN_ID, toSeq: 3, commitment: c3, prevAnchorTx: ptrAfter2 }),
        thirdPartySigner,
        node,
    );
    const sAfter2 = JSON.parse(fs.readFileSync(sPath, 'utf8'));
    sAfter2.pendingAnchor = {
        txHash: thirdPartyRd3.hash,
        toSeq: 3,
        commitment: c3.toString('hex'),
        prevAnchorTx: ptrAfter2,
        sender: PAYER_3,
        expiryEpochSeconds: Math.floor(Date.now() / 1000) + 300,
    };
    fs.writeFileSync(sPath, JSON.stringify(sAfter2) + '\n', { mode: 0o600 });

    const workerFail3 = new AnchorWorker({
        uuid: AGENT_UUID,
        tokenId: TOKEN_ID,
        trailPath: tPath,
        statePath: sPath,
        tokenLockDir,
        everyRecords: 1,
        once: true,
        nodeClient: node,
        signer: ownerSigner,
        source: () => [],
        log: () => {},
    });
    await assert.rejects(() => workerFail3.tick(), /disagrees with current trail\/owner state/);
    assert.equal(JSON.parse(fs.readFileSync(sPath, 'utf8')).pendingAnchor?.txHash, thirdPartyRd3.hash);
});
