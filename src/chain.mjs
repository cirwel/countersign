// Concordium testnet access. Reading needs no keys; signing reads a key file that lives outside the repo.
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import {
    AccountAddress,
    AccountTransactionType,
    CcdAmount,
    ConcordiumHdWallet,
    ContractAddress,
    ContractEvent,
    DataBlob,
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
import { ConcordiumGRPCNodeClient, credentials } from '@concordium/web-sdk/nodejs';
import {
    decodeAgentOf,
    decodeGetAdmin,
    decodeGetMetadataUtf8,
    encodeGetMetadataParam,
    encodeSetMetadataParam,
    encodeTokenId,
    parseCis2Event,
    parseMetadataSetEvent,
} from './cis8004.mjs';
import { REGISTRY, REGISTRY_MODULE_REF, TESTNET_GENESIS, assertRegistry } from './registry.mjs';
import { decodeAnchor } from './trail.mjs';

export { TESTNET_GENESIS };
export const EXPLORER_TX = (hash) => `https://ccdexplorer.io/testnet/transaction/${hash}`;
export const UUID_KEY = 'unitares.agent_uuid';
export const ANCHOR_KEY = 'countersign.anchor';
export const WITNESS_KEY = 'countersign.witness';
export const TX_RE = /^[0-9a-f]{64}$/;
const utf8Fatal = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const DEFAULT_NODE_HOST = 'grpc.testnet.concordium.com';
const DEFAULT_NODE_PORT = 20000;
const DEFAULT_RPC_TIMEOUT_MS = 30000;
const MAX_REGISTRY_ENERGY = 100000;

let explicitConfig = null;
let cached;
let cachedKey;
let cachedPromise;
let cachedPromiseKey;
const verifiedClients = new WeakMap();

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Compares two Base58Check Concordium account addresses canonically, treating aliases of the same account as equal. */
export function isSameAccount(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    try {
        return AccountAddress.isAlias(AccountAddress.fromBase58(a), AccountAddress.fromBase58(b));
    } catch {
        return false;
    }
}

export function isTransientRpcError(err) {
    if (!err) return false;
    const code = err.code;
    if (
        code === 'UNAVAILABLE' ||
        code === 'RESOURCE_EXHAUSTED' ||
        code === 'DEADLINE_EXCEEDED' ||
        code === 14 ||
        code === 8 ||
        code === 4 ||
        code === 429 ||
        code === '429'
    ) {
        return true;
    }
    if (err.status === 429 || err.statusCode === 429) return true;
    return /HTTP status code 429|\b(?:UNAVAILABLE|RESOURCE_EXHAUSTED|DEADLINE_EXCEEDED)\b/i.test(String(err.message ?? ''));
}

function isNotFoundError(err) {
    return err?.code === 'NOT_FOUND' || err?.code === 5;
}

export async function withRpcRetry(fn, { maxRetries = 4, baseDelayMs = 1000, deadlineMs, now = Date.now, onBackoff } = {}) {
    let attempt = 0;
    while (true) {
        try {
            return await fn();
        } catch (err) {
            if (!isTransientRpcError(err) || attempt >= maxRetries) throw err;
            if (deadlineMs !== undefined && now() >= deadlineMs) throw err;
            let delay = Math.round(baseDelayMs * 2 ** attempt * (0.85 + 0.3 * Math.random()));
            if (deadlineMs !== undefined) {
                const rem = deadlineMs - now();
                if (rem <= 0) throw err;
                delay = Math.min(delay, rem);
            }
            attempt += 1;
            if (onBackoff) await onBackoff(delay);
            else await sleep(delay);
        }
    }
}

/** Bounded-concurrency RPC pool with exponential backoff retry on transient 429 / UNAVAILABLE / RESOURCE_EXHAUSTED / DEADLINE_EXCEEDED. */
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

function envNodeInsecure() {
    const v = String(process.env.COUNTERSIGN_NODE_INSECURE ?? '').trim().toLowerCase();
    return v === '1' || v === 'true';
}

export function formatGrpcHost(host) {
    return host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
}

function parseNodeString(raw) {
    const spec = raw.trim();
    if (!spec) return null;
    let rest = spec;
    let tls;
    let explicitTls = false;
    const schemeMatch = /^(https?|grpcs?):\/\/(.*)$/i.exec(spec);
    if (schemeMatch) {
        const scheme = schemeMatch[1].toLowerCase();
        explicitTls = true;
        tls = scheme === 'https' || scheme === 'grpcs';
        rest = schemeMatch[2];
        if (!rest || rest.includes('/') || rest.includes('?') || rest.includes('#') || rest.includes('@')) {
            throw new Error(`invalid node address: ${raw}`);
        }
    }
    if (rest.startsWith('[')) {
        const m = /^\[([^\]]+)\](?::(\d+))?$/.exec(rest);
        if (!m || !net.isIPv6(m[1])) throw new Error(`invalid IPv6 node address: ${raw}`);
        const port = m[2] ? Number(m[2]) : DEFAULT_NODE_PORT;
        if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`invalid node port in ${raw}`);
        return { host: m[1], port, tls, explicitTls };
    }
    if (net.isIPv6(rest)) {
        return { host: rest, port: DEFAULT_NODE_PORT, tls, explicitTls };
    }
    const parts = rest.split(':');
    if (parts.length === 1) {
        return { host: parts[0], port: DEFAULT_NODE_PORT, tls, explicitTls };
    }
    if (parts.length === 2 && parts[0].length > 0 && /^\d+$/.test(parts[1])) {
        const port = Number(parts[1]);
        if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`invalid node port in ${raw}`);
        return { host: parts[0], port, tls, explicitTls };
    }
    throw new Error(`invalid node address: ${raw}`);
}

function resolveEnvNodeConfig() {
    const parsed = process.env.COUNTERSIGN_NODE ? parseNodeString(process.env.COUNTERSIGN_NODE) : null;
    const host = parsed?.host ?? DEFAULT_NODE_HOST;
    const port = parsed?.port ?? DEFAULT_NODE_PORT;
    const explicitTls = parsed?.explicitTls ?? false;
    const tls = explicitTls ? parsed.tls : !envNodeInsecure();
    return { host, port, tls, explicitTls, rpcTimeoutMs: DEFAULT_RPC_TIMEOUT_MS };
}

function normalizeNodeConfig(opts) {
    if (opts === undefined || opts === null) return null;
    if (typeof opts === 'string') {
        const parsed = parseNodeString(opts);
        if (!parsed) return null;
        return {
            host: parsed.host,
            port: parsed.port,
            tls: parsed.explicitTls ? parsed.tls : !envNodeInsecure(),
            rpcTimeoutMs: DEFAULT_RPC_TIMEOUT_MS,
        };
    }
    if (typeof opts !== 'object') throw new TypeError('configureNode expects an options object or node URL/host[:port] string');

    let parsedHost = null;
    if (opts.host !== undefined) {
        if (typeof opts.host !== 'string' || opts.host.trim().length === 0) {
            throw new Error('node host must be a non-empty string');
        }
        parsedHost = parseNodeString(opts.host);
    }
    if (opts.tls !== undefined && typeof opts.tls !== 'boolean') {
        throw new Error('node tls option must be a boolean');
    }

    const base = opts.host === undefined ? resolveEnvNodeConfig() : null;
    const host = parsedHost?.host ?? base.host;
    const port = opts.port !== undefined ? Number(opts.port) : (parsedHost?.port ?? base.port);
    const hasExplicitTlsScheme = parsedHost ? parsedHost.explicitTls : base.explicitTls;
    const schemeTls = parsedHost ? parsedHost.tls : base.tls;

    if (hasExplicitTlsScheme && schemeTls === true && (opts.tls === false || opts.insecure === true)) {
        throw new Error('cannot combine explicit TLS scheme with insecure node option');
    }
    if (hasExplicitTlsScheme && schemeTls === false && opts.tls === true) {
        throw new Error('cannot combine explicit plaintext scheme with tls: true');
    }

    let tls;
    if (opts.tls !== undefined) tls = opts.tls;
    else if (opts.insecure === true) tls = false;
    else if (hasExplicitTlsScheme) tls = schemeTls;
    else if (opts.host !== undefined) tls = !envNodeInsecure();
    else tls = base.tls;

    const rpcTimeoutMs = opts.rpcTimeoutMs !== undefined ? Number(opts.rpcTimeoutMs) : DEFAULT_RPC_TIMEOUT_MS;
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`invalid node port: ${opts.port}`);
    if (!Number.isSafeInteger(rpcTimeoutMs) || rpcTimeoutMs <= 0) throw new Error(`invalid rpcTimeoutMs: ${opts.rpcTimeoutMs}`);
    return { host, port, tls, rpcTimeoutMs };
}

function effectiveNodeConfig() {
    if (explicitConfig) return explicitConfig;
    const env = resolveEnvNodeConfig();
    return { host: env.host, port: env.port, tls: env.tls, rpcTimeoutMs: env.rpcTimeoutMs };
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

/** Applies CLI/worker node and TLS options to the shared node configuration when specified. */
export function applyNodeOptions(node, nodeInsecure) {
    if (!node && !nodeInsecure) return;
    const cfg = typeof node === 'string' ? { host: node } : (node && typeof node === 'object' ? { ...node } : {});
    if (nodeInsecure) cfg.tls = false;
    configureNode(cfg);
}

/** Instantiates a ConcordiumGRPCNodeClient for the configured endpoint without issuing RPCs yet. */
export function createGrpcClient(cfg = effectiveNodeConfig()) {
    const creds = cfg.tls ? credentials.createSsl() : credentials.createInsecure();
    return new ConcordiumGRPCNodeClient(formatGrpcHost(cfg.host), cfg.port, creds, {
        timeout: cfg.rpcTimeoutMs ?? DEFAULT_RPC_TIMEOUT_MS,
    });
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
    const key = `${formatGrpcHost(cfg.host)}:${cfg.port}:${cfg.tls ? 'tls' : 'plain'}:${cfg.rpcTimeoutMs ?? DEFAULT_RPC_TIMEOUT_MS}`;
    if (cached && cachedKey === key) return cached;
    if (cachedPromise && cachedPromiseKey === key) return cachedPromise;

    cached = undefined;
    cachedKey = undefined;
    const p = (async () => {
        const c = createGrpcClient(cfg);
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

/**
 * Loads a Concordium account signer from an explicit file path (or optional env var), enforcing chmod 0600 permissions
 * and canonical Base58Check accountAddress without falling back to the agent owner's default keyfile.
 */
export function loadSignerFromFile(filePath, { envVar } = {}) {
    const rawPath = filePath ?? (envVar ? process.env[envVar] : undefined);
    if (typeof rawPath !== 'string' || rawPath.trim().length === 0) {
        const hint = envVar ? ` (set ${envVar} or pass explicit keyfile path)` : '';
        throw new Error(`signer keyfile path is required${hint}`);
    }
    const file = rawPath.trim().replace(/^~(?=$|\/)/, os.homedir());
    if ((fs.statSync(file).mode & 0o077) !== 0) {
        throw new Error('key file must not be readable by group or others (chmod 600)');
    }
    const k = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!k || typeof k !== 'object' || Array.isArray(k)) {
        throw new Error(`invalid keyfile ${file}: expected JSON object`);
    }
    if (typeof k.accountAddress !== 'string' || k.accountAddress.length === 0) {
        throw new Error(`invalid keyfile ${file}: missing accountAddress`);
    }
    const sender = AccountAddress.fromBase58(k.accountAddress);
    if (sender.address !== k.accountAddress) {
        throw new Error(`invalid keyfile ${file}: accountAddress is not in canonical Base58Check form`);
    }
    let signKey;
    if (typeof k.signKey === 'string' && k.signKey.length > 0) {
        signKey = k.signKey;
    } else if (typeof k.seedPhrase === 'string' && k.seedPhrase.length > 0) {
        signKey = ConcordiumHdWallet.fromSeedPhrase(k.seedPhrase, 'Testnet').getAccountSigningKey(0, 0, 0).toString('hex');
    } else {
        throw new Error(`invalid keyfile ${file}: missing signKey or seedPhrase`);
    }
    return { address: sender.address, sender, signer: buildBasicAccountSigner(signKey) };
}

/** Key file: { accountAddress, seedPhrase } (identity 0, credential 0 on identity provider 0) or { accountAddress, signKey }. */
export function loadSigner() {
    return loadSignerFromFile(keyfilePath(), { envVar: 'COUNTERSIGN_KEYFILE' });
}

export async function waitForFinalizedPolling(c, hash, { timeoutMs = 180000, pollIntervalMs = 2000, now = () => performance.now() } = {}) {
    const txObj = typeof hash === 'string' ? TransactionHash.fromHexString(hash) : hash;
    const txLabel = typeof hash === 'string' ? hash : hash.toString();
    const deadline = now() + timeoutMs;
    const timeoutErr = () => new Error(`transaction ${txLabel} did not finalize within ${timeoutMs}ms`);
    while (true) {
        const remaining = deadline - now();
        if (remaining <= 0) throw timeoutErr();
        const retryOpts =
            remaining <= 1500
                ? { maxRetries: 0, baseDelayMs: 0, deadlineMs: deadline, now }
                : { maxRetries: 2, baseDelayMs: Math.min(500, Math.max(1, Math.floor(remaining / 4))), deadlineMs: deadline, now };
        let timer;
        let status;
        try {
            status = await Promise.race([
                withRpcRetry(() => c.getBlockItemStatus(txObj), retryOpts),
                new Promise((_, reject) => {
                    timer = setTimeout(() => reject(timeoutErr()), remaining);
                }),
            ]);
        } finally {
            clearTimeout(timer);
        }
        if (now() >= deadline) throw timeoutErr();
        if (status?.status === 'finalized') {
            const summary = status.outcome?.summary;
            if (!summary) throw new Error(`transaction ${txLabel} finalized without outcome summary`);
            if (summary.transactionType === 'failed' || summary.rejectReason) {
                throw new Error(`transaction ${txLabel} was rejected: ${JSON.stringify(summary.rejectReason ?? summary, bigintSafe)}`);
            }
            return { hash: txLabel, summary };
        }
        const afterPollRemaining = deadline - now();
        if (afterPollRemaining <= 0) throw timeoutErr();
        await sleep(Math.min(pollIntervalMs, Math.max(1, afterPollRemaining)));
    }
}

/** Inspects a transaction's current node state ('absent', 'pending', 'committed', or 'finalized'). */
export async function getTransactionState(txHash, nodeClient) {
    const c = nodeClient ?? (await client());
    await assertTestnet(c);
    const txObj = typeof txHash === 'string' ? TransactionHash.fromHexString(txHash) : txHash;
    let status;
    try {
        status = await withRpcRetry(() => c.getBlockItemStatus(txObj));
    } catch (err) {
        if (isNotFoundError(err)) return { state: 'absent' };
        throw err;
    }
    if (!status) return { state: 'absent' };
    if (status.status === 'received') return { state: 'pending' };
    if (status.status === 'committed') return { state: 'committed' };
    if (status.status === 'finalized') {
        return {
            state: 'finalized',
            summary: status.outcome?.summary,
            blockHash: status.outcome?.blockHash,
        };
    }
    throw new Error(`unexpected block item status for ${txHash}: ${status.status}`);
}

async function signSendWait(builder, who, nodeClient, pollOpts = {}) {
    const { onSigned, expectedNonce, ...waitOpts } = pollOpts ?? {};
    const c = nodeClient ?? (await client());
    await assertTestnet(c);
    const next = await withRpcRetry(() => c.getNextAccountNonce(who.sender));
    let txNonce = next.nonce;
    if (expectedNonce !== undefined && expectedNonce !== null) {
        const exp = BigInt(expectedNonce);
        const nextVal = BigInt(next.nonce?.value ?? next.nonce);
        if (next.allFinal !== true || nextVal !== exp) {
            throw new Error(
                `owner nonce CAS failed for ${who.address}: expected finalized nonce ${exp}, got ${nextVal} (allFinal=${next.allFinal})`,
            );
        }
        txNonce = SequenceNumber.create(exp);
    }
    const tx = builder.addMetadata({ sender: who.sender, nonce: txNonce }).build();
    const signed = await Transaction.signAndFinalize(tx, who.signer);
    const txHash = Buffer.from(Transaction.getAccountTransactionHash(signed)).toString('hex');
    const expiryEpochSeconds = Number(signed.header?.expiry?.expiryEpochSeconds ?? 0);
    if (onSigned) {
        await onSigned({ txHash, expiryEpochSeconds, signed });
    }
    const hash = await c.sendTransaction(signed);
    console.log('submitted tx:', hash.toString());
    return waitForFinalizedPolling(c, hash, waitOpts);
}

export const bigintSafe = (_k, v) => (typeof v === 'bigint' ? v.toString() : v);

/** Atomically writes bytes or UTF-8 string via same-directory temp file + fsync + chmod + rename. */
export function writeFileAtomic(filePath, content, { mode = 0o600 } = {}) {
    const dir = path.dirname(filePath);
    fs.mkdirSync(dir, { recursive: true });
    const tmpPath = path.join(dir, `.${path.basename(filePath)}.tmp.${process.pid}.${crypto.randomUUID()}`);
    const fd = fs.openSync(tmpPath, 'w', mode);
    try {
        const buf = typeof content === 'string' ? Buffer.from(content, 'utf8') : Buffer.from(content);
        let offset = 0;
        while (offset < buf.length) {
            offset += fs.writeSync(fd, buf, offset, buf.length - offset);
        }
        fs.fchmodSync(fd, mode);
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

export function sendRegisterData(bytes, who = loadSigner(), nodeClient, pollOpts) {
    return signSendWait(Transaction.registerData({ data: new DataBlob(Buffer.from(bytes)) }), who, nodeClient, pollOpts);
}

/**
 * Signs and submits an unsigned payload built by the Agent Registry MCP server.
 * The server is not trusted to choose what gets signed: the caller states the entrypoint it expects,
 * the contract must be the pinned registry, the energy is capped, and where the caller can build the
 * parameter itself the server's bytes must equal it.
 */
export function sendRegistryUpdate(built, who, expect, nodeClient, pollOpts) {
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
    return signSendWait(Transaction.updateContract(payload, Energy.create(energy)), who, nodeClient, pollOpts);
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

function addressToString(addr) {
    if (typeof addr === 'string') return addr;
    if (addr && typeof addr.address === 'string') return addr.address;
    return addr !== undefined && addr !== null ? String(addr) : '';
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

/** Reads and decodes CIS-8004.getAdmin() directly from a Concordium node. */
export async function readAdmin({ blockHash, nodeClient } = {}) {
    const bytes = await invokeRegistryView('CIS-8004.getAdmin', Buffer.alloc(0), blockHash, nodeClient);
    return decodeGetAdmin(bytes);
}

/** Builds CIS-8004.setMetadata locally, estimates energy via dry-run invokeContract, and submits it on testnet. */
export async function sendSetMetadata(tokenId, key, valueUtf8, who = loadSigner(), nodeClient, pollOpts) {
    const c = nodeClient ?? (await client());
    await assertTestnet(c);
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
    return signSendWait(Transaction.updateContract(payload, Energy.create(energy)), who, c, pollOpts);
}

/** Finalized register-data transaction: who sent it, what bytes it carries, timestamp, and block height. */
export async function readRegisterData(txHash, nodeClient) {
    const c = nodeClient ?? (await client());
    await assertTestnet(c);
    const status = await withRpcRetry(() => c.getBlockItemStatus(TransactionHash.fromHexString(txHash)));
    if (!status || status.status !== 'finalized') throw new Error(`transaction ${txHash} is not finalized (${status?.status ?? 'absent'})`);
    const s = status.outcome.summary;
    if (s.transactionType !== 'registerData') throw new Error(`transaction ${txHash} is ${s.transactionType}, not registerData`);
    const block = await withRpcRetry(() => c.getBlockInfo(status.outcome.blockHash));
    const data = typeof s.dataRegistered.data === 'string' ? Buffer.from(s.dataRegistered.data, 'hex') : Buffer.from(s.dataRegistered.data);
    return {
        sender: addressToString(s.sender),
        data,
        blockTime: block.blockSlotTime.toISOString(),
        blockHeight: Number(block.blockHeight),
        blockHash: status.outcome.blockHash,
        txIndex: s.index !== undefined && s.index !== null ? Number(s.index) : null,
    };
}

/**
 * Resolves the 0-based transaction index of `txHash` within a finalized `blockHash` by streaming
 * `getBlockTransactionEvents` under a bounded timeout. Used as a same-block tie-breaker when
 * `getBlockItemStatus` omits `summary.index`.
 */
export async function readTransactionBlockIndex(blockHash, txHash, nodeClient, { streamTimeoutMs = 15_000 } = {}) {
    if (!blockHash || typeof txHash !== 'string') return null;
    const c = nodeClient ?? (await client());
    await assertTestnet(c);
    return withRpcRetry(async () => {
        const ac = new AbortController();
        let timedOut = false;
        const timeoutErr = Object.assign(
            new Error(`gRPC stream timed out after ${streamTimeoutMs}ms`),
            { code: 'DEADLINE_EXCEEDED' },
        );
        const timer = setTimeout(() => {
            timedOut = true;
            ac.abort(timeoutErr);
        }, streamTimeoutMs);
        try {
            let txIdx = 0;
            for await (const s of c.getBlockTransactionEvents(blockHash, ac.signal)) {
                if (ac.signal.aborted) throw ac.signal.reason;
                if (s?.hash?.toString() === txHash) {
                    return s.index !== undefined && s.index !== null ? Number(s.index) : txIdx;
                }
                txIdx += 1;
            }
            return null;
        } catch (err) {
            if (timedOut) throw timeoutErr;
            throw err;
        } finally {
            clearTimeout(timer);
        }
    });
}

/** Reads a finalized plain CCD transfer (or transferWithMemo) directly from a Concordium testnet node. */
export async function readAccountTransfer(txHash, nodeClient) {
    if (typeof txHash !== 'string' || !TX_RE.test(txHash)) {
        throw new Error(`invalid transaction hash: ${txHash}`);
    }
    const c = nodeClient ?? (await client());
    await assertTestnet(c);
    const status = await withRpcRetry(() => c.getBlockItemStatus(TransactionHash.fromHexString(txHash)));
    if (!status || status.status !== 'finalized') {
        throw new Error(`transaction ${txHash} is not finalized (${status?.status ?? 'absent'})`);
    }
    const s = status.outcome?.summary;
    if (!s) throw new Error(`transaction ${txHash} finalized without outcome summary`);
    if (s.transactionType === 'failed' || s.rejectReason) {
        throw new Error(`transaction ${txHash} failed on chain`);
    }
    if (s.transactionType !== 'transfer' && s.transactionType !== 'transferWithMemo') {
        throw new Error(`transaction ${txHash} is ${s.transactionType}, not transfer or transferWithMemo`);
    }
    const rawAmt = s.transfer?.amount?.microCcdAmount ?? s.transfer?.amount;
    if (rawAmt === undefined || rawAmt === null) {
        throw new Error(`transfer ${txHash} missing amount`);
    }
    const amountMicroCcd = BigInt(rawAmt);
    const to = addressToString(s.transfer?.to);
    const sender = addressToString(s.sender);
    if (!to || !sender) {
        throw new Error(`transfer ${txHash} missing sender or recipient`);
    }
    let memoHex = null;
    if (s.transactionType === 'transferWithMemo') {
        const rawMemo = s.memo?.memo ?? s.memo;
        if (typeof rawMemo === 'string') {
            memoHex = rawMemo.toLowerCase();
        } else if (Buffer.isBuffer(rawMemo) || rawMemo instanceof Uint8Array) {
            memoHex = Buffer.from(rawMemo).toString('hex');
        } else {
            throw new Error(`transferWithMemo ${txHash} missing memo bytes`);
        }
        if (!/^(?:[0-9a-f]{2})*$/.test(memoHex)) {
            throw new Error(`transferWithMemo ${txHash} has invalid hex memo`);
        }
    }
    const block = await withRpcRetry(() => c.getBlockInfo(status.outcome.blockHash));
    return {
        txHash,
        sender,
        to,
        amountMicroCcd,
        memoHex,
        blockHeight: Number(block.blockHeight),
        blockTime: block.blockSlotTime.toISOString(),
    };
}

/** Encodes parameters for a native CCD transfer (with optional <=256-byte DataBlob memo). */
export function encodeSimpleTransferParams({ to, microCcd, memoBytes } = {}) {
    let toAddress;
    if (typeof to === 'string') {
        toAddress = AccountAddress.fromBase58(to);
        if (toAddress.address !== to) {
            throw new Error(`recipient address ${to} is not in canonical Base58Check form`);
        }
    } else if (to && typeof to.address === 'string') {
        toAddress = to;
    } else {
        throw new Error('transfer recipient address is required');
    }
    const amt = BigInt(microCcd);
    if (amt < 0n) throw new Error('transfer microCcd must be non-negative');
    const amount = CcdAmount.fromMicroCcd(amt);

    let memo;
    if (memoBytes !== undefined && memoBytes !== null) {
        let buf;
        if (Buffer.isBuffer(memoBytes)) buf = memoBytes;
        else if (memoBytes instanceof Uint8Array) buf = Buffer.from(memoBytes);
        else if (typeof memoBytes === 'string') {
            if (!/^(?:[0-9a-f]{2})*$/i.test(memoBytes)) {
                throw new Error('memoBytes hex string must be even-length hexadecimal');
            }
            buf = Buffer.from(memoBytes, 'hex');
        } else {
            throw new TypeError('memoBytes must be a Buffer, Uint8Array, or hex string');
        }
        memo = new DataBlob(buf);
    }
    return memo !== undefined ? { toAddress, amount, memo } : { toAddress, amount };
}

/** Sends a native CCD transfer (with memo when memoBytes is given) and waits for finalization on testnet. */
export function sendTransferWithMemo({
    to,
    microCcd,
    memoBytes,
    who = loadSigner(),
    nodeClient,
    pollOpts,
    onSigned,
    expectedNonce,
} = {}) {
    const params = encodeSimpleTransferParams({ to, microCcd, memoBytes });
    const builder = params.memo
        ? Transaction.transfer({ toAddress: params.toAddress, amount: params.amount }, params.memo)
        : Transaction.transfer({ toAddress: params.toAddress, amount: params.amount });
    const mergedPollOpts = {
        ...(pollOpts ?? {}),
        ...(onSigned !== undefined ? { onSigned } : {}),
        ...(expectedNonce !== undefined ? { expectedNonce } : {}),
    };
    return signSendWait(builder, who, nodeClient, mergedPollOpts);
}

function validateSenderSignaturesShape(senderSigs, declaredNumSignatures) {
    if (!senderSigs || typeof senderSigs !== 'object' || Array.isArray(senderSigs)) {
        throw new Error('sponsored transaction missing sender signatures');
    }
    let total = 0;
    for (const [credIdx, credSigs] of Object.entries(senderSigs)) {
        if (!/^(?:0|[1-9][0-9]*)$/.test(credIdx) || !credSigs || typeof credSigs !== 'object' || Array.isArray(credSigs)) {
            throw new Error('malformed credential signature map in sponsored transaction');
        }
        for (const [keyIdx, sigHex] of Object.entries(credSigs)) {
            if (!/^(?:0|[1-9][0-9]*)$/.test(keyIdx) || typeof sigHex !== 'string' || !/^[0-9a-f]{128}$/i.test(sigHex)) {
                throw new Error('malformed Ed25519 signature in sponsored transaction');
            }
            total += 1;
        }
    }
    if (total === 0 || BigInt(total) > declaredNumSignatures) {
        throw new Error(`sender signature count (${total}) invalid for declared numSignatures=${declaredNumSignatures}`);
    }
}

/**
 * Builds and owner-signs a Concordium Protocol 10 fee-sponsored V1 `CIS-8004.setMetadata` transaction
 * ready for transport to the witness sponsor via `Transaction.toJSONString`.
 */
export async function buildSignedSponsoredSetMetadata({
    tokenId,
    key = ANCHOR_KEY,
    valueUtf8,
    who = loadSigner(),
    sponsorAddress,
    expectedNonce,
    expiryEpochSeconds,
    nodeClient,
} = {}) {
    if (!who || typeof who.address !== 'string' || !who.sender || !who.signer) {
        throw new Error('valid owner signer { address, sender, signer } is required');
    }
    if (typeof sponsorAddress !== 'string' || sponsorAddress.length === 0) {
        throw new Error('sponsorAddress is required');
    }
    const sponsorAddr = AccountAddress.fromBase58(sponsorAddress);
    if (sponsorAddr.address !== sponsorAddress) {
        throw new Error(`sponsorAddress ${sponsorAddress} is not in canonical Base58Check form`);
    }
    if (isSameAccount(sponsorAddr.address, who.address)) {
        throw new Error('sponsor account cannot be the same as owner account');
    }

    const c = nodeClient ?? (await client());
    await assertTestnet(c);

    const cs = await withRpcRetry(() => c.getConsensusStatus());
    const tipBlockHash = cs.lastFinalizedBlock;
    const paramBuf = encodeSetMetadataParam(tokenId, key, valueUtf8);
    const contract = registryContractAddress();
    const receiveName = ReceiveName.fromString('CIS-8004.setMetadata');

    const dryRun = await withRpcRetry(() =>
        c.invokeContract(
            {
                invoker: who.sender,
                contract,
                method: receiveName,
                parameter: Parameter.fromBuffer(paramBuf),
            },
            tipBlockHash,
        ),
    );
    if (dryRun.tag !== 'success') {
        throw new Error(`dry-run CIS-8004.setMetadata failed: ${JSON.stringify(dryRun.reason ?? dryRun, bigintSafe)}`);
    }
    const used = Number(dryRun.usedEnergy?.value ?? dryRun.usedEnergy);
    const energy = Math.max(used + 500, Math.ceil(used * 1.25));
    if (!(energy > 0 && energy <= MAX_REGISTRY_ENERGY)) {
        throw new Error(`CIS-8004.setMetadata estimated ${energy} energy (cap ${MAX_REGISTRY_ENERGY}); refusing to sign`);
    }

    const next = await withRpcRetry(() => c.getNextAccountNonce(who.sender));
    let exp = BigInt(next.nonce?.value ?? next.nonce);
    if (expectedNonce !== undefined && expectedNonce !== null) {
        const wanted = BigInt(expectedNonce);
        if (next.allFinal !== true || exp !== wanted) {
            throw new Error(
                `owner nonce CAS failed for ${who.address}: expected finalized nonce ${wanted}, got ${exp} (allFinal=${next.allFinal})`,
            );
        }
        exp = wanted;
    }

    let resolvedExpiry;
    if (expiryEpochSeconds !== undefined && expiryEpochSeconds !== null) {
        resolvedExpiry = BigInt(expiryEpochSeconds);
        if (resolvedExpiry <= 0n) throw new Error(`invalid expiryEpochSeconds: ${expiryEpochSeconds}`);
    } else {
        const tipBlock = await withRpcRetry(() => c.getBlockInfo(tipBlockHash));
        resolvedExpiry = BigInt(Math.floor(tipBlock.blockSlotTime.getTime() / 1000) + 300);
    }

    const payload = {
        amount: CcdAmount.zero(),
        address: contract,
        receiveName,
        message: Parameter.fromBuffer(paramBuf),
    };
    const signable = Transaction.updateContract(payload, Energy.create(energy))
        .addMetadata({
            sender: who.sender,
            nonce: SequenceNumber.create(exp),
            expiry: TransactionExpiry.fromEpochSeconds(resolvedExpiry),
        })
        .addSponsor(sponsorAddr)
        .build();

    const withSender = await Transaction.sign(signable, who.signer);
    return {
        transactionJson: Transaction.toJSONString(withSender),
        nonce: Number(exp),
        expiryEpochSeconds: Number(resolvedExpiry),
        energy,
    };
}

/**
 * Strictly validates an owner-signed Protocol 10 sponsored `CIS-8004.setMetadata` transaction against all
 * fail-closed invariants, co-signs as sponsor, submits to Concordium testnet, and polls for finalization.
 */
export async function validateAndSponsorSetMetadata({
    transactionJson,
    expectedOwner,
    expectedSponsor,
    expectedTokenId,
    expectedKey = ANCHOR_KEY,
    expectedValueUtf8,
    maxEnergy = MAX_REGISTRY_ENERGY,
    maxExpiryLeadSeconds = 3600,
    sponsorSigner,
    nodeClient,
    pollOpts,
} = {}) {
    if (typeof transactionJson !== 'string' || transactionJson.trim().length === 0) {
        throw new Error('transactionJson must be a non-empty JSON string');
    }
    if (typeof expectedOwner !== 'string' || AccountAddress.fromBase58(expectedOwner).address !== expectedOwner) {
        throw new Error('expectedOwner must be a canonical Base58Check account address');
    }
    if (typeof expectedSponsor !== 'string' || AccountAddress.fromBase58(expectedSponsor).address !== expectedSponsor) {
        throw new Error('expectedSponsor must be a canonical Base58Check account address');
    }
    if (isSameAccount(expectedOwner, expectedSponsor)) {
        throw new Error('sponsor account cannot be the same as owner account');
    }
    const signerObj = sponsorSigner?.signer ?? sponsorSigner;
    if (!signerObj || typeof signerObj.sign !== 'function') {
        throw new Error('sponsorSigner with sign() is required');
    }
    if (sponsorSigner?.address !== undefined && sponsorSigner.address !== expectedSponsor) {
        throw new Error(`sponsorSigner ${sponsorSigner.address} does not match expectedSponsor ${expectedSponsor}`);
    }

    const c = nodeClient ?? (await client());
    await assertTestnet(c);

    let rawJson;
    try {
        rawJson = JSON.parse(transactionJson);
    } catch (err) {
        throw new Error(`invalid transactionJson JSON: ${err.message}`);
    }
    if (!rawJson || typeof rawJson !== 'object' || Array.isArray(rawJson)) {
        throw new Error('transactionJson must decode to a JSON object');
    }

    let parsed;
    try {
        // Note: @concordium/web-sdk@12.0.3 Transaction.fromJSONString throws `fromJSON is not a function`; signableFromJSON is required.
        parsed = Transaction.signableFromJSON(rawJson);
    } catch (err) {
        throw new Error(`invalid signable transaction payload: ${err.message}`);
    }

    if (parsed.version !== 1 || !Transaction.isSignable(parsed) || !Transaction.isSponsorable(parsed)) {
        throw new Error('transaction must be a v1 signable sponsorable transaction');
    }
    const rawSponsorSig = parsed.signatures?.sponsor;
    const hasSponsorSig =
        rawSponsorSig !== undefined &&
        (typeof rawSponsorSig !== 'object' ||
            rawSponsorSig === null ||
            Array.isArray(rawSponsorSig) ||
            Object.keys(rawSponsorSig).length > 0);
    if (hasSponsorSig) {
        throw new Error('transaction already contains a sponsor signature');
    }
    if (parsed.payload?.type !== AccountTransactionType.Update) {
        throw new Error(`unexpected transaction payload type ${parsed.payload?.type}; expected Update`);
    }
    const attachedMicroCcd = BigInt(parsed.payload.amount?.microCcdAmount ?? parsed.payload.amount ?? 0n);
    if (attachedMicroCcd !== 0n) {
        throw new Error(`refusing non-zero CCD amount ${attachedMicroCcd} on sponsored setMetadata`);
    }
    if (!isRegistryAddress(parsed.payload.address)) {
        throw new Error('sponsored transaction does not target pinned registry <12802,0>');
    }
    if (parsed.payload.receiveName?.value !== 'CIS-8004.setMetadata') {
        throw new Error(`sponsored transaction calls ${parsed.payload.receiveName?.value}, expected CIS-8004.setMetadata`);
    }

    const expectedParam = encodeSetMetadataParam(expectedTokenId, expectedKey, expectedValueUtf8);
    const actualParam = Buffer.from(Parameter.toBuffer(parsed.payload.message));
    if (!actualParam.equals(expectedParam)) {
        throw new Error('sponsored transaction parameter bytes do not match expected CIS-8004.setMetadata arguments');
    }
    if (parsed.header?.sender?.address !== expectedOwner) {
        throw new Error(`sponsored transaction sender ${parsed.header?.sender?.address} must exactly match owner ${expectedOwner}`);
    }
    if (parsed.header?.sponsor?.account?.address !== expectedSponsor) {
        throw new Error(
            `sponsored transaction sponsor ${parsed.header?.sponsor?.account?.address} does not match expected sponsor ${expectedSponsor}`,
        );
    }
    if (parsed.header?.sponsor?.numSignatures !== 1n) {
        throw new Error(`sponsored transaction sponsor.numSignatures must be 1, got ${parsed.header?.sponsor?.numSignatures}`);
    }
    const numSigs = parsed.header?.numSignatures;
    if (typeof numSigs !== 'bigint' || numSigs < 1n || numSigs > 10n) {
        throw new Error(`sponsored transaction numSignatures ${numSigs} outside allowed [1, 10]`);
    }
    const execEnergy = parsed.header?.executionEnergyAmount?.value;
    if (typeof execEnergy !== 'bigint' || execEnergy <= 0n || execEnergy > BigInt(maxEnergy)) {
        throw new Error(`sponsored transaction executionEnergyAmount ${execEnergy} exceeds allowed cap ${maxEnergy}`);
    }
    validateSenderSignaturesShape(parsed.signatures?.sender, numSigs);

    const cs = await withRpcRetry(() => c.getConsensusStatus());
    const tipBlockHash = cs.lastFinalizedBlock;
    const tipBlock = await withRpcRetry(() => c.getBlockInfo(tipBlockHash));
    const finalizedChainEpochSec = BigInt(Math.floor(tipBlock.blockSlotTime.getTime() / 1000));
    const txExpiry = parsed.header?.expiry?.expiryEpochSeconds;
    if (
        typeof txExpiry !== 'bigint' ||
        txExpiry <= finalizedChainEpochSec ||
        txExpiry > finalizedChainEpochSec + BigInt(maxExpiryLeadSeconds)
    ) {
        throw new Error(
            `sponsored transaction expiry ${txExpiry} outside valid window (${finalizedChainEpochSec}, ${finalizedChainEpochSec + BigInt(maxExpiryLeadSeconds)}]`,
        );
    }

    const ownerAccountInfo = await withRpcRetry(() => c.getAccountInfo(parsed.header.sender, tipBlockHash));
    if (!ownerAccountInfo || !ownerAccountInfo.accountCredentials || typeof ownerAccountInfo.accountThreshold !== 'number') {
        throw new Error(`owner account ${expectedOwner} missing credential keys for signature verification`);
    }
    const sigValid = await Transaction.verifySignature(parsed, parsed.signatures.sender, ownerAccountInfo);
    if (!sigValid) {
        throw new Error('invalid owner signature on sponsored setMetadata transaction');
    }

    const dryRun = await withRpcRetry(() =>
        c.invokeContract(
            {
                invoker: parsed.header.sender,
                contract: registryContractAddress(),
                method: ReceiveName.fromString('CIS-8004.setMetadata'),
                parameter: parsed.payload.message,
            },
            tipBlockHash,
        ),
    );
    if (dryRun.tag !== 'success') {
        throw new Error(`dry-run CIS-8004.setMetadata failed: ${JSON.stringify(dryRun.reason ?? dryRun, bigintSafe)}`);
    }
    const usedEnergy = BigInt(dryRun.usedEnergy?.value ?? dryRun.usedEnergy ?? 0n);
    if (usedEnergy > execEnergy) {
        throw new Error(`dry-run usedEnergy (${usedEnergy}) exceeds transaction executionEnergyAmount (${execEnergy})`);
    }

    // Clone signatures before Transaction.sponsor because it mutates signatures in place.
    const cleanSignable = {
        version: 1,
        header: parsed.header,
        payload: parsed.payload,
        signatures: { sender: structuredClone(parsed.signatures.sender) },
    };
    const sponsored = await Transaction.sponsor(cleanSignable, signerObj);
    const finalized = Transaction.finalize(sponsored);
    const txHash = Buffer.from(Transaction.getAccountTransactionHash(finalized)).toString('hex');

    const { onSigned, ...waitOpts } = pollOpts ?? {};
    if (onSigned) {
        await onSigned({ txHash, expiryEpochSeconds: Number(txExpiry), finalized });
    }
    const sentHash = await c.sendTransaction(finalized);
    const finalizedRes = await waitForFinalizedPolling(c, sentHash ?? txHash, waitOpts);
    return { hash: finalizedRes.hash, summary: finalizedRes.summary, txHash };
}

/**
 * Reconstructs the complete, unbroken CIS-8004 MetadataSet history for tokenId between registration and tip
 * directly from a Concordium node, verifying mint ownership, pinned immutable contract module, zero initial
 * operators, and uninterrupted exclusive ownership across every owner transaction block.
 */
export async function readRegistryHistory(
    tokenId,
    {
        tipBlockHash,
        tipBlockHeight,
        agent,
        hintAnchorTxHashes = [],
        maxOwnerTxs = 2000,
        maxAdminTxs = maxOwnerTxs,
        streamTimeoutMs = DEFAULT_RPC_TIMEOUT_MS,
        nodeClient,
        pool: providedPool,
    } = {},
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
    const accountNonceCaches = new Map();

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

    const nonceAtFor = (accountAddr, h) => {
        const acctKey = accountAddr.address;
        let cache = accountNonceCaches.get(acctKey);
        if (!cache) {
            cache = new Map();
            accountNonceCaches.set(acctKey, cache);
        }
        let p = cache.get(h);
        if (!p) {
            p = (async () => {
                const bh = await blockHashAt(h);
                const info = await rpc.run(() => c.getAccountInfo(accountAddr, bh));
                return BigInt(info.accountNonce?.value ?? info.accountNonce);
            })();
            cache.set(h, p);
        }
        return p;
    };

    const collectStreamWithTimeout = async (streamFn, isEarlyStop = null) => {
        const ac = new AbortController();
        let timedOut = false;
        const timeoutErr = Object.assign(
            new Error(`gRPC stream timed out after ${streamTimeoutMs}ms`),
            { code: 'DEADLINE_EXCEEDED' },
        );
        const timer = setTimeout(() => {
            timedOut = true;
            ac.abort(timeoutErr);
        }, streamTimeoutMs);
        const abortEarly = (reason) => ac.abort(reason);
        try {
            return await streamFn(ac.signal, abortEarly);
        } catch (err) {
            if (isEarlyStop && isEarlyStop()) return true;
            if (timedOut) throw timeoutErr;
            throw err;
        } finally {
            clearTimeout(timer);
        }
    };

    const getBlockEvents = async (h) => {
        const bh = await blockHashAt(h);
        return rpc.run(() =>
            collectStreamWithTimeout(async (signal) => {
                const items = [];
                for await (const s of c.getBlockTransactionEvents(bh, signal)) {
                    if (signal.aborted) throw signal.reason;
                    items.push(s);
                }
                return items;
            }),
        );
    };

    // 1. Locate registration block height via 2-point linear interpolation + binary/regula-falsi search.
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

    // 2. Find Mint event for tokenId in [regHeight-2n, regHeight+2n] and verify Mint.owner matches current owner.
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
                            txIndex: summary.index !== undefined && summary.index !== null ? Number(summary.index) : txIdx,
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
    const loSummaries = await getBlockEvents(lo);
    const mintHits = findMintsInBlock(lo, loSummaries);
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
    if (typeof mintHit.owner !== 'string' || !isSameAccount(mintHit.owner, owner)) {
        throw new Error(`token ${targetTokenId} was minted to ${JSON.stringify(mintHit.owner)}, not current owner ${owner}`);
    }
    if (mintHit.amount !== 1n) {
        throw new Error(`token ${targetTokenId} Mint amount was ${mintHit.amount}, expected 1`);
    }

    const regHeight = mintHit.height;
    const regBlockHash = await blockHashAt(regHeight);
    const resolvedTipBlockHash = tipBlockHash ?? (await blockHashAt(tipH));

    // 3. Verify registry sourceModule.moduleRef and admin identity at both registration and tip.
    const [regInst, tipInst, regAdmin, tipAdmin] = await Promise.all([
        rpc.run(() => c.getInstanceInfo(registryAddr, regBlockHash)),
        rpc.run(() => c.getInstanceInfo(registryAddr, resolvedTipBlockHash)),
        rpc.limit(() => readAdmin({ blockHash: regBlockHash, nodeClient: c })),
        rpc.limit(() => readAdmin({ blockHash: resolvedTipBlockHash, nodeClient: c })),
    ]);
    const refOf = (info) => info?.sourceModule?.moduleRef ?? String(info?.sourceModule ?? '');
    if (refOf(regInst) !== REGISTRY_MODULE_REF || refOf(tipInst) !== REGISTRY_MODULE_REF) {
        throw new Error(
            `registry contract sourceModule mismatch (reg=${refOf(regInst)}, tip=${refOf(tipInst)}, expected=${REGISTRY_MODULE_REF})`,
        );
    }
    if ((regAdmin !== null) !== (tipAdmin !== null) || (regAdmin !== null && !isSameAccount(regAdmin, tipAdmin))) {
        throw new Error(`registry admin changed between registration (${regAdmin}) and tip (${tipAdmin})`);
    }
    const adminAddr = regAdmin !== null && !isSameAccount(regAdmin, owner) ? AccountAddress.fromBase58(regAdmin) : null;

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
        let matched = false;
        const hasInitialOperator = await rpc.run(() =>
            collectStreamWithTimeout(
                async (signal, abortEarly) => {
                    for await (const entry of c.getInstanceState(registryAddr, regBlockHash, signal)) {
                        if (signal.aborted) throw signal.reason;
                        const k = typeof entry.key === 'string' ? entry.key.toLowerCase() : Buffer.from(entry.key).toString('hex');
                        if (k.startsWith(opSubmap)) {
                            matched = true;
                            abortEarly();
                            return true;
                        }
                    }
                    return false;
                },
                () => matched,
            ),
        );
        if (hasInitialOperator) {
            throw new Error(`owner ${owner} had pre-existing CIS-2 operator(s) at registration block ${regHeight}`);
        }
    }

    const checkAccountNonceSpan = async (accountAddr, maxTxs, label) => {
        const [nStart, nEnd] = await Promise.all([nonceAtFor(accountAddr, regHeight), nonceAtFor(accountAddr, tipH)]);
        if (nEnd < nStart) {
            throw new Error(`non-monotonic ${label} accountNonce (${nEnd} < ${nStart})`);
        }
        if (nEnd - nStart > BigInt(maxTxs)) {
            const capName = label === 'admin' ? 'maxAdminTxs' : 'maxOwnerTxs';
            throw new Error(`${label} ${accountAddr.address} executed ${nEnd - nStart} transactions between block ${regHeight} and ${tipH}, exceeding ${capName}=${maxTxs}`);
        }
        return { nStart, nEnd };
    };

    const scanAccountTxBlocks = async (accountAddr, splitPoints, maxTxs, label) => {
        const { nStart, nEnd } = await checkAccountNonceSpan(accountAddr, maxTxs, label);
        if (nEnd === nStart) return [];

        const binaryRange = async (rLo, rHi, nLo, nHi) => {
            if (nHi < nLo) throw new Error(`non-monotonic ${label} accountNonce (${nHi} < ${nLo})`);
            if (nLo === nHi || rLo >= rHi) return [];
            if (rHi === rLo + 1n) return [rHi];
            const mid = (rLo + rHi) / 2n;
            const nMid = await nonceAtFor(accountAddr, mid);
            if (nMid < nLo || nHi < nMid) throw new Error(`non-monotonic ${label} accountNonce across [${rLo}, ${mid}, ${rHi}]`);
            const [left, right] = await Promise.all([
                nMid > nLo ? binaryRange(rLo, mid, nLo, nMid) : [],
                nHi > nMid ? binaryRange(mid, rHi, nMid, nHi) : [],
            ]);
            return left.concat(right);
        };

        const scanRange = async (rLo, rHi, nLo, nHi) => {
            if (nHi < nLo) throw new Error(`non-monotonic ${label} accountNonce (${nHi} < ${nLo})`);
            if (nLo === nHi || rLo >= rHi) return [];
            if (rHi === rLo + 1n) return [rHi];
            if (rHi - rLo <= 32n) return binaryRange(rLo, rHi, nLo, nHi);

            let prev = rLo;
            let step = 8n;
            while (prev < rHi) {
                const next = prev + step < rHi ? prev + step : rHi;
                const nNext = await nonceAtFor(accountAddr, next);
                if (nNext < nLo) throw new Error(`non-monotonic ${label} accountNonce (${nNext} < ${nLo})`);
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

        const pointNonces = await Promise.all(splitPoints.map((p) => nonceAtFor(accountAddr, p)));
        const intervalResults = await Promise.all(
            splitPoints.slice(0, -1).map((p, i) => scanRange(p, splitPoints[i + 1], pointNonces[i], pointNonces[i + 1])),
        );
        return intervalResults.flat();
    };

    // 5. Check owner (and admin if distinct) nonce span BEFORE following hint links.
    const ownerNonceSpanCheck = await checkAccountNonceSpan(ownerAddr, maxOwnerTxs, 'owner');
    const ownerNonceSpan = Number(ownerNonceSpanCheck.nEnd - ownerNonceSpanCheck.nStart);
    if (adminAddr) await checkAccountNonceSpan(adminAddr, maxAdminTxs, 'admin');

    // 6. Follow hintAnchorTxHashes / prevAnchorTx links (bounded & owner/token/height-validated) to get split hints.
    const maxHintHops = Math.min(Number(maxOwnerTxs), 256);
    const seenHints = new Set();
    const hintHeightSet = new Set();
    const hintQueue = [...hintAnchorTxHashes].filter((h) => typeof h === 'string' && /^[0-9a-f]{64}$/.test(h));
    let hintHops = 0;
    while (hintQueue.length > 0 && hintHops < maxHintHops) {
        const hTx = hintQueue.shift();
        if (seenHints.has(hTx)) continue;
        seenHints.add(hTx);
        hintHops += 1;
        try {
            const rd = await rpc.limit(() => readRegisterData(hTx, c));
            if (!isSameAccount(rd.sender, owner)) continue;
            const h = BigInt(rd.blockHeight);
            if (!(h > regHeight && h < tipH)) continue;
            const dec = decodeAnchor(rd.data);
            if (dec.tokenId !== targetTokenId) continue;
            hintHeightSet.add(h);
            if (dec.prevAnchorTx && !seenHints.has(dec.prevAnchorTx)) hintQueue.push(dec.prevAnchorTx);
        } catch {
            // Hints are strictly advisory; exhaustive nonce scanning guarantees completeness.
        }
    }

    // 7. Exhaustively find every block in (regHeight, tipH] where owner's (or admin's) accountNonce increased.
    const splitSet = new Set([regHeight, tipH]);
    for (const h of hintHeightSet) {
        if (h - 1n > regHeight) splitSet.add(h - 1n);
        splitSet.add(h);
    }
    const ownerPoints = [...splitSet].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const [ownerHeights, adminHeights] = await Promise.all([
        scanAccountTxBlocks(ownerAddr, ownerPoints, maxOwnerTxs, 'owner'),
        adminAddr ? scanAccountTxBlocks(adminAddr, [regHeight, tipH], maxAdminTxs, 'admin') : [],
    ]);
    const discoveredHeights = [...new Set([...ownerHeights, ...adminHeights])].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

    // 8. Stream getBlockTransactionEvents for regHeight and discovered blocks in bounded ascending batches.
    const collected = [];

    const processBlock = (h, summaries, startAfterMint) => {
        for (let txIdx = 0; txIdx < summaries.length; txIdx++) {
            const summary = summaries[txIdx];
            if (!Array.isArray(summary.events) || summary.rejectReason) continue;
            const txHash = summary.hash.toString();
            const txSender = addressToString(summary.sender);
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
                    if (parsed.type === 'Unknown') {
                        throw new Error(`unknown CIS-8004 event tag 0x${parsed.tag.toString(16)} at block ${h} (tx ${txHash})`);
                    }
                    if (parsed.type === 'AdminTransferred') {
                        throw new Error(`registry admin transferred at block ${h} (tx ${txHash})`);
                    }
                    if (parsed.type === 'Transfer' && parsed.tokenId === targetTokenId) {
                        if (!isSameAccount(parsed.from, owner) || !isSameAccount(parsed.to, owner)) {
                            throw new Error(`token ${targetTokenId} was transferred (${parsed.from} -> ${parsed.to}) at block ${h} (tx ${txHash})`);
                        }
                    } else if (parsed.type === 'Burn' && parsed.tokenId === targetTokenId) {
                        throw new Error(`token ${targetTokenId} was burned at block ${h} (tx ${txHash})`);
                    } else if (parsed.type === 'UpdateOperator' && parsed.update === 'Add' && typeof parsed.owner === 'string' && isSameAccount(parsed.owner, owner)) {
                        throw new Error(`owner ${owner} added CIS-2 operator ${parsed.operator} at block ${h} (tx ${txHash})`);
                    } else if (parsed.type === 'MetadataSet') {
                        const meta = parseMetadataSetEvent(rawHex, targetTokenId);
                        if (meta) {
                            if (summary.type !== 'accountTransaction' || !isSameAccount(txSender, owner)) {
                                throw new Error(`MetadataSet for token ${targetTokenId} at block ${h} was submitted by ${txSender || 'non-account'}, not owner ${owner}`);
                            }
                            const txIndex = summary.index !== undefined && summary.index !== null ? Number(summary.index) : txIdx;
                            collected.push({ ...meta, sender: txSender, txHash, blockHeight: Number(h), txIndex });
                        }
                    }
                }
            }
        }
    };

    processBlock(regHeight, mintHit.summaries, true);
    const BATCH_SIZE = 10;
    for (let i = 0; i < discoveredHeights.length; i += BATCH_SIZE) {
        const batch = discoveredHeights.slice(i, i + BATCH_SIZE);
        const batchEvents = await Promise.all(batch.map(getBlockEvents));
        for (let j = 0; j < batch.length; j++) {
            processBlock(batch[j], batchEvents[j], false);
        }
    }

    return {
        regHeight: Number(regHeight),
        regBlockHash: regBlockHash.toString(),
        mintTxHash: mintHit.txHash,
        mintTxIndex: mintHit.txIndex,
        owner,
        scannedBlocks: discoveredHeights.length,
        ownerNonceSpan,
        maxOwnerTxs,
        events: collected,
    };
}

export const chainIsUnbroken = (anchors) => anchors.every((a, i) => a.prevAnchorTx === (i === 0 ? null : anchors[i - 1].txHash));
export const coverageGrows = (anchors) => anchors.every((a, i) => a.toSeq > (i === 0 ? 0 : anchors[i - 1].toSeq));

function parseWitnessEventValue(event, owner) {
    const val = utf8Fatal.decode(event.value);
    if (val === '') return null;
    let parsed;
    try {
        parsed = AccountAddress.fromBase58(val);
    } catch (err) {
        throw new Error(`countersign.witness value in tx ${event.txHash} is invalid Base58Check: ${err.message}`);
    }
    if (parsed.address !== val) {
        throw new Error(`countersign.witness value in tx ${event.txHash} is not in canonical Base58Check form`);
    }
    if (owner && isSameAccount(val, owner)) {
        throw new Error(`countersign.witness in tx ${event.txHash} cannot equal owner account ${owner}`);
    }
    return val;
}

function walkWitnessTimeline(history) {
    if (!history || !Array.isArray(history.events)) {
        throw new Error('history with events array is required');
    }
    let activeWitness = null;
    let sawWitnessEvent = false;
    let lastWitnessEvent = null;
    const transitions = [];
    const anchorSpecs = [];
    for (let eventIdx = 0; eventIdx < history.events.length; eventIdx++) {
        const e = history.events[eventIdx];
        if (e.key === WITNESS_KEY) {
            sawWitnessEvent = true;
            activeWitness = parseWitnessEventValue(e, history.owner);
            lastWitnessEvent = {
                witness: activeWitness,
                txHash: e.txHash,
                blockHeight: e.blockHeight,
                timestampMs: e.timestampMs,
                sender: e.sender,
                txIndex: e.txIndex ?? null,
                eventIndex: eventIdx,
            };
            transitions.push(lastWitnessEvent);
        } else if (e.key === ANCHOR_KEY) {
            anchorSpecs.push({
                event: e,
                eventIndex: eventIdx,
                authorizedWitness: activeWitness,
                witnessEvent: lastWitnessEvent,
            });
        }
    }
    return {
        currentWitness: activeWitness,
        sawWitnessEvent,
        transitions,
        anchorSpecs,
    };
}

/**
 * Chronologically replays `countersign.witness` MetadataSet events in `history.events`, enforcing canonical non-owner
 * Base58Check values (or empty string to clear). Performs zero RPCs.
 */
export function extractWitnessState(history) {
    const { currentWitness, sawWitnessEvent, transitions } = walkWitnessTimeline(history);
    return { currentWitness, sawWitnessEvent, transitions };
}

/**
 * Confirms on-chain `CIS-8004.getMetadata(tokenId, 'countersign.witness')` agrees with the reconstructed
 * `MetadataSet` timeline (accounting for CIS-8004 storing cleared metadata as `""` rather than deleting the key).
 */
export function witnessMatchesOnChain(witnessState, onChainWitness) {
    if (witnessState.currentWitness !== null && witnessState.currentWitness !== undefined) {
        return onChainWitness === witnessState.currentWitness;
    }
    if (witnessState.sawWitnessEvent === false) {
        return onChainWitness === null;
    }
    return onChainWitness === null || onChainWitness === '';
}

/** Loads and decodes every register-data anchor transaction referenced in MetadataSet history. */
export async function loadAnchorsFromHistory(history, nodeClient, tipBlockHeight) {
    const { anchorSpecs } = walkWitnessTimeline(history);
    const pool = createRpcPool(5);
    return pool.map(anchorSpecs, async ({ event: p, eventIndex, authorizedWitness, witnessEvent }) => {
        const txHash = utf8Fatal.decode(p.value);
        if (!TX_RE.test(txHash)) {
            throw new Error(`the pointer was once set to a value that is not a transaction hash (in ${p.txHash})`);
        }
        const tx = await readRegisterData(txHash, nodeClient);
        if (tipBlockHeight !== undefined && tx.blockHeight > Number(tipBlockHeight)) {
            throw new Error(`anchor transaction ${txHash} at block ${tx.blockHeight} is after pinned tip block ${tipBlockHeight}`);
        }
        return {
            txHash,
            ...decodeAnchor(tx.data),
            sender: tx.sender,
            blockTime: tx.blockTime,
            blockHeight: tx.blockHeight,
            pointerBlockHeight: p.blockHeight,
            pointerTxIndex: p.txIndex ?? null,
            pointerEventIndex: eventIndex,
            authorizedWitness,
            witnessEvent,
        };
    });
}

/** Verifies chain continuity, authorized signer, trail commitments, and current pointer alignment across existing anchors. */
export function verifyExistingAnchors(existing, { tokenId, ownerAccount, commitmentAt, currentPointer }) {
    if (!chainIsUnbroken(existing) || !coverageGrows(existing)) {
        throw new Error('the existing anchors do not form one chain; refusing to add to it');
    }
    const getCommitment = typeof commitmentAt === 'function' ? commitmentAt : (seq) => commitmentAt.get(seq);
    for (const a of existing) {
        const expectedSender = a.authorizedWitness ?? ownerAccount;
        if (!isSameAccount(a.sender, expectedSender) || a.tokenId !== tokenId) {
            const role = a.authorizedWitness ? 'witness' : 'owner';
            throw new Error(`existing anchor ${a.txHash} does not belong to authorized ${role} ${expectedSender} / token ${tokenId}`);
        }
        const got = getCommitment(a.toSeq);
        const gotHex = Buffer.isBuffer(got) ? got.toString('hex') : got;
        if (gotHex !== a.commitment) {
            throw new Error(`this trail does not match the anchor covering records 1..${a.toSeq} (${a.txHash}); refusing to anchor`);
        }
    }
    const prev = existing.at(-1) ?? null;
    if (currentPointer !== (prev?.txHash ?? null)) {
        throw new Error('the current pointer is not the last one in the event history yet; retry shortly');
    }
    return prev;
}
