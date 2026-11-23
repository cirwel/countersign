// x402 v2 payment protocol codecs, crash-safe PaymentLedger, payment verifiers, and SSRF-safe witness clients.
import crypto from 'node:crypto';
import fs from 'node:fs';
import { AccountAddress } from '@concordium/web-sdk';
import { TX_RE, client, isSameAccount, readAccountTransfer, writeFileAtomic } from './chain.mjs';
import { safeJsonFetch } from './cis8004.mjs';
import { REGISTRY, TESTNET_GENESIS } from './registry.mjs';
import { canonical } from './trail.mjs';

export const X402_VERSION = 2;
export const CONCORDIUM_TESTNET_CAIP2 = `ccd:${TESTNET_GENESIS.slice(0, 32)}`;
export const HEADER_PAYMENT_REQUIRED = 'payment-required';
export const HEADER_PAYMENT_SIGNATURE = 'payment-signature';
export const HEADER_PAYMENT_RESPONSE = 'payment-response';

const U64_MAX = (1n << 64n) - 1n;
const TOKEN_ID_RE = /^(?:0|[1-9][0-9]*)$/;
const STRICT_BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const utf8Fatal = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function isPlainObject(v) {
    return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function assertCanonicalAccount(addr, label = 'account') {
    if (typeof addr !== 'string' || addr.length === 0) {
        throw new Error(`${label} must be a non-empty Base58Check address`);
    }
    const parsed = AccountAddress.fromBase58(addr);
    if (parsed.address !== addr) {
        throw new Error(`${label} ${addr} is not in canonical Base58Check form`);
    }
    return parsed.address;
}

function assertTokenIdStr(tokenId) {
    const s = typeof tokenId === 'bigint' || typeof tokenId === 'number' ? String(tokenId) : tokenId;
    if (typeof s !== 'string' || !TOKEN_ID_RE.test(s) || BigInt(s) > U64_MAX) {
        throw new Error(`invalid u64 tokenId: ${tokenId}`);
    }
    return s;
}

function normalizeBinding(binding) {
    if (!isPlainObject(binding)) {
        throw new Error('payment binding must be a plain object');
    }
    const tokenId = assertTokenIdStr(binding.tokenId);
    if (!Number.isSafeInteger(binding.toSeq) || binding.toSeq <= 0) {
        throw new Error(`invalid binding toSeq: ${binding.toSeq}`);
    }
    if (typeof binding.commitment !== 'string' || !TX_RE.test(binding.commitment)) {
        throw new Error('binding commitment must be 64 lowercase hex characters');
    }
    const prev = binding.prevAnchorTx ?? null;
    if (prev !== null && (typeof prev !== 'string' || !TX_RE.test(prev))) {
        throw new Error('binding prevAnchorTx must be null or 64 lowercase hex characters');
    }
    return {
        tokenId,
        toSeq: binding.toSeq,
        commitment: binding.commitment,
        prevAnchorTx: prev,
    };
}

function bindingsEqual(a, b) {
    return (
        a.tokenId === b.tokenId &&
        a.toSeq === b.toSeq &&
        a.commitment === b.commitment &&
        (a.prevAnchorTx ?? null) === (b.prevAnchorTx ?? null)
    );
}

function normalizeBaseUrl(rawUrl, label = 'URL') {
    let u;
    try {
        u = new URL(rawUrl);
    } catch {
        throw new Error(`invalid ${label}: ${rawUrl}`);
    }
    const cleanPath = u.pathname.replace(/\/+$/, '');
    return `${u.origin}${cleanPath}`;
}

function conflictError(message) {
    return Object.assign(new Error(message), { statusCode: 409 });
}

/** Encodes a plain JSON object into a base64 x402 HTTP header value. */
export function encodeX402Header(obj) {
    if (!isPlainObject(obj)) {
        throw new TypeError('x402 header payload must be a plain object');
    }
    return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64');
}

/** Strictly decodes and validates a base64-encoded JSON object from an x402 HTTP header. */
export function decodeX402Header(str, label = 'x402 header') {
    if (typeof str !== 'string') {
        throw new Error(`${label} must be a string`);
    }
    const trimmed = str.trim();
    if (trimmed.length === 0 || trimmed.length % 4 !== 0 || !STRICT_BASE64_RE.test(trimmed)) {
        throw new Error(`${label} is not valid base64`);
    }
    const raw = Buffer.from(trimmed, 'base64');
    if (raw.length === 0) {
        throw new Error(`${label} decoded to empty bytes`);
    }
    let text;
    try {
        text = utf8Fatal.decode(raw);
    } catch (err) {
        throw new Error(`${label} is not valid UTF-8: ${err.message}`);
    }
    let parsed;
    try {
        parsed = JSON.parse(text);
    } catch (err) {
        throw new Error(`${label} is not valid JSON: ${err.message}`);
    }
    if (!isPlainObject(parsed)) {
        throw new Error(`${label} must decode to a JSON object`);
    }
    return parsed;
}

/**
 * Computes the deterministic 32-byte payment memo binding an x402 payment to one exact anchor transition:
 * SHA-256("countersign.x402.v1\n" + tokenId + "\n" + toSeq + "\n" + commitment + "\n" + (prevAnchorTx ?? "genesis"))
 */
export function computePaymentMemo({ tokenId, toSeq, commitment, prevAnchorTx = null }) {
    const tid = assertTokenIdStr(tokenId);
    if (!Number.isSafeInteger(toSeq) || toSeq <= 0) {
        throw new Error(`toSeq must be a positive safe integer, got ${toSeq}`);
    }
    if (typeof commitment !== 'string' || !TX_RE.test(commitment)) {
        throw new Error('commitment must be 64 lowercase hex characters');
    }
    if (prevAnchorTx !== null && (typeof prevAnchorTx !== 'string' || !TX_RE.test(prevAnchorTx))) {
        throw new Error('prevAnchorTx must be null or 64 lowercase hex characters');
    }
    const preimage = `countersign.x402.v1\n${tid}\n${toSeq}\n${commitment}\n${prevAnchorTx ?? 'genesis'}`;
    return crypto.createHash('sha256').update(preimage, 'utf8').digest('hex');
}

/** Constructs an x402 v2 PaymentRequired envelope for a Concordium testnet witness anchor request. */
export function createPaymentRequirements({
    payTo,
    amountMicroCcd,
    resource,
    memoHex,
    tokenId,
    toSeq,
    commitment,
    prevAnchorTx = null,
    witnessAccount,
    sponsorPointer,
    maxTimeoutSeconds = 300,
}) {
    const canonicalPayTo = assertCanonicalAccount(payTo, 'payTo');
    const amt = BigInt(amountMicroCcd);
    if (amt < 0n) throw new Error(`amountMicroCcd must be non-negative, got ${amountMicroCcd}`);
    if (!Number.isSafeInteger(maxTimeoutSeconds) || maxTimeoutSeconds <= 0) {
        throw new Error(`maxTimeoutSeconds must be a positive safe integer, got ${maxTimeoutSeconds}`);
    }
    const tid = assertTokenIdStr(tokenId);
    const computedMemo = computePaymentMemo({ tokenId: tid, toSeq, commitment, prevAnchorTx });
    if (memoHex !== undefined && memoHex !== null) {
        if (typeof memoHex !== 'string' || memoHex !== computedMemo) {
            throw new Error('memoHex does not match computed payment memo');
        }
    }
    if (witnessAccount !== undefined) {
        assertCanonicalAccount(witnessAccount, 'witnessAccount');
    }
    const resourceObj =
        typeof resource === 'string'
            ? { url: resource, description: 'Countersign witness anchor', mimeType: 'application/json' }
            : resource;
    if (!isPlainObject(resourceObj) || typeof resourceObj.url !== 'string' || resourceObj.url.length === 0) {
        throw new Error('resource must be a URL string or { url, ... } object');
    }
    return {
        x402Version: X402_VERSION,
        resource: resourceObj,
        accepts: [
            {
                scheme: 'exact',
                network: CONCORDIUM_TESTNET_CAIP2,
                amount: amt.toString(),
                asset: 'CCD',
                payTo: canonicalPayTo,
                maxTimeoutSeconds,
                extra: {
                    memoHex: computedMemo,
                    tokenId: tid,
                    toSeq,
                    commitment,
                    prevAnchorTx: prevAnchorTx ?? null,
                    ...(witnessAccount !== undefined ? { witnessAccount } : {}),
                    ...(sponsorPointer !== undefined ? { sponsorPointer: Boolean(sponsorPointer) } : {}),
                },
            },
        ],
    };
}

/**
 * Crash-safe atomic payment and sponsored-pointer ledger.
 * Transitions: `claimed` -> `broadcasted` -> `committed`.
 * Entries in `broadcasted` or `committed` are NEVER released by `releasePreBroadcast` so ambiguous or
 * crashed broadcasts cannot allow payment replay.
 */
export class PaymentLedger {
    constructor(filePath = null) {
        this.filePath = filePath;
        this.payments = new Map();
        this.sponsorPointers = new Map();
        if (this.filePath) {
            this.load();
        }
    }

    load() {
        this.payments.clear();
        this.sponsorPointers.clear();
        if (!this.filePath || !fs.existsSync(this.filePath)) return;
        let parsed;
        try {
            parsed = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
        } catch (err) {
            throw new Error(`corrupt payment ledger ${this.filePath}: ${err.message}`);
        }
        if (!isPlainObject(parsed) || parsed.version !== 1) {
            throw new Error(`invalid payment ledger ${this.filePath}: expected version 1 JSON object`);
        }
        if (parsed.payments !== undefined) {
            if (!isPlainObject(parsed.payments)) {
                throw new Error(`invalid payment ledger ${this.filePath}: payments must be an object`);
            }
            for (const [k, v] of Object.entries(parsed.payments)) {
                if (!isPlainObject(v)) throw new Error(`corrupt payment entry ${k} in ${this.filePath}`);
                this.payments.set(k, v);
            }
        }
        if (parsed.sponsorPointers !== undefined) {
            if (!isPlainObject(parsed.sponsorPointers)) {
                throw new Error(`invalid payment ledger ${this.filePath}: sponsorPointers must be an object`);
            }
            for (const [k, v] of Object.entries(parsed.sponsorPointers)) {
                if (!isPlainObject(v)) throw new Error(`corrupt sponsorPointers entry ${k} in ${this.filePath}`);
                this.sponsorPointers.set(k, v);
            }
        }
    }

    _persist() {
        if (!this.filePath) return;
        const payments = Object.create(null);
        for (const [k, v] of this.payments.entries()) payments[k] = v;
        const sponsorPointers = Object.create(null);
        for (const [k, v] of this.sponsorPointers.entries()) sponsorPointers[k] = v;
        const payload = {
            version: 1,
            payments,
            sponsorPointers,
            updatedAt: new Date().toISOString(),
        };
        writeFileAtomic(this.filePath, JSON.stringify(payload, null, 2) + '\n', { mode: 0o600 });
    }

    get(paymentId) {
        if (typeof paymentId !== 'string' || paymentId.length === 0) return null;
        return this.payments.get(paymentId) ?? null;
    }

    findBySettlementTx({ network = CONCORDIUM_TESTNET_CAIP2, transaction } = {}) {
        if (typeof transaction !== 'string' || transaction.length === 0) return null;
        const legacyKey = `facilitator:${network}:${transaction}`;
        const direct = this.payments.get(legacyKey);
        if (direct) return direct;
        for (const entry of this.payments.values()) {
            if (
                entry.settled?.transaction === transaction &&
                (entry.settled?.network ?? CONCORDIUM_TESTNET_CAIP2) === network
            ) {
                return entry;
            }
        }
        return null;
    }

    assertNoEquivocation(binding, currentPaymentId = null) {
        const normBinding = normalizeBinding(binding);
        for (const e of this.payments.values()) {
            if (currentPaymentId !== null && e.paymentId === currentPaymentId) continue;
            if (e.status !== 'settled' && e.status !== 'broadcasted' && e.status !== 'committed') continue;
            if (!isPlainObject(e.binding)) continue;
            if (
                String(e.binding.tokenId) === normBinding.tokenId &&
                (e.binding.prevAnchorTx ?? null) === normBinding.prevAnchorTx
            ) {
                if (e.binding.toSeq !== normBinding.toSeq || e.binding.commitment !== normBinding.commitment) {
                    throw conflictError(
                        `equivocating anchor request for token ${normBinding.tokenId} at prevAnchorTx ${normBinding.prevAnchorTx ?? 'genesis'} (conflicts with ${e.status} ${e.paymentId})`,
                    );
                }
            }
        }
    }

    claim(paymentId, binding) {
        if (typeof paymentId !== 'string' || paymentId.trim().length === 0) {
            throw new Error('paymentId must be a non-empty string');
        }
        const normBinding = normalizeBinding(binding);
        const existing = this.payments.get(paymentId);
        if (existing) {
            const existingBinding = normalizeBinding(existing.binding);
            if (!bindingsEqual(existingBinding, normBinding)) {
                throw conflictError(`payment ${paymentId} was already claimed for a different anchor binding`);
            }
            if (existing.status === 'committed') {
                return { action: 'return_cached', entry: existing };
            }
            throw conflictError(`payment ${paymentId} is already ${existing.status}`);
        }
        this.assertNoEquivocation(normBinding, paymentId);
        const now = new Date().toISOString();
        const entry = {
            paymentId,
            status: 'claimed',
            binding: normBinding,
            settled: null,
            txHash: null,
            expiryEpochSeconds: null,
            result: null,
            createdAt: now,
            updatedAt: now,
        };
        this.payments.set(paymentId, entry);
        this._persist();
        return { action: 'proceed', entry };
    }

    markSettled(paymentId, settledInfo = {}) {
        const entry = this.payments.get(paymentId);
        if (!entry) throw new Error(`unknown paymentId ${paymentId} in markSettled`);
        if (entry.status !== 'claimed' && entry.status !== 'settled') {
            throw new Error(`cannot mark payment ${paymentId} settled from status ${entry.status}`);
        }
        this.assertNoEquivocation(entry.binding, paymentId);
        entry.status = 'settled';
        entry.settled = settledInfo ?? {};
        entry.updatedAt = new Date().toISOString();
        this._persist();
        return entry;
    }

    markBroadcast(paymentId, { txHash, expiryEpochSeconds = null } = {}) {
        const entry = this.payments.get(paymentId);
        if (!entry) throw new Error(`unknown paymentId ${paymentId} in markBroadcast`);
        if (entry.status !== 'claimed' && entry.status !== 'settled') {
            throw new Error(`cannot mark payment ${paymentId} broadcast from status ${entry.status}`);
        }
        if (typeof txHash !== 'string' || !TX_RE.test(txHash)) {
            throw new Error(`invalid txHash in markBroadcast: ${txHash}`);
        }
        this.assertNoEquivocation(entry.binding, paymentId);
        entry.status = 'broadcasted';
        entry.txHash = txHash;
        entry.expiryEpochSeconds = expiryEpochSeconds ?? null;
        entry.updatedAt = new Date().toISOString();
        this._persist();
        return entry;
    }

    releaseBroadcastKeepSettled(paymentId) {
        const entry = this.payments.get(paymentId);
        if (!entry || entry.status !== 'broadcasted') return false;
        entry.status = 'settled';
        entry.txHash = null;
        entry.expiryEpochSeconds = null;
        entry.updatedAt = new Date().toISOString();
        this._persist();
        return true;
    }

    commit(paymentId, result) {
        const entry = this.payments.get(paymentId);
        if (!entry) throw new Error(`unknown paymentId ${paymentId} in commit`);
        if (entry.status !== 'claimed' && entry.status !== 'settled' && entry.status !== 'broadcasted') {
            throw new Error(`cannot commit payment ${paymentId} from status ${entry.status}`);
        }
        if (!isPlainObject(result) || typeof result.txHash !== 'string' || !TX_RE.test(result.txHash)) {
            throw new Error('commit requires result with valid 64-hex txHash');
        }
        entry.status = 'committed';
        entry.txHash = result.txHash;
        entry.result = result;
        entry.updatedAt = new Date().toISOString();
        this._persist();
        return entry;
    }

    releasePreBroadcast(paymentId) {
        if (typeof paymentId !== 'string' || paymentId.length === 0) return false;
        const entry = this.payments.get(paymentId);
        if (!entry || entry.status !== 'claimed') return false;
        this.payments.delete(paymentId);
        this._persist();
        return true;
    }

    _sponsorKey(tokenId, anchorTxHash) {
        const tid = assertTokenIdStr(tokenId);
        if (typeof anchorTxHash !== 'string' || !TX_RE.test(anchorTxHash)) {
            throw new Error(`invalid anchorTxHash: ${anchorTxHash}`);
        }
        return { key: `${tid}:${anchorTxHash}`, tokenId: tid, anchorTxHash };
    }

    getSponsor(tokenId, anchorTxHash) {
        const { key } = this._sponsorKey(tokenId, anchorTxHash);
        return this.sponsorPointers.get(key) ?? null;
    }

    claimSponsor(tokenId, anchorTxHash, binding = null) {
        const { key, tokenId: tid, anchorTxHash: anchorHash } = this._sponsorKey(tokenId, anchorTxHash);
        const normReqHash =
            binding?.requestHash !== undefined && binding?.requestHash !== null ? String(binding.requestHash) : null;
        const existing = this.sponsorPointers.get(key);
        if (existing) {
            if (existing.status === 'committed') {
                if (normReqHash !== null && existing.requestHash !== null && existing.requestHash !== normReqHash) {
                    throw conflictError(`sponsor pointer ${key} was already committed with a different payload`);
                }
                return { action: 'return_cached', entry: existing };
            }
            throw conflictError(`sponsor pointer ${key} is already ${existing.status}`);
        }
        const now = new Date().toISOString();
        const entry = {
            key,
            tokenId: tid,
            anchorTxHash: anchorHash,
            requestHash: normReqHash,
            status: 'claimed',
            metadataTxHash: null,
            expiryEpochSeconds: null,
            result: null,
            createdAt: now,
            updatedAt: now,
        };
        this.sponsorPointers.set(key, entry);
        this._persist();
        return { action: 'proceed', entry };
    }

    markSponsorBroadcast(tokenId, anchorTxHash, { metadataTxHash, expiryEpochSeconds = null } = {}) {
        const { key } = this._sponsorKey(tokenId, anchorTxHash);
        const entry = this.sponsorPointers.get(key);
        if (!entry) throw new Error(`unknown sponsor pointer ${key} in markSponsorBroadcast`);
        if (entry.status !== 'claimed') {
            throw new Error(`cannot mark sponsor pointer ${key} broadcast from status ${entry.status}`);
        }
        if (typeof metadataTxHash !== 'string' || !TX_RE.test(metadataTxHash)) {
            throw new Error(`invalid metadataTxHash in markSponsorBroadcast: ${metadataTxHash}`);
        }
        entry.status = 'broadcasted';
        entry.metadataTxHash = metadataTxHash;
        entry.expiryEpochSeconds = expiryEpochSeconds ?? null;
        entry.updatedAt = new Date().toISOString();
        this._persist();
        return entry;
    }

    commitSponsor(tokenId, anchorTxHash, result) {
        const { key } = this._sponsorKey(tokenId, anchorTxHash);
        const entry = this.sponsorPointers.get(key);
        if (!entry) throw new Error(`unknown sponsor pointer ${key} in commitSponsor`);
        if (entry.status !== 'claimed' && entry.status !== 'broadcasted') {
            throw new Error(`cannot commit sponsor pointer ${key} from status ${entry.status}`);
        }
        if (!isPlainObject(result) || typeof result.metadataTxHash !== 'string' || !TX_RE.test(result.metadataTxHash)) {
            throw new Error('commitSponsor requires result with valid 64-hex metadataTxHash');
        }
        entry.status = 'committed';
        entry.metadataTxHash = result.metadataTxHash;
        entry.result = result;
        entry.updatedAt = new Date().toISOString();
        this._persist();
        return entry;
    }

    releasePreBroadcastSponsor(tokenId, anchorTxHash) {
        const { key } = this._sponsorKey(tokenId, anchorTxHash);
        const entry = this.sponsorPointers.get(key);
        if (!entry || entry.status !== 'claimed') return false;
        this.sponsorPointers.delete(key);
        this._persist();
        return true;
    }

    releaseExpiredOrFailedSponsor(tokenId, anchorTxHash) {
        const { key } = this._sponsorKey(tokenId, anchorTxHash);
        const entry = this.sponsorPointers.get(key);
        if (!entry || entry.status !== 'broadcasted') return false;
        this.sponsorPointers.delete(key);
        this._persist();
        return true;
    }
}

/**
 * Verifies an x402 `PAYMENT-SIGNATURE` backed directly by a finalized Concordium testnet transferWithMemo
 * paying at least `minAmountMicroCcd` to `payTo` with a constant-time memo match against `expectedMemoHex`.
 */
export function createConcordiumTransferVerifier({ nodeClient, payTo, minAmountMicroCcd }) {
    const canonicalPayTo = assertCanonicalAccount(payTo, 'payTo');
    const minAmount = BigInt(minAmountMicroCcd);
    if (minAmount < 0n) throw new Error(`minAmountMicroCcd must be non-negative, got ${minAmountMicroCcd}`);

    const decodeAndValidateEnvelope = (header) => {
        const decoded = typeof header === 'string' ? decodeX402Header(header, 'PAYMENT-SIGNATURE') : header;
        if (!isPlainObject(decoded)) {
            throw new Error('PAYMENT-SIGNATURE must decode to a JSON object');
        }
        if (decoded.x402Version !== X402_VERSION) {
            throw new Error(`unsupported x402Version ${decoded.x402Version}; expected ${X402_VERSION}`);
        }
        const txHash = decoded.payload?.txHash;
        if (typeof txHash !== 'string' || !TX_RE.test(txHash)) {
            throw new Error('PAYMENT-SIGNATURE payload.txHash must be a 64-hex transaction hash');
        }
        return { decoded, txHash };
    };

    return {
        derivePaymentId(header) {
            const { txHash } = decodeAndValidateEnvelope(header);
            return `ccd:${txHash}`;
        },
        async verify({ header, requirements, expectedMemoHex }) {
            if (typeof expectedMemoHex !== 'string' || !TX_RE.test(expectedMemoHex)) {
                throw new Error('expectedMemoHex must be 64 lowercase hex characters');
            }
            const { decoded, txHash } = decodeAndValidateEnvelope(header);
            if (decoded.accepted !== undefined) {
                if (!isPlainObject(decoded.accepted)) {
                    throw new Error('PAYMENT-SIGNATURE accepted field must be an object');
                }
                if (decoded.accepted.scheme !== 'exact' || decoded.accepted.network !== CONCORDIUM_TESTNET_CAIP2) {
                    throw new Error('PAYMENT-SIGNATURE accepted scheme/network mismatch');
                }
                if (decoded.accepted.payTo !== undefined && !isSameAccount(decoded.accepted.payTo, canonicalPayTo)) {
                    throw new Error('PAYMENT-SIGNATURE accepted payTo mismatch');
                }
                if (decoded.accepted.amount !== undefined && BigInt(decoded.accepted.amount) < minAmount) {
                    throw new Error('PAYMENT-SIGNATURE accepted amount below required minimum');
                }
            }
            if (requirements?.extra?.memoHex && requirements.extra.memoHex !== expectedMemoHex) {
                throw new Error('requirements memoHex disagrees with expectedMemoHex');
            }

            const c = nodeClient ?? (await client());
            const tx = await readAccountTransfer(txHash, c);
            if (!isSameAccount(tx.to, canonicalPayTo)) {
                throw new Error(`payment transfer ${txHash} went to ${tx.to}, expected ${canonicalPayTo}`);
            }
            if (tx.amountMicroCcd < minAmount) {
                throw new Error(`payment transfer ${txHash} amount ${tx.amountMicroCcd} is below required ${minAmount}`);
            }
            if (typeof tx.memoHex !== 'string' || !TX_RE.test(tx.memoHex)) {
                throw new Error(`payment transfer ${txHash} missing 32-byte payment memo`);
            }
            const gotBuf = Buffer.from(tx.memoHex, 'hex');
            const expBuf = Buffer.from(expectedMemoHex, 'hex');
            if (gotBuf.length !== expBuf.length || !crypto.timingSafeEqual(gotBuf, expBuf)) {
                throw new Error(`payment transfer ${txHash} memo does not match expected anchor commitment memo`);
            }

            return {
                paymentId: `ccd:${tx.txHash}`,
                payer: tx.sender,
                txHash: tx.txHash,
                amountMicroCcd: tx.amountMicroCcd.toString(),
                network: CONCORDIUM_TESTNET_CAIP2,
            };
        },
    };
}

/**
 * Verifies and settles an x402 `PAYMENT-SIGNATURE` via an external facilitator over SSRF-hardened HTTPS,
 * separating `/verify` from `/settle` so the witness only settles after ledger claim and pre-broadcast checks.
 */
export function createFacilitatorVerifier({
    facilitatorUrl,
    allowPrivate = false,
    timeoutMs = 15000,
    maxBytes = 65536,
    lookupFn,
    requestFn,
    ca,
} = {}) {
    const baseUrl = normalizeBaseUrl(facilitatorUrl, 'facilitatorUrl');
    const parsePayload = (header, requirements, expectedMemoHex) => {
        const decoded = typeof header === 'string' ? decodeX402Header(header, 'PAYMENT-SIGNATURE') : header;
        if (!isPlainObject(decoded)) {
            throw new Error('PAYMENT-SIGNATURE must decode to a JSON object');
        }
        if (decoded.x402Version !== X402_VERSION) {
            throw new Error(`unsupported x402Version ${decoded.x402Version}; expected ${X402_VERSION}`);
        }
        const paymentRequirements = isPlainObject(requirements) && Array.isArray(requirements.accepts)
            ? requirements.accepts[0]
            : requirements;
        if (requirements !== undefined && !isPlainObject(paymentRequirements)) {
            throw new Error('paymentRequirements object is required for facilitator verification');
        }
        if (expectedMemoHex && paymentRequirements?.extra?.memoHex && paymentRequirements.extra.memoHex !== expectedMemoHex) {
            throw new Error('paymentRequirements memoHex disagrees with expectedMemoHex');
        }
        const paymentId = `facilitator:sha256:${crypto.createHash('sha256').update(canonical(decoded), 'utf8').digest('hex')}`;
        return { decoded, paymentRequirements, paymentId };
    };

    return {
        derivePaymentId(header) {
            const decoded = typeof header === 'string' ? decodeX402Header(header, 'PAYMENT-SIGNATURE') : header;
            if (!isPlainObject(decoded) || decoded.x402Version !== X402_VERSION) {
                throw new Error('invalid PAYMENT-SIGNATURE envelope');
            }
            return `facilitator:sha256:${crypto.createHash('sha256').update(canonical(decoded), 'utf8').digest('hex')}`;
        },
        async verify({ header, requirements, expectedMemoHex }) {
            const { decoded, paymentRequirements, paymentId } = parsePayload(header, requirements, expectedMemoHex);
            if (!isPlainObject(paymentRequirements)) {
                throw new Error('paymentRequirements object is required for facilitator verification');
            }
            const reqBody = {
                x402Version: X402_VERSION,
                paymentPayload: decoded,
                paymentRequirements,
            };
            const verifyRes = await safeJsonFetch(`${baseUrl}/verify`, {
                method: 'POST',
                body: reqBody,
                allowPrivate,
                allowHttp: Boolean(allowPrivate),
                timeoutMs,
                maxBytes,
                lookupFn,
                requestFn,
                ca,
                label: 'x402 facilitator /verify',
                urlLabel: 'facilitatorUrl',
            });
            if (!isPlainObject(verifyRes.data) || verifyRes.data.isValid !== true) {
                throw new Error(
                    `facilitator /verify rejected payment: ${verifyRes.data?.invalidReason ?? 'isValid !== true'}`,
                );
            }
            return {
                paymentId,
                payer: verifyRes.data.payer ?? null,
                network: CONCORDIUM_TESTNET_CAIP2,
            };
        },
        async settle({ header, requirements, expectedMemoHex }) {
            const { decoded, paymentRequirements, paymentId } = parsePayload(header, requirements, expectedMemoHex);
            if (!isPlainObject(paymentRequirements)) {
                throw new Error('paymentRequirements object is required for facilitator settlement');
            }
            const reqBody = {
                x402Version: X402_VERSION,
                paymentPayload: decoded,
                paymentRequirements,
            };
            const settleRes = await safeJsonFetch(`${baseUrl}/settle`, {
                method: 'POST',
                body: reqBody,
                allowPrivate,
                allowHttp: Boolean(allowPrivate),
                timeoutMs,
                maxBytes,
                lookupFn,
                requestFn,
                ca,
                label: 'x402 facilitator /settle',
                urlLabel: 'facilitatorUrl',
            });
            if (!isPlainObject(settleRes.data) || settleRes.data.success !== true) {
                throw new Error(
                    `facilitator /settle failed: ${settleRes.data?.errorReason ?? 'success !== true'}`,
                );
            }
            const network = typeof settleRes.data.network === 'string' && settleRes.data.network.length > 0
                ? settleRes.data.network
                : CONCORDIUM_TESTNET_CAIP2;
            const settledTx = typeof settleRes.data.transaction === 'string' && settleRes.data.transaction.length > 0
                ? settleRes.data.transaction
                : null;
            return {
                paymentId,
                payer: settleRes.data.payer ?? null,
                transaction: settledTx,
                txHash: settledTx,
                network,
            };
        },
    };
}

/** Fetches and validates a witness service's `/health` descriptor against testnet genesis & `<12802,0>`. */
export async function fetchWitnessHealth({
    witnessUrl,
    allowPrivate = false,
    timeoutMs = 15000,
    lookupFn,
    requestFn,
    ca,
} = {}) {
    const base = normalizeBaseUrl(witnessUrl, 'witnessUrl');
    const res = await safeJsonFetch(`${base}/health`, {
        method: 'GET',
        allowPrivate,
        allowHttp: Boolean(allowPrivate),
        timeoutMs,
        maxBytes: 65536,
        lookupFn,
        requestFn,
        ca,
        label: 'witness /health',
        urlLabel: 'witnessUrl',
    });
    const d = res.data;
    if (!isPlainObject(d) || d.ok !== true) {
        throw new Error('witness /health did not report ok: true');
    }
    if (d.network !== 'testnet' || d.genesis !== TESTNET_GENESIS) {
        throw new Error(`witness /health is not on Concordium testnet (${d.network}, ${d.genesis})`);
    }
    if (Number(d.registry?.index) !== REGISTRY.index || Number(d.registry?.subindex) !== REGISTRY.subindex) {
        throw new Error(`witness /health registry mismatch: ${JSON.stringify(d.registry)}`);
    }
    const witnessAccount = assertCanonicalAccount(d.witnessAccount, 'witnessAccount');
    const payTo = d.payTo !== undefined && d.payTo !== null ? assertCanonicalAccount(d.payTo, 'payTo') : witnessAccount;
    let priceMicroCcd;
    if (d.priceMicroCcd !== undefined && d.priceMicroCcd !== null) {
        const ps = String(d.priceMicroCcd);
        if (!/^(?:0|[1-9][0-9]*)$/.test(ps)) {
            throw new Error(`witness /health invalid priceMicroCcd: ${d.priceMicroCcd}`);
        }
        priceMicroCcd = ps;
    }
    return {
        ...d,
        witnessAccount,
        payTo,
        ...(priceMicroCcd !== undefined ? { priceMicroCcd } : {}),
    };
}

function validateAndParsePaymentRequired(
    rawHeader,
    { tokenId, toSeq, commitment, prevAnchorTx, expectedMemoHex, expectedPayTo, maxPriceMicroCcd, expectedWitnessAccount },
) {
    if (typeof rawHeader !== 'string' || rawHeader.length === 0) {
        throw new Error('402 response missing PAYMENT-REQUIRED header');
    }
    const pr = decodeX402Header(rawHeader, 'PAYMENT-REQUIRED');
    if (pr.x402Version !== X402_VERSION) {
        throw new Error(`witness returned unsupported x402Version ${pr.x402Version}; expected ${X402_VERSION}`);
    }
    if (!Array.isArray(pr.accepts) || pr.accepts.length === 0) {
        throw new Error('witness PAYMENT-REQUIRED missing accepts array');
    }
    const matched = pr.accepts.find(
        (a) => isPlainObject(a) && a.scheme === 'exact' && a.network === CONCORDIUM_TESTNET_CAIP2,
    );
    if (!matched) {
        throw new Error(`witness PAYMENT-REQUIRED offered no exact/${CONCORDIUM_TESTNET_CAIP2} payment option`);
    }
    assertCanonicalAccount(matched.payTo, 'payment requirement payTo');
    if (expectedPayTo && !isSameAccount(matched.payTo, expectedPayTo)) {
        throw new Error(`witness PAYMENT-REQUIRED payTo ${matched.payTo} does not match expected ${expectedPayTo}`);
    }
    if (typeof matched.amount !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(matched.amount)) {
        throw new Error(`witness PAYMENT-REQUIRED invalid amount: ${matched.amount}`);
    }
    if (maxPriceMicroCcd !== null && maxPriceMicroCcd !== undefined && BigInt(matched.amount) > BigInt(maxPriceMicroCcd)) {
        throw new Error(`witness PAYMENT-REQUIRED amount ${matched.amount} exceeds maxPriceMicroCcd ${maxPriceMicroCcd}`);
    }
    if (!isPlainObject(matched.extra) || matched.extra.memoHex !== expectedMemoHex) {
        throw new Error('witness PAYMENT-REQUIRED memoHex does not match locally computed anchor commitment memo');
    }
    if (expectedWitnessAccount) {
        if (
            typeof matched.extra.witnessAccount !== 'string' ||
            !isSameAccount(matched.extra.witnessAccount, expectedWitnessAccount)
        ) {
            throw new Error(
                `witness PAYMENT-REQUIRED extra.witnessAccount (${matched.extra.witnessAccount ?? 'missing'}) does not match expected ${expectedWitnessAccount}`,
            );
        }
    }
    if (matched.extra.tokenId !== undefined && String(matched.extra.tokenId) !== String(tokenId)) {
        throw new Error('witness PAYMENT-REQUIRED extra.tokenId mismatch');
    }
    if (matched.extra.toSeq !== undefined && matched.extra.toSeq !== toSeq) {
        throw new Error('witness PAYMENT-REQUIRED extra.toSeq mismatch');
    }
    if (matched.extra.commitment !== undefined && matched.extra.commitment !== commitment) {
        throw new Error('witness PAYMENT-REQUIRED extra.commitment mismatch');
    }
    if (matched.extra.prevAnchorTx !== undefined && (matched.extra.prevAnchorTx ?? null) !== (prevAnchorTx ?? null)) {
        throw new Error('witness PAYMENT-REQUIRED extra.prevAnchorTx mismatch');
    }
    return { paymentRequired: pr, accepted: matched };
}

/**
 * Requests a countersigned anchor from a witness service over x402 v2, verifying the 402 memo binding
 * locally before executing `payFn` and validating the returned `PAYMENT-RESPONSE` and anchor record.
 */
export async function requestWitnessAnchor({
    witnessUrl,
    tokenId,
    toSeq,
    commitment,
    prevAnchorTx = null,
    paymentSignature,
    payFn,
    expectedPayTo = null,
    maxPriceMicroCcd = null,
    expectedWitnessAccount = null,
    allowPrivate = false,
    timeoutMs = 210000,
    lookupFn,
    requestFn,
    ca,
} = {}) {
    const base = normalizeBaseUrl(witnessUrl, 'witnessUrl');
    const tid = assertTokenIdStr(tokenId);
    const expectedMemoHex = computePaymentMemo({ tokenId: tid, toSeq, commitment, prevAnchorTx });
    const body = { tokenId: tid, toSeq, commitment, prevAnchorTx: prevAnchorTx ?? null };

    const postAnchor = (sigHeader) =>
        safeJsonFetch(`${base}/v1/anchor`, {
            method: 'POST',
            headers: sigHeader ? { [HEADER_PAYMENT_SIGNATURE]: sigHeader } : {},
            body,
            allowPrivate,
            allowHttp: Boolean(allowPrivate),
            timeoutMs,
            maxBytes: 65536,
            acceptStatus: (s) => (s >= 200 && s < 300) || s === 402 || (s >= 400 && s < 600),
            lookupFn,
            requestFn,
            ca,
            label: 'witness /v1/anchor',
            urlLabel: 'witnessUrl',
        });

    let res;
    if (paymentSignature !== undefined && paymentSignature !== null) {
        const sigStr = typeof paymentSignature === 'string' ? paymentSignature : encodeX402Header(paymentSignature);
        res = await postAnchor(sigStr);
    } else {
        res = await postAnchor(null);
        if (res.statusCode === 402) {
            const rawPr = res.headers[HEADER_PAYMENT_REQUIRED];
            const { paymentRequired, accepted } = validateAndParsePaymentRequired(rawPr, {
                tokenId: tid,
                toSeq,
                commitment,
                prevAnchorTx,
                expectedMemoHex,
                expectedPayTo,
                maxPriceMicroCcd,
                expectedWitnessAccount,
            });
            if (typeof payFn !== 'function') {
                throw new Error('witness returned 402 Payment Required and no payFn/paymentSignature was provided');
            }
            const payment = await payFn(accepted, paymentRequired);
            const sigStr = typeof payment === 'string' ? payment : encodeX402Header(payment);
            res = await postAnchor(sigStr);
        }
    }

    if (res.statusCode < 200 || res.statusCode >= 300) {
        const detail = res.data?.error ?? (res.text || `HTTP ${res.statusCode}`);
        throw new Error(`witness /v1/anchor failed (HTTP ${res.statusCode}): ${detail}`);
    }
    const d = res.data;
    if (!isPlainObject(d) || !TX_RE.test(d.txHash ?? '')) {
        throw new Error('witness /v1/anchor response missing valid txHash');
    }
    assertCanonicalAccount(d.witnessAccount, 'witnessAccount');
    if (expectedWitnessAccount && !isSameAccount(d.witnessAccount, expectedWitnessAccount)) {
        throw new Error(`witness /v1/anchor response witnessAccount ${d.witnessAccount} does not match ${expectedWitnessAccount}`);
    }
    if (d.tokenId !== undefined && String(d.tokenId) !== tid) {
        throw new Error('witness /v1/anchor response tokenId mismatch');
    }
    if (d.toSeq !== undefined && d.toSeq !== toSeq) {
        throw new Error('witness /v1/anchor response toSeq mismatch');
    }
    if (d.commitment !== undefined && d.commitment !== commitment) {
        throw new Error('witness /v1/anchor response commitment mismatch');
    }
    if (d.prevAnchorTx !== undefined && (d.prevAnchorTx ?? null) !== (prevAnchorTx ?? null)) {
        throw new Error('witness /v1/anchor response prevAnchorTx mismatch');
    }
    const rawRespHdr = res.headers[HEADER_PAYMENT_RESPONSE];
    if (typeof rawRespHdr !== 'string' || rawRespHdr.length === 0) {
        throw new Error('witness /v1/anchor 200 response missing PAYMENT-RESPONSE header');
    }
    const paymentResponse = decodeX402Header(rawRespHdr, 'PAYMENT-RESPONSE');
    if (paymentResponse.success !== true) {
        throw new Error('witness PAYMENT-RESPONSE did not indicate success: true');
    }
    if (paymentResponse.network !== undefined && paymentResponse.network !== CONCORDIUM_TESTNET_CAIP2) {
        throw new Error(`witness PAYMENT-RESPONSE network mismatch: ${paymentResponse.network}`);
    }
    return { ...d, paymentResponse };
}

/** Submits an owner-signed Protocol 10 `CIS-8004.setMetadata` transaction to `/v1/sponsor-pointer`. */
export async function requestSponsoredPointer({
    witnessUrl,
    tokenId,
    anchorTxHash,
    transactionJson,
    allowPrivate = false,
    timeoutMs = 60000,
    lookupFn,
    requestFn,
    ca,
} = {}) {
    const base = normalizeBaseUrl(witnessUrl, 'witnessUrl');
    const tid = assertTokenIdStr(tokenId);
    if (typeof anchorTxHash !== 'string' || !TX_RE.test(anchorTxHash)) {
        throw new Error(`invalid anchorTxHash: ${anchorTxHash}`);
    }
    if (typeof transactionJson !== 'string' || transactionJson.trim().length === 0) {
        throw new Error('transactionJson must be a non-empty string');
    }
    const res = await safeJsonFetch(`${base}/v1/sponsor-pointer`, {
        method: 'POST',
        body: { tokenId: tid, anchorTxHash, transactionJson },
        allowPrivate,
        allowHttp: Boolean(allowPrivate),
        timeoutMs,
        maxBytes: 65536,
        acceptStatus: (s) => (s >= 200 && s < 300) || (s >= 400 && s < 600),
        lookupFn,
        requestFn,
        ca,
        label: 'witness /v1/sponsor-pointer',
        urlLabel: 'witnessUrl',
    });
    if (res.statusCode < 200 || res.statusCode >= 300) {
        const detail = res.data?.error ?? (res.text || `HTTP ${res.statusCode}`);
        throw new Error(`witness /v1/sponsor-pointer failed (HTTP ${res.statusCode}): ${detail}`);
    }
    const d = res.data;
    if (!isPlainObject(d) || !TX_RE.test(d.metadataTxHash ?? '')) {
        throw new Error('witness /v1/sponsor-pointer response missing valid metadataTxHash');
    }
    if (d.anchorTxHash !== anchorTxHash) {
        throw new Error('witness /v1/sponsor-pointer response anchorTxHash mismatch');
    }
    assertCanonicalAccount(d.witnessAccount, 'witnessAccount');
    return d;
}
