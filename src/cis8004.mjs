// Pure CIS-8004 / CIS-2 binary codecs, Concordium badge codec, and Agent Card validator.
import crypto from 'node:crypto';
import { AccountAddress, ContractAddress, tokenAddressFromBase58, tokenAddressToBase58 } from '@concordium/web-sdk';
import { REGISTRY, TESTNET_GENESIS } from './registry.mjs';

const BADGE_EXTENSION_URI = 'https://docs.concordium.com/a2a-extensions/concordium-badge/v1';
const utf8Fatal = new TextDecoder('utf-8', { fatal: true });
const U64_MAX = (1n << 64n) - 1n;
const MAX_SAFE_BIGINT = BigInt(Number.MAX_SAFE_INTEGER);
const HEX_EVEN_LOWER_RE = /^(?:[0-9a-f]{2})*$/;

function toBuffer(bytes, label = 'bytes') {
    if (Buffer.isBuffer(bytes)) return bytes;
    if (bytes instanceof Uint8Array) return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    throw new TypeError(`${label} must be a Buffer or Uint8Array`);
}

function parseTokenId(tokenId) {
    let n;
    if (typeof tokenId === 'bigint') {
        n = tokenId;
    } else if (typeof tokenId === 'number') {
        if (!Number.isSafeInteger(tokenId) || tokenId < 0) throw new Error(`invalid tokenId: ${tokenId}`);
        n = BigInt(tokenId);
    } else if (typeof tokenId === 'string') {
        if (!/^(?:0|[1-9][0-9]*)$/.test(tokenId)) throw new Error(`invalid tokenId string: ${tokenId}`);
        n = BigInt(tokenId);
    } else {
        throw new Error(`invalid tokenId type: ${typeof tokenId}`);
    }
    if (n < 0n || n > U64_MAX) throw new Error(`tokenId out of u64 range: ${tokenId}`);
    return n;
}

function u32le(n) {
    if (!Number.isSafeInteger(n) || n < 0 || n > 0xffffffff) throw new Error(`u32 length out of range: ${n}`);
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n, 0);
    return b;
}

function assertEvenLowerHex(hex, label = 'hex') {
    if (typeof hex !== 'string' || !HEX_EVEN_LOWER_RE.test(hex)) {
        throw new Error(`${label} must be even-length lowercase hex`);
    }
}

class BinaryReader {
    constructor(bytes, label = 'payload') {
        this.buf = toBuffer(bytes, label);
        this.offset = 0;
        this.label = label;
    }

    remaining() {
        return this.buf.length - this.offset;
    }

    assertRemaining(n) {
        if (n < 0 || this.remaining() < n) {
            throw new Error(`truncated ${this.label} at offset ${this.offset}: need ${n} bytes, have ${this.remaining()}`);
        }
    }

    readU8() {
        this.assertRemaining(1);
        return this.buf[this.offset++];
    }

    readU32LE() {
        this.assertRemaining(4);
        const v = this.buf.readUInt32LE(this.offset);
        this.offset += 4;
        return v;
    }

    readU64LE() {
        this.assertRemaining(8);
        const v = this.buf.readBigUInt64LE(this.offset);
        this.offset += 8;
        return v;
    }

    readBytes(n) {
        this.assertRemaining(n);
        const s = this.buf.subarray(this.offset, this.offset + n);
        this.offset += n;
        return s;
    }

    readByteListU32() {
        const len = this.readU32LE();
        return Buffer.from(this.readBytes(len));
    }

    readStringU32() {
        const len = this.readU32LE();
        const bytes = this.readBytes(len);
        return utf8Fatal.decode(bytes);
    }

    readAccountAddress() {
        return AccountAddress.fromBuffer(this.readBytes(32)).address;
    }

    readContractAddress() {
        const index = this.readU64LE();
        const subindex = this.readU64LE();
        if (index > MAX_SAFE_BIGINT || subindex > MAX_SAFE_BIGINT) {
            throw new Error(`${this.label}: contract address exceeds safe integer range`);
        }
        return { index: Number(index), subindex: Number(subindex) };
    }

    readAddress() {
        const kind = this.readU8();
        if (kind === 0) return this.readAccountAddress();
        if (kind === 1) return this.readContractAddress();
        throw new Error(`${this.label}: invalid Address tag ${kind}`);
    }

    readTimestampMs() {
        const ms = this.readU64LE();
        if (ms > MAX_SAFE_BIGINT) throw new Error(`${this.label}: timestamp exceeds safe integer range`);
        return Number(ms);
    }

    readOption(readInner) {
        const tag = this.readU8();
        if (tag === 0) return null;
        if (tag === 1) return readInner();
        throw new Error(`${this.label}: invalid Option tag ${tag}`);
    }

    readULeb128(maxBytes = 37) {
        let value = 0n;
        let shift = 0n;
        for (let i = 0; i < maxBytes; i++) {
            const byte = this.readU8();
            value |= BigInt(byte & 0x7f) << shift;
            if ((byte & 0x80) === 0) return value;
            shift += 7n;
        }
        throw new Error(`${this.label}: ULEB128 exceeded ${maxBytes} bytes`);
    }

    assertEnd() {
        if (this.offset !== this.buf.length) {
            throw new Error(`${this.label}: unexpected trailing bytes (${this.remaining()} unread)`);
        }
    }
}

/** Encodes a u64 token ID in CIS-2 length-prefixed form: 0x08 followed by 8-byte LE u64. */
export function encodeTokenId(tokenId) {
    const n = parseTokenId(tokenId);
    const b = Buffer.alloc(9);
    b[0] = 8;
    b.writeBigUInt64LE(n, 1);
    return b;
}

/** Encodes CIS-8004.getMetadata parameter: token_id (ByteList U8) | key (String U32). */
export function encodeGetMetadataParam(tokenId, key) {
    if (typeof key !== 'string') throw new TypeError('metadata key must be a string');
    const k = Buffer.from(key, 'utf8');
    return Buffer.concat([encodeTokenId(tokenId), u32le(k.length), k]);
}

/** Encodes CIS-8004.setMetadata parameter: token_id | key (String U32) | value (List U32 U8). */
export function encodeSetMetadataParam(tokenId, key, valueUtf8) {
    if (typeof key !== 'string') throw new TypeError('metadata key must be a string');
    if (typeof valueUtf8 !== 'string') throw new TypeError('metadata value must be a string');
    const k = Buffer.from(key, 'utf8');
    const v = Buffer.from(valueUtf8, 'utf8');
    return Buffer.concat([encodeTokenId(tokenId), u32le(k.length), k, u32le(v.length), v]);
}

/** Encodes a token id + contract into a Base58Check CIS-2 token address (badge). */
export function encodeBadge(tokenId, registry = REGISTRY) {
    const n = parseTokenId(tokenId);
    const idBuf = Buffer.alloc(8);
    idBuf.writeBigUInt64LE(n, 0);
    return tokenAddressToBase58({
        contract: ContractAddress.create(BigInt(registry.index), BigInt(registry.subindex)),
        id: idBuf.toString('hex'),
    });
}

/** Decodes a Base58Check CIS-2 badge and enforces an 8-byte LE u64 token id and canonical encoding. */
export function decodeBadge(badge) {
    if (typeof badge !== 'string' || badge.length === 0) throw new Error('badge must be a non-empty string');
    const parsed = tokenAddressFromBase58(badge);
    if (!/^[0-9a-f]{16}$/.test(parsed.id)) {
        throw new Error(`unexpected CIS-8004 token id encoding in badge (${parsed.id})`);
    }
    if (tokenAddressToBase58(parsed) !== badge) {
        throw new Error('badge is not in canonical CIS-2 Base58Check form');
    }
    if (parsed.contract.index > MAX_SAFE_BIGINT || parsed.contract.subindex > MAX_SAFE_BIGINT) {
        throw new Error('badge contract address exceeds safe integer range');
    }
    const tokenId = Buffer.from(parsed.id, 'hex').readBigUInt64LE(0).toString();
    return {
        contract: { index: Number(parsed.contract.index), subindex: Number(parsed.contract.subindex) },
        tokenId,
    };
}

/** Strictly decodes the return value of CIS-8004.agentOf according to the <12802,0> schema. */
export function decodeAgentOf(bytes) {
    const r = new BinaryReader(bytes, 'agentOf');
    const agent = r.readOption(() => {
        const tidLen = r.readU8();
        if (tidLen !== 8) throw new Error(`agentOf: expected 8-byte token_id, got ${tidLen}`);
        const tokenId = r.readU64LE().toString();
        const ownerAccount = r.readAccountAddress();
        const agentUri = r.readOption(() => r.readStringU32());
        const metadataHashHex = r.readOption(() => Buffer.from(r.readBytes(32)).toString('hex'));
        const externalReference = r.readOption(() => {
            const contractAddress = r.readContractAddress();
            const kindTag = r.readU8();
            if (kindTag !== 0) throw new Error(`agentOf: unsupported external_reference kind ${kindTag}`);
            const namespace = r.readStringU32();
            const keyType = r.readStringU32();
            const publicKeyHex = r.readByteListU32().toString('hex');
            return { contractAddress, kind: 'Cis8', namespace, keyType, publicKeyHex };
        });
        const agentWallet = r.readOption(() => r.readAccountAddress());
        const statusTag = r.readU8();
        let status;
        if (statusTag === 0) status = 'Active';
        else if (statusTag === 1) status = 'Revoked';
        else throw new Error(`agentOf: invalid status tag ${statusTag}`);
        const registeredAtMs = r.readTimestampMs();
        const revokedAtMs = r.readOption(() => r.readTimestampMs());
        const revocationReason = r.readOption(() => r.readStringU32());
        const metaCount = r.readU32LE();
        const onChainMetadata = [];
        for (let i = 0; i < metaCount; i++) {
            // Bound remaining length check implicitly via BinaryReader inside each entry.
            const key = r.readStringU32();
            const value = r.readByteListU32();
            onChainMetadata.push({ key, value });
        }
        return {
            tokenId,
            ownerAccount,
            agentUri,
            metadataHashHex,
            externalReference,
            agentWallet,
            status,
            registeredAtMs,
            revokedAtMs,
            revocationReason,
            onChainMetadata,
        };
    });
    r.assertEnd();
    return agent;
}

/** Strictly decodes CIS-8004.getMetadata raw Option<Vec<u8>> bytes. */
export function decodeGetMetadata(bytes) {
    const r = new BinaryReader(bytes, 'getMetadata');
    const val = r.readOption(() => r.readByteListU32());
    r.assertEnd();
    return val;
}

/** Strictly decodes CIS-8004.getMetadata as fatal UTF-8 text (or null when absent). */
export function decodeGetMetadataUtf8(bytes) {
    const raw = decodeGetMetadata(bytes);
    return raw === null ? null : utf8Fatal.decode(raw);
}

/**
 * Parses a CIS-8004 MetadataSet (0xf3) event if it targets expectedTokenId.
 * Returns null for non-0xf3 events or 0xf3 events targeting another tokenId; throws if targeting expectedTokenId and malformed.
 */
export function parseMetadataSetEvent(hex, expectedTokenId) {
    assertEvenLowerHex(hex, 'MetadataSet event');
    const buf = Buffer.from(hex, 'hex');
    if (buf.length === 0 || buf[0] !== 0xf3) return null;
    if (buf.length < 2) throw new Error('truncated MetadataSet event');
    const tidLen = buf[1];
    if (buf.length < 2 + tidLen) throw new Error('truncated MetadataSet token_id');
    const expectedTid = encodeTokenId(expectedTokenId);
    if (!buf.subarray(1, 2 + tidLen).equals(expectedTid)) return null;

    const r = new BinaryReader(buf.subarray(2 + tidLen), 'MetadataSet');
    const key = r.readStringU32();
    const value = r.readByteListU32();
    const timestampMs = r.readTimestampMs();
    r.assertEnd();
    return { tokenId: parseTokenId(expectedTokenId).toString(), key, value, timestampMs };
}

function readCis2TokenId(r) {
    const len = r.readU8();
    const raw = r.readBytes(len);
    const tokenIdHex = Buffer.from(raw).toString('hex');
    const tokenId = len === 8 ? raw.readBigUInt64LE(0).toString() : null;
    return { tokenId, tokenIdHex };
}

/** Decodes CIS-2 / CIS-8004 contract event hex strictly with cursor exhaustion checks. */
export function parseCis2Event(hex) {
    assertEvenLowerHex(hex, 'CIS-2 event');
    if (hex.length === 0) throw new Error('empty CIS-2 event hex');
    const r = new BinaryReader(Buffer.from(hex, 'hex'), 'CIS-2 event');
    const tag = r.readU8();
    if (tag === 0xfe) {
        const { tokenId, tokenIdHex } = readCis2TokenId(r);
        const amount = r.readULeb128();
        const owner = r.readAddress();
        r.assertEnd();
        return { type: 'Mint', tokenId, tokenIdHex, amount, owner };
    }
    if (tag === 0xff) {
        const { tokenId, tokenIdHex } = readCis2TokenId(r);
        const amount = r.readULeb128();
        const from = r.readAddress();
        const to = r.readAddress();
        r.assertEnd();
        return { type: 'Transfer', tokenId, tokenIdHex, amount, from, to };
    }
    if (tag === 0xfc) {
        const opTag = r.readU8();
        let update;
        if (opTag === 0) update = 'Remove';
        else if (opTag === 1) update = 'Add';
        else throw new Error(`UpdateOperator: invalid update tag ${opTag}`);
        const owner = r.readAddress();
        const operator = r.readAddress();
        r.assertEnd();
        return { type: 'UpdateOperator', update, owner, operator };
    }
    if (tag === 0xfd) {
        const { tokenId, tokenIdHex } = readCis2TokenId(r);
        const amount = r.readULeb128();
        const owner = r.readAddress();
        r.assertEnd();
        return { type: 'Burn', tokenId, tokenIdHex, amount, owner };
    }
    if (tag === 0xf3) {
        return { type: 'MetadataSet', rawHex: hex };
    }
    return { type: 'Other', tag, rawHex: hex };
}

/**
 * Verifies Agent Card bytes against the on-chain SHA-256 hash and concordium-badge/v1 extension binding.
 */
export function verifyAgentCardBytes(
    bytes,
    { badge, ownerAccount, metadataHashHex, registry = REGISTRY, genesisPrefix = TESTNET_GENESIS.slice(0, 32) } = {},
) {
    const buf = toBuffer(bytes, 'agent card');
    if (typeof metadataHashHex !== 'string' || !/^[0-9a-f]{64}$/.test(metadataHashHex)) {
        throw new Error('on-chain metadataHashHex must be 64 lowercase hex characters');
    }
    if (typeof badge !== 'string' || badge.length === 0) throw new Error('badge is required for Agent Card verification');
    if (typeof ownerAccount !== 'string' || ownerAccount.length === 0) throw new Error('ownerAccount is required for Agent Card verification');
    if (typeof genesisPrefix !== 'string' || !/^[0-9a-f]{32}$/.test(genesisPrefix)) {
        throw new Error('genesisPrefix must be 32 lowercase hex characters');
    }

    const actualHash = crypto.createHash('sha256').update(buf).digest('hex');
    if (actualHash !== metadataHashHex) {
        throw new Error(`agent card SHA-256 mismatch: expected ${metadataHashHex}, got ${actualHash}`);
    }

    let card;
    try {
        card = JSON.parse(utf8Fatal.decode(buf));
    } catch (e) {
        throw new Error(`agent card is not valid UTF-8 JSON: ${e.message}`);
    }
    if (!card || typeof card !== 'object' || Array.isArray(card)) {
        throw new Error('agent card JSON must be an object');
    }

    const extensions = card.capabilities?.extensions;
    if (!Array.isArray(extensions)) {
        throw new Error('agent card missing capabilities.extensions array');
    }
    const matches = extensions.filter((ext) => ext && typeof ext === 'object' && ext.uri === BADGE_EXTENSION_URI);
    if (matches.length !== 1) {
        throw new Error(`agent card must contain exactly one ${BADGE_EXTENSION_URI} extension (found ${matches.length})`);
    }
    const params = matches[0].params;
    if (!params || typeof params !== 'object') {
        throw new Error('concordium-badge/v1 extension missing params');
    }

    const expectedTokenAddress = `ccd:${genesisPrefix}/cis-2:${badge}`;
    if (params.tokenAddress !== expectedTokenAddress) {
        throw new Error(`agent card tokenAddress mismatch: expected ${expectedTokenAddress}, got ${params.tokenAddress}`);
    }

    const expectedOwner = `ccd:${genesisPrefix}:${ownerAccount}`;
    if (params.owner?.account !== expectedOwner) {
        throw new Error(`agent card owner.account mismatch: expected ${expectedOwner}, got ${params.owner?.account}`);
    }

    const expectedContract = `ccd:${genesisPrefix}:${registry.index}.${registry.subindex}`;
    if (params.contracts?.cis8004 !== expectedContract) {
        throw new Error(`agent card contracts.cis8004 mismatch: expected ${expectedContract}, got ${params.contracts?.cis8004}`);
    }

    return { sha256: actualHash, card, extension: matches[0] };
}

/**
 * Fetches an Agent Card over HTTPS without redirects, enforcing a timeout and streaming byte cap.
 */
export async function fetchAgentCard(uri, { timeoutMs = 15000, maxBytes = 1048576 } = {}) {
    let url;
    try {
        url = new URL(uri);
    } catch {
        throw new Error(`invalid agentUri: ${uri}`);
    }
    if (url.protocol !== 'https:') {
        throw new Error(`refusing non-HTTPS agentUri protocol ${url.protocol}`);
    }
    if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
        throw new Error(`invalid maxBytes: ${maxBytes}`);
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error(`fetching agent card timed out after ${timeoutMs}ms`)), timeoutMs);
    try {
        const res = await fetch(url, { redirect: 'error', signal: controller.signal });
        if (!res.ok) {
            await res.body?.cancel?.().catch(() => {});
            throw new Error(`HTTP ${res.status} fetching agent card from ${url.origin}${url.pathname}`);
        }
        const cl = res.headers.get('content-length');
        if (cl !== null && /^\d+$/.test(cl) && Number(cl) > maxBytes) {
            await res.body?.cancel?.().catch(() => {});
            throw new Error(`agent card Content-Length (${cl}) exceeds ${maxBytes} byte limit`);
        }
        if (!res.body) return Buffer.alloc(0);

        const reader = res.body.getReader();
        const chunks = [];
        let total = 0;
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (value) {
                total += value.byteLength;
                if (total > maxBytes) {
                    await reader.cancel().catch(() => {});
                    throw new Error(`agent card exceeds ${maxBytes} byte limit`);
                }
                chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
            }
        }
        return Buffer.concat(chunks, total);
    } finally {
        clearTimeout(timer);
    }
}
