// Pure CIS-8004 / CIS-2 binary codecs, Concordium badge codec, and SSRF-hardened Agent Card validator.
import crypto from 'node:crypto';
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import zlib from 'node:zlib';
import { AccountAddress, ContractAddress, tokenAddressFromBase58, tokenAddressToBase58 } from '@concordium/web-sdk';
import { REGISTRY, TESTNET_GENESIS } from './registry.mjs';

const BADGE_EXTENSION_URI = 'https://docs.concordium.com/a2a-extensions/concordium-badge/v1';
const utf8Fatal = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
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

    readU16LE() {
        this.assertRemaining(2);
        const v = this.buf.readUInt16LE(this.offset);
        this.offset += 2;
        return v;
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

    readStringU16() {
        const len = this.readU16LE();
        return utf8Fatal.decode(this.readBytes(len));
    }

    readStringU32() {
        const len = this.readU32LE();
        return utf8Fatal.decode(this.readBytes(len));
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

    readExternalReference() {
        const contractAddress = this.readContractAddress();
        const kindTag = this.readU8();
        if (kindTag !== 0) throw new Error(`${this.label}: unsupported external_reference kind ${kindTag}`);
        const namespace = this.readStringU32();
        const keyType = this.readStringU32();
        const publicKeyHex = this.readByteListU32().toString('hex');
        return { contractAddress, kind: 'Cis8', namespace, keyType, publicKeyHex };
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
        const externalReference = r.readOption(() => r.readExternalReference());
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

/** Strictly decodes CIS-8004.getMetadata as fatal, BOM-preserving UTF-8 text (or null when absent). */
export function decodeGetMetadataUtf8(bytes) {
    const raw = decodeGetMetadata(bytes);
    return raw === null ? null : utf8Fatal.decode(raw);
}

/** Strictly decodes CIS-8004.getAdmin return value: Option<AccountAddress>. */
export function decodeGetAdmin(bytes) {
    const r = new BinaryReader(bytes, 'getAdmin');
    const admin = r.readOption(() => r.readAccountAddress());
    r.assertEnd();
    return admin;
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

/** Decodes every CIS-8004 / CIS-2 contract event tag strictly with cursor exhaustion checks. */
export function parseCis2Event(hex) {
    assertEvenLowerHex(hex, 'CIS-2 event');
    if (hex.length === 0) throw new Error('empty CIS-2 event hex');
    const r = new BinaryReader(Buffer.from(hex, 'hex'), 'CIS-2 event');
    const tag = r.readU8();
    switch (tag) {
        case 0xf0: {
            const { tokenId, tokenIdHex } = readCis2TokenId(r);
            const ownerAccount = r.readAccountAddress();
            const agentUri = r.readOption(() => r.readStringU32());
            const metadataHashHex = r.readOption(() => Buffer.from(r.readBytes(32)).toString('hex'));
            const externalReference = r.readOption(() => r.readExternalReference());
            const registeredAtMs = r.readTimestampMs();
            r.assertEnd();
            return { type: 'Registered', tokenId, tokenIdHex, ownerAccount, agentUri, metadataHashHex, externalReference, registeredAtMs };
        }
        case 0xf1: {
            const { tokenId, tokenIdHex } = readCis2TokenId(r);
            const agentUri = r.readOption(() => r.readStringU32());
            const metadataHashHex = r.readOption(() => Buffer.from(r.readBytes(32)).toString('hex'));
            const updatedAtMs = r.readTimestampMs();
            r.assertEnd();
            return { type: 'URIUpdated', tokenId, tokenIdHex, agentUri, metadataHashHex, updatedAtMs };
        }
        case 0xf2: {
            const { tokenId, tokenIdHex } = readCis2TokenId(r);
            const externalReference = r.readOption(() => r.readExternalReference());
            const updatedAtMs = r.readTimestampMs();
            r.assertEnd();
            return { type: 'ExternalReferenceSet', tokenId, tokenIdHex, externalReference, updatedAtMs };
        }
        case 0xf3: {
            return { type: 'MetadataSet', rawHex: hex };
        }
        case 0xf4: {
            const { tokenId, tokenIdHex } = readCis2TokenId(r);
            const ownerAccount = r.readAccountAddress();
            const reason = r.readOption(() => r.readStringU32());
            const revokedAtMs = r.readTimestampMs();
            r.assertEnd();
            return { type: 'Revoked', tokenId, tokenIdHex, ownerAccount, reason, revokedAtMs };
        }
        case 0xf5: {
            const { tokenId, tokenIdHex } = readCis2TokenId(r);
            const newWallet = r.readOption(() => r.readAccountAddress());
            const updatedAtMs = r.readTimestampMs();
            r.assertEnd();
            return { type: 'AgentWalletSet', tokenId, tokenIdHex, newWallet, updatedAtMs };
        }
        case 0xf7: {
            const previous = r.readOption(() => r.readAccountAddress());
            const next = r.readOption(() => r.readAccountAddress());
            const updatedAtMs = r.readTimestampMs();
            r.assertEnd();
            return { type: 'AdminTransferred', previous, next, updatedAtMs };
        }
        case 0xf8: {
            const previousCis8Contract = r.readContractAddress();
            const newCis8Contract = r.readContractAddress();
            r.assertEnd();
            return { type: 'ExternalRegistriesUpdated', previousCis8Contract, newCis8Contract };
        }
        case 0xfb: {
            const { tokenId, tokenIdHex } = readCis2TokenId(r);
            const url = r.readStringU16();
            const hashHex = r.readOption(() => Buffer.from(r.readBytes(32)).toString('hex'));
            r.assertEnd();
            return { type: 'TokenMetadata', tokenId, tokenIdHex, url, hashHex };
        }
        case 0xfc: {
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
        case 0xfd: {
            const { tokenId, tokenIdHex } = readCis2TokenId(r);
            const amount = r.readULeb128();
            const owner = r.readAddress();
            r.assertEnd();
            return { type: 'Burn', tokenId, tokenIdHex, amount, owner };
        }
        case 0xfe: {
            const { tokenId, tokenIdHex } = readCis2TokenId(r);
            const amount = r.readULeb128();
            const owner = r.readAddress();
            r.assertEnd();
            return { type: 'Mint', tokenId, tokenIdHex, amount, owner };
        }
        case 0xff: {
            const { tokenId, tokenIdHex } = readCis2TokenId(r);
            const amount = r.readULeb128();
            const from = r.readAddress();
            const to = r.readAddress();
            r.assertEnd();
            return { type: 'Transfer', tokenId, tokenIdHex, amount, from, to };
        }
        default:
            return { type: 'Unknown', tag, rawHex: hex };
    }
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

function isDisallowedIpv4Octets(a, b, c) {
    if (a === 0) return true; // 0.0.0.0/8 unspecified
    if (a === 10) return true; // 10.0.0.0/8 RFC1918
    if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
    if (a === 127) return true; // 127.0.0.0/8 loopback
    if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local / IMDS
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 RFC1918
    if (a === 192 && b === 0 && (c === 0 || c === 2)) return true; // 192.0.0.0/24 & TEST-NET-1
    if (a === 192 && b === 168) return true; // 192.168.0.0/16 RFC1918
    if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 benchmarking
    if (a === 198 && b === 51 && c === 100) return true; // TEST-NET-2
    if (a === 203 && b === 0 && c === 113) return true; // TEST-NET-3
    if (a >= 224) return true; // 224.0.0.0/4 multicast + 240.0.0.0/4 reserved
    return false;
}

function parseIpv6Groups(raw) {
    let ip = raw.toLowerCase();
    // Handle embedded trailing IPv4 dotted quad (e.g. ::ffff:127.0.0.1).
    const lastColon = ip.lastIndexOf(':');
    let tailV4 = null;
    if (lastColon !== -1 && ip.slice(lastColon + 1).includes('.')) {
        const v4 = ip.slice(lastColon + 1);
        if (!net.isIPv4(v4)) return null;
        const oct = v4.split('.').map(Number);
        tailV4 = [(oct[0] << 8) | oct[1], (oct[2] << 8) | oct[3]];
        ip = ip.slice(0, lastColon);
        if (ip.endsWith(':')) ip += ':';
        // Wait: for `::ffff:127.0.0.1`, slice gives `::ffff`, while for `::127.0.0.1`, slice gives `:`.
        if (ip === ':') ip = '::';
    }
    const halves = ip.split('::');
    if (halves.length > 2) return null;
    const parseSide = (s) => (s === '' ? [] : s.split(':').map((g) => parseInt(g, 16)));
    const left = parseSide(halves[0]);
    const right = halves.length === 2 ? parseSide(halves[1]) : [];
    const targetLen = tailV4 ? 6 : 8;
    const missing = targetLen - (left.length + right.length);
    if (halves.length === 1 && missing !== 0) return null;
    if (halves.length === 2 && missing < 0) return null;
    const groups = [...left, ...new Array(Math.max(0, missing)).fill(0), ...right, ...(tailV4 ?? [])];
    return groups.length === 8 && groups.every((n) => Number.isInteger(n) && n >= 0 && n <= 0xffff) ? groups : null;
}

export function isDisallowedIp(rawIp) {
    if (typeof rawIp !== 'string' || rawIp.length === 0) return true;
    if (rawIp.includes('%')) return true; // scoped zone ID (e.g. link-local)
    const ip = rawIp.trim();
    if (net.isIPv4(ip)) {
        const [a, b, c] = ip.split('.').map(Number);
        return isDisallowedIpv4Octets(a, b, c);
    }
    if (!net.isIPv6(ip)) return true;
    const g = parseIpv6Groups(ip);
    if (!g) return true;
    // Unspecified :: or loopback ::1
    if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0 && g[6] === 0 && g[7] <= 1) {
        return true;
    }
    // IPv4-mapped (::ffff:0:0/96), IPv4-compatible (::/96), IPv4-translated (::ffff:0:0:0/96), NAT64 (64:ff9b::/96)
    const isV4Mapped = g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && (g[5] === 0xffff || g[5] === 0);
    const isV4Translated = g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0xffff && g[5] === 0;
    const isNat64 = g[0] === 0x0064 && g[1] === 0xff9b && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0;
    if (isV4Mapped || isV4Translated || isNat64) {
        return isDisallowedIpv4Octets(g[6] >>> 8, g[6] & 0xff, g[7] >>> 8);
    }
    // 6to4 (2002::/16) embedding private IPv4
    if (g[0] === 0x2002 && isDisallowedIpv4Octets(g[1] >>> 8, g[1] & 0xff, g[2] >>> 8)) return true;
    // ULA fc00::/7
    if ((g[0] & 0xfe00) === 0xfc00) return true;
    // Link-local fe80::/10 & deprecated site-local fec0::/10
    if ((g[0] & 0xffc0) === 0xfe80 || (g[0] & 0xffc0) === 0xfec0) return true;
    // Multicast ff00::/8
    if ((g[0] & 0xff00) === 0xff00) return true;
    // Documentation 2001:db8::/32
    if (g[0] === 0x2001 && g[1] === 0x0db8) return true;
    return false;
}

/**
 * Performs an SSRF-hardened HTTP(S) request without redirects, enforcing pre-connect public-IP DNS/literal guards,
 * streaming compressed and decompressed byte caps, and wall-clock timeout.
 * Plaintext http:// is refused unless both allowHttp === true and allowPrivate === true.
 */
export async function safeHttpsRequest(
    uri,
    {
        method = 'GET',
        headers = {},
        body,
        timeoutMs = 15000,
        maxBytes = 1048576,
        allowPrivate = false,
        allowHttp = false,
        acceptStatus = (status) => status >= 200 && status < 300,
        lookupFn = dns.lookup,
        requestFn,
        ca,
        label = 'response',
        urlLabel = 'URL',
    } = {},
) {
    let url;
    try {
        url = new URL(uri);
    } catch {
        throw new Error(`invalid ${urlLabel}: ${uri}`);
    }
    const protocolAllowed = url.protocol === 'https:' || (allowHttp && allowPrivate && url.protocol === 'http:');
    if (!protocolAllowed) {
        throw new Error(`refusing non-HTTPS ${urlLabel} protocol ${url.protocol}`);
    }
    if (url.username || url.password) {
        throw new Error(`refusing ${urlLabel} containing embedded credentials`);
    }
    if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
        throw new Error(`invalid maxBytes: ${maxBytes}`);
    }
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
        throw new Error(`invalid timeoutMs: ${timeoutMs}`);
    }

    const hostname = url.hostname.startsWith('[') && url.hostname.endsWith(']') ? url.hostname.slice(1, -1) : url.hostname;
    if (!allowPrivate && net.isIP(hostname) && isDisallowedIp(hostname)) {
        throw new Error(`refusing private or non-public IP address ${hostname} in ${urlLabel}`);
    }

    const safeLookup = (host, options, cb) => {
        let opts = options;
        let callback = cb;
        if (typeof opts === 'function') {
            callback = opts;
            opts = {};
        }
        lookupFn(host, opts, (err, addrOrList, family) => {
            if (err) return callback(err);
            if (Array.isArray(addrOrList)) {
                if (addrOrList.length === 0) return callback(new Error(`DNS lookup returned no addresses for ${host}`));
                for (const entry of addrOrList) {
                    if (!allowPrivate && isDisallowedIp(entry.address)) {
                        return callback(new Error(`refusing private or non-public IP ${entry.address} for ${host}`));
                    }
                }
                return callback(null, addrOrList);
            }
            if (!allowPrivate && isDisallowedIp(addrOrList)) {
                return callback(new Error(`refusing private or non-public IP ${addrOrList} for ${host}`));
            }
            return callback(null, addrOrList, family);
        });
    };

    const transportRequestFn = requestFn ?? (url.protocol === 'http:' ? http.request : https.request);
    let bodyBuf = null;
    if (body !== undefined && body !== null) {
        if (Buffer.isBuffer(body)) bodyBuf = body;
        else if (body instanceof Uint8Array) bodyBuf = Buffer.from(body.buffer, body.byteOffset, body.byteLength);
        else if (typeof body === 'string') bodyBuf = Buffer.from(body, 'utf8');
        else throw new TypeError('request body must be a Buffer, Uint8Array, or string');
    }

    const reqHeaders = {
        accept: 'application/json',
        'accept-encoding': 'gzip, br, deflate, identity',
        ...headers,
    };
    if (bodyBuf !== null && reqHeaders['content-length'] === undefined && reqHeaders['Content-Length'] === undefined) {
        reqHeaders['content-length'] = String(bodyBuf.byteLength);
    }

    return new Promise((resolve, reject) => {
        let settled = false;
        let activeRes = null;
        let activeDecompressor = null;
        const done = (err, value) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            if (err) reject(err);
            else resolve(value);
        };

        const reqOpts = {
            method,
            agent: false,
            lookup: safeLookup,
            ...(ca !== undefined && url.protocol === 'https:' ? { ca } : {}),
            headers: reqHeaders,
        };

        const req = transportRequestFn(url, reqOpts, (res) => {
            activeRes = res;
            const fail = (err) => {
                done(err);
                activeDecompressor?.destroy();
                res.destroy();
                req.destroy();
            };
            const status = res.statusCode ?? 0;
            if (status >= 300 && status < 400) {
                fail(new Error(`refusing HTTP ${status} redirect fetching ${label}`));
                return;
            }
            if (!acceptStatus(status)) {
                fail(new Error(`HTTP ${status} fetching ${label} from ${url.origin}${url.pathname}`));
                return;
            }
            const cl = res.headers?.['content-length'];
            if (typeof cl === 'string' && /^\d+$/.test(cl) && Number(cl) > maxBytes) {
                fail(new Error(`${label} Content-Length (${cl}) exceeds ${maxBytes} byte limit`));
                return;
            }

            const encHeader = String(res.headers?.['content-encoding'] ?? '').trim().toLowerCase();
            let decompressor = null;
            if (encHeader === '' || encHeader === 'identity') {
                decompressor = null;
            } else if (encHeader === 'gzip' || encHeader === 'x-gzip') {
                decompressor = zlib.createGunzip();
            } else if (encHeader === 'deflate') {
                decompressor = zlib.createInflate();
            } else if (encHeader === 'br') {
                decompressor = zlib.createBrotliDecompress();
            } else {
                fail(new Error(`unsupported Content-Encoding: ${encHeader}`));
                return;
            }
            activeDecompressor = decompressor;

            if (!decompressor) {
                const chunks = [];
                let total = 0;
                res.on('data', (chunk) => {
                    const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
                    total += b.byteLength;
                    if (total > maxBytes) {
                        fail(new Error(`${label} exceeds ${maxBytes} byte limit`));
                        return;
                    }
                    chunks.push(b);
                });
                res.on('end', () => done(null, { statusCode: status, headers: res.headers ?? {}, body: Buffer.concat(chunks, total) }));
                res.on('error', (err) => fail(err));
                res.on('aborted', () => fail(new Error(`${label} response aborted`)));
                return;
            }

            let wireTotal = 0;
            res.on('data', (chunk) => {
                const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
                wireTotal += b.byteLength;
                if (wireTotal > maxBytes) {
                    fail(new Error(`${label} exceeds ${maxBytes} byte limit`));
                }
            });
            res.on('error', (err) => fail(err));
            res.on('aborted', () => fail(new Error(`${label} response aborted`)));

            const chunks = [];
            let decodedTotal = 0;
            decompressor.on('data', (chunk) => {
                const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
                decodedTotal += b.byteLength;
                if (decodedTotal > maxBytes) {
                    fail(new Error(`${label} exceeds ${maxBytes} byte limit`));
                    return;
                }
                chunks.push(b);
            });
            decompressor.on('end', () => done(null, { statusCode: status, headers: res.headers ?? {}, body: Buffer.concat(chunks, decodedTotal) }));
            decompressor.on('error', (err) => fail(new Error(`invalid compressed ${label}: ${err.message}`)));
            res.pipe(decompressor);
        });

        const timer = setTimeout(() => {
            const err = new Error(`fetching ${label} timed out after ${timeoutMs}ms`);
            done(err);
            activeDecompressor?.destroy();
            activeRes?.destroy();
            req.destroy(err);
        }, timeoutMs);

        req.on('error', (err) => done(err));
        if (bodyBuf !== null) req.end(bodyBuf);
        else req.end();
    });
}

/**
 * Fetches and strictly parses JSON over SSRF-hardened HTTP(S) using `safeHttpsRequest`.
 */
export async function safeJsonFetch(
    uri,
    {
        method = 'GET',
        headers = {},
        body,
        timeoutMs = 15000,
        maxBytes = 65536,
        allowPrivate = false,
        allowHttp = false,
        acceptStatus = (status) => status >= 200 && status < 300,
        lookupFn = dns.lookup,
        requestFn,
        ca,
        label = 'JSON response',
        urlLabel = 'URL',
    } = {},
) {
    let encodedBody = body;
    const reqHeaders = { ...headers };
    if (body !== undefined && body !== null && typeof body !== 'string' && !Buffer.isBuffer(body) && !(body instanceof Uint8Array)) {
        encodedBody = JSON.stringify(body);
        if (reqHeaders['content-type'] === undefined && reqHeaders['Content-Type'] === undefined) {
            reqHeaders['content-type'] = 'application/json';
        }
    }
    const res = await safeHttpsRequest(uri, {
        method,
        headers: reqHeaders,
        body: encodedBody,
        timeoutMs,
        maxBytes,
        allowPrivate,
        allowHttp,
        acceptStatus,
        lookupFn,
        requestFn,
        ca,
        label,
        urlLabel,
    });
    let data = null;
    let text = '';
    if (res.body.length > 0) {
        text = utf8Fatal.decode(res.body);
        try {
            data = JSON.parse(text);
        } catch (err) {
            if (res.statusCode >= 200 && res.statusCode < 300) {
                throw new Error(`${label} is not valid JSON: ${err.message}`);
            }
        }
    } else if (res.statusCode >= 200 && res.statusCode < 300) {
        throw new Error(`${label} returned an empty body`);
    }
    return { statusCode: res.statusCode, headers: res.headers, data, text, body: res.body };
}

/**
 * Fetches an Agent Card over HTTPS without redirects, enforcing pre-connect SSRF IP checks,
 * timeout, and a streaming byte cap.
 */
export async function fetchAgentCard(
    uri,
    { timeoutMs = 15000, maxBytes = 1048576, allowPrivate = false, lookupFn = dns.lookup, requestFn, ca } = {},
) {
    const res = await safeHttpsRequest(uri, {
        method: 'GET',
        timeoutMs,
        maxBytes,
        allowPrivate,
        allowHttp: false,
        lookupFn,
        requestFn,
        ca,
        label: 'agent card',
        urlLabel: 'agentUri',
    });
    return res.body;
}
