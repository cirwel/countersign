// Canonical trail format and commitment chain (countersign.trail.v1).
// Pure functions, no I/O beyond reading a trail file. See SPEC.md.
import crypto from 'node:crypto';
import fs from 'node:fs';

export const SCHEMA = 'countersign.trail.v1';
export const RECORD_KEYS = ['checkpoint_id', 'prev_checkpoint_id', 'provenance', 'recorded_at', 'report_excerpt', 'seq'];
const ANCHOR_MAGIC = Buffer.from('CSGN');
const ANCHOR_VERSION = 1;
export const ANCHOR_LENGTH = 4 + 1 + 8 + 8 + 32 + 32;

const sha256 = (...parts) => {
    const h = crypto.createHash('sha256');
    for (const p of parts) h.update(p);
    return h.digest();
};

/** Orders strings by Unicode code point (JavaScript's default order is by UTF-16 code unit, which differs for astral characters). */
function byCodePoint(a, b) {
    const x = Array.from(a, (c) => c.codePointAt(0));
    const y = Array.from(b, (c) => c.codePointAt(0));
    for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
    return x.length - y.length;
}

/** Deterministic JSON: object keys sorted by code point, no insignificant whitespace, UTF-8. */
export function canonical(value) {
    if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
    if (typeof value === 'number') {
        if (!Number.isSafeInteger(value)) throw new Error('only safe integers are allowed in a trail');
        return String(value);
    }
    if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
    if (typeof value === 'object') {
        const keys = Object.keys(value).sort(byCodePoint);
        return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
    }
    throw new Error(`unsupported value type ${typeof value}`);
}

const HEADER_KEYS = ['agent_uuid', 'registry', 'schema', 'source', 'token_id'];
const TIME_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$/;
const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
/** Exact key-set match, compared element by element (a joined-string comparison could be fooled by a key containing a comma). */
const hasExactlyKeys = (obj, keys) => {
    const have = Object.keys(obj).sort();
    return have.length === keys.length && have.every((k, i) => k === keys[i]);
};

export function checkHeader(header) {
    if (!isPlainObject(header) || header.schema !== SCHEMA) throw new Error(`trail header schema must be ${SCHEMA}`);
    if (!hasExactlyKeys(header, HEADER_KEYS)) throw new Error(`trail header keys must be exactly ${HEADER_KEYS.join(', ')}`);
    if (typeof header.agent_uuid !== 'string' || header.agent_uuid.length === 0) throw new Error('trail header agent_uuid must be a non-empty string');
    if (typeof header.token_id !== 'string' || !/^[0-9]+$/.test(header.token_id)) throw new Error('trail header token_id must be a decimal string');
    if (typeof header.source !== 'string' || !isPlainObject(header.registry)) throw new Error('trail header source must be a string and registry an object');
    return header;
}

export function checkRecord(record, expectedSeq, prevId) {
    if (!isPlainObject(record) || !hasExactlyKeys(record, RECORD_KEYS)) throw new Error(`seq ${expectedSeq}: record keys must be exactly ${RECORD_KEYS.join(', ')}`);
    if (record.seq !== expectedSeq) throw new Error(`expected seq ${expectedSeq}, found ${record.seq}`);
    if (typeof record.checkpoint_id !== 'string' || record.checkpoint_id.length === 0) throw new Error(`seq ${expectedSeq}: checkpoint_id must be a non-empty string`);
    if (record.prev_checkpoint_id !== prevId) throw new Error(`seq ${expectedSeq}: prev_checkpoint_id does not link to the previous record`);
    if (typeof record.recorded_at !== 'string' || !TIME_RE.test(record.recorded_at)) throw new Error(`seq ${expectedSeq}: recorded_at must be UTC with microseconds`);
    if (typeof record.report_excerpt !== 'string' || !isPlainObject(record.provenance)) throw new Error(`seq ${expectedSeq}: report_excerpt must be a string and provenance an object`);
    return record;
}

/** h_0 commits to the schema and the header, so a trail cannot be replayed under another agent or registry entry. */
export const genesisHash = (header) => sha256(SCHEMA + '\n', canonical(checkHeader(header)));
/** h_i = SHA-256(h_{i-1} || SHA-256(canonical(record_i))) */
export const stepHash = (prev, record) => sha256(prev, sha256(canonical(record)));

/**
 * Walks a trail and returns the commitment after every record in `wanted` (a Set of seq numbers),
 * plus the last one. Validates sequence numbers and prev links as it goes.
 */
export function commitments(header, records, wanted = new Set()) {
    let h = genesisHash(header);
    let prevId = null;
    let seq = 0;
    const at = new Map();
    for (const record of records) {
        seq += 1;
        checkRecord(record, seq, prevId);
        h = stepHash(h, record);
        prevId = record.checkpoint_id;
        if (wanted.has(seq)) at.set(seq, h);
    }
    return { last: h, count: seq, at };
}

/**
 * Reads a trail file and insists that it is byte-for-byte in canonical form: every line must equal the
 * canonical serialization of what it parses to. That rules out duplicate keys, reordered keys, alternate
 * number spellings, blank lines and carriage returns, so two files that verify are the same bytes.
 */
export function readTrail(file) {
    // Fatal decoding: bytes that are not valid UTF-8 are an error, never silently replaced.
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(fs.readFileSync(file));
    if (!text.endsWith('\n')) throw new Error('trail file must end with a newline');
    const lines = text.slice(0, -1).split('\n');
    const values = lines.map((line, i) => {
        let value;
        try {
            value = JSON.parse(line);
        } catch {
            throw new Error(`line ${i + 1} is not JSON`);
        }
        if (value === null || typeof value !== 'object' || canonical(value) !== line) throw new Error(`line ${i + 1} is not in canonical form`);
        return value;
    });
    return { header: checkHeader(values[0]), records: values.slice(1) };
}

export function writeTrail(file, header, records) {
    const out = [canonical(checkHeader(header)), ...records.map(canonical)].join('\n') + '\n';
    fs.writeFileSync(file, out);
}

const u64 = (n) => {
    const b = Buffer.alloc(8);
    b.writeBigUInt64BE(BigInt(n));
    return b;
};

/** 85-byte register-data payload: "CSGN" | version | token_id u64 | to_seq u64 | commitment | previous anchor tx hash (zeros if none). */
export function encodeAnchor({ tokenId, toSeq, commitment, prevAnchorTx }) {
    const prev = prevAnchorTx ? Buffer.from(prevAnchorTx, 'hex') : Buffer.alloc(32);
    if (commitment.length !== 32 || prev.length !== 32) throw new Error('commitment and previous anchor must be 32 bytes');
    return Buffer.concat([ANCHOR_MAGIC, Buffer.from([ANCHOR_VERSION]), u64(tokenId), u64(toSeq), commitment, prev]);
}

export function decodeAnchor(bytes) {
    const b = Buffer.from(bytes);
    if (b.length !== ANCHOR_LENGTH || !b.subarray(0, 4).equals(ANCHOR_MAGIC)) throw new Error('not a countersign anchor');
    if (b[4] !== ANCHOR_VERSION) throw new Error(`unsupported anchor version ${b[4]}`);
    const prev = b.subarray(53, 85);
    if (b.readBigUInt64BE(13) > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('anchor sequence number is out of range');
    return {
        tokenId: b.readBigUInt64BE(5).toString(),
        toSeq: Number(b.readBigUInt64BE(13)),
        commitment: b.subarray(21, 53).toString('hex'),
        prevAnchorTx: prev.every((x) => x === 0) ? null : prev.toString('hex'),
    };
}
