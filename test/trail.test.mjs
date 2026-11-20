import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonical, commitments, decodeAnchor, encodeAnchor, genesisHash, readTrail } from '../src/trail.mjs';

const header = { schema: 'countersign.trail.v1', source: 'test', agent_uuid: '00000000-0000-4000-8000-000000000001', token_id: '7', registry: { network: 'testnet', index: 12802, subindex: 0 } };
const rec = (seq, prev, text) => ({
    seq,
    checkpoint_id: `id-${seq}`,
    prev_checkpoint_id: prev,
    recorded_at: `2026-11-0${seq}T00:00:00.000000Z`,
    report_excerpt: text,
    provenance: { producer: 'sync_state' },
});
const records = () => [rec(1, null, 'one'), rec(2, 'id-1', 'two'), rec(3, 'id-2', 'three')];

test('canonical JSON sorts keys and is insensitive to input key order', () => {
    assert.equal(canonical({ b: 1, a: [true, null, 'x'] }), '{"a":[true,null,"x"],"b":1}');
    assert.equal(canonical({ z: { y: 1, x: 2 } }), canonical({ z: { x: 2, y: 1 } }));
    assert.throws(() => canonical({ a: 1.5 }));
});

test('the commitment is stable and every prefix has its own commitment', () => {
    const a = commitments(header, records(), new Set([1, 2]));
    const b = commitments(header, records(), new Set([1, 2]));
    assert.equal(a.last.toString('hex'), b.last.toString('hex'));
    assert.equal(a.count, 3);
    assert.notEqual(a.at.get(1).toString('hex'), a.at.get(2).toString('hex'));
    // A prefix commitment does not depend on later records.
    assert.equal(commitments(header, records().slice(0, 2)).last.toString('hex'), a.at.get(2).toString('hex'));
});

test('changing one character of one record changes every later commitment', () => {
    const honest = commitments(header, records(), new Set([1, 2, 3]));
    const edited = records();
    edited[1].report_excerpt = 'twO';
    const tampered = commitments(header, edited, new Set([1, 2, 3]));
    assert.equal(tampered.at.get(1).toString('hex'), honest.at.get(1).toString('hex'));
    assert.notEqual(tampered.at.get(2).toString('hex'), honest.at.get(2).toString('hex'));
    assert.notEqual(tampered.at.get(3).toString('hex'), honest.at.get(3).toString('hex'));
});

test('dropping, reordering or relinking records is rejected', () => {
    const r = records();
    assert.throws(() => commitments(header, [r[0], r[2]]), /expected seq 2/);
    assert.throws(() => commitments(header, [r[1], r[0], r[2]]), /expected seq 1/);
    const relinked = records();
    relinked[2].prev_checkpoint_id = 'id-1';
    assert.throws(() => commitments(header, relinked), /does not link/);
    const extraKey = records();
    extraKey[0].note = 'x';
    assert.throws(() => commitments(header, extraKey), /record keys/);
});

test('the header is part of the commitment', () => {
    const other = { ...header, token_id: '8' };
    assert.notEqual(genesisHash(header).toString('hex'), genesisHash(other).toString('hex'));
    assert.notEqual(commitments(header, records()).last.toString('hex'), commitments(other, records()).last.toString('hex'));
});

test('anchor payload round-trips and rejects foreign data', () => {
    const { last } = commitments(header, records());
    const first = encodeAnchor({ tokenId: '7', toSeq: 3, commitment: last, prevAnchorTx: null });
    assert.equal(first.length, 85);
    assert.deepEqual(decodeAnchor(first), { tokenId: '7', toSeq: 3, commitment: last.toString('hex'), prevAnchorTx: null });
    const prev = 'ab'.repeat(32);
    assert.equal(decodeAnchor(encodeAnchor({ tokenId: '7', toSeq: 9, commitment: last, prevAnchorTx: prev })).prevAnchorTx, prev);
    assert.throws(() => decodeAnchor(Buffer.alloc(85)), /not a countersign anchor/);
    assert.throws(() => decodeAnchor(Buffer.alloc(32)), /not a countersign anchor/);
});

test('the published Watcher trail is well formed', () => {
    const { header: h, records: rs } = readTrail(new URL('../trail/watcher.jsonl', import.meta.url).pathname);
    const { count } = commitments(h, rs);
    assert.ok(count > 1000);
    assert.equal(h.agent_uuid, '907e3195-c649-49db-b753-1edc1a105f33');
});

test('a trail file must be byte-for-byte canonical', async () => {
    const fs = await import('node:fs');
    const os = await import('node:os');
    const path = await import('node:path');
    const { writeTrail } = await import('../src/trail.mjs');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'countersign-test-'));
    const good = path.join(dir, 'good.jsonl');
    writeTrail(good, header, records());
    assert.equal(readTrail(good).records.length, 3);
    const text = fs.readFileSync(good, 'utf8');
    const variants = {
        'duplicate key': text.replace('"report_excerpt":"two"', '"report_excerpt":"evil","report_excerpt":"two"'),
        'number respelled': text.replace('"seq":2', '"seq":2.0'),
        'carriage returns': text.replace(/\n/g, '\r\n'),
        'blank line': text.replace('\n', '\n\n'),
        'no final newline': text.slice(0, -1),
        'extra whitespace': text.replace('"seq":2', '"seq": 2'),
    };
    for (const [name, body] of Object.entries(variants)) {
        const f = path.join(dir, 'bad.jsonl');
        fs.writeFileSync(f, body);
        assert.throws(() => readTrail(f), undefined, name);
    }
    fs.rmSync(dir, { recursive: true });
});

test('object keys are ordered by code point, not UTF-16 code unit', () => {
    // U+FF5E sorts before U+1F600 by code point but after it by UTF-16 code unit.
    assert.equal(canonical({ '\u{1F600}': 1, '～': 2 }), '{"～":2,"\u{1F600}":1}');
});

test('record and header fields are type-checked, and key sets are compared exactly', () => {
    const bad = (mutate) => { const r = records(); mutate(r); return () => commitments(header, r); };
    assert.throws(bad((r) => { r[0].recorded_at = 'yesterday'; }), /recorded_at/);
    assert.throws(bad((r) => { r[0].report_excerpt = 7; }), /report_excerpt/);
    assert.throws(bad((r) => { r[0].provenance = []; }), /provenance/);
    // One key containing commas must not stand in for several keys.
    assert.throws(() => commitments(header, [{ 'checkpoint_id,prev_checkpoint_id,provenance,recorded_at,report_excerpt,seq': 1 }]), /record keys/);
    assert.throws(() => genesisHash({ ...header, token_id: 7 }), /token_id/);
    assert.throws(() => genesisHash({ ...header, extra: 1 }), /header keys/);
});

test('an anchor with an out-of-range sequence number is rejected', () => {
    const { last } = commitments(header, records());
    const a = encodeAnchor({ tokenId: '7', toSeq: 3, commitment: last, prevAnchorTx: null });
    a.writeBigUInt64BE(2n ** 60n, 13);
    assert.throws(() => decodeAnchor(a), /out of range/);
});
