#!/usr/bin/env node
// countersign: register an agent, export its trail, anchor a commitment, verify.
import crypto from 'node:crypto';
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { parseArgs } from 'node:util';
import { EXPLORER_TX, loadSigner, readRegisterData, sendRegisterData, sendRegistryUpdate } from './chain.mjs';
import { NETWORK, REGISTRY, mcp } from './registry.mjs';
import { SCHEMA, commitments, decodeAnchor, encodeAnchor, readTrail, writeTrail } from './trail.mjs';

const UUID_KEY = 'unitares.agent_uuid';
const ANCHOR_KEY = 'countersign.anchor';
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TX_RE = /^[0-9a-f]{64}$/;
const hex = (s) => Buffer.from(s, 'utf8').toString('hex');
const sha256hex = (b) => crypto.createHash('sha256').update(b).digest('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** CIS-2 token id as the registry serializes it: one length byte, then the id little-endian. */
function tokenIdBytes(tokenId) {
    const b = Buffer.alloc(9);
    b[0] = 8;
    b.writeBigUInt64LE(BigInt(tokenId), 1);
    return b;
}
const u32le = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n);
    return b;
};
/** setMetadata parameter, built locally so the payload returned by the registry server can be checked before signing. */
function setMetadataParam(tokenId, key, valueUtf8) {
    const k = Buffer.from(key, 'utf8');
    const v = Buffer.from(valueUtf8, 'utf8');
    return Buffer.concat([tokenIdBytes(tokenId), u32le(k.length), k, u32le(v.length), v]).toString('hex');
}

async function badgeOf(tokenId) {
    const r = await mcp('token_address', { contract_index: REGISTRY.index, contract_subindex: REGISTRY.subindex, token_id: String(tokenId) });
    return r.token_address;
}

async function metadataText(tokenId, key) {
    const r = await mcp('get_metadata', { token_id: String(tokenId), key });
    return r?.value_hex ? Buffer.from(r.value_hex, 'hex').toString('utf8') : null;
}

async function anchorPointer(tokenId) {
    const text = await metadataText(tokenId, ANCHOR_KEY);
    if (text !== null && !TX_RE.test(text)) throw new Error(`metadata ${ANCHOR_KEY} is not a transaction hash`);
    return text;
}

/**
 * Every value the entry's anchor pointer has ever held, oldest first, read from the registry's MetadataSet events.
 * Event layout: 0xf3 | token id (length byte + little-endian id) | key length u32 LE | key | value length u32 LE | value | timestamp u64.
 * The server returns events oldest first; that order is kept within a block.
 */
async function anchorPointerHistory(tokenId) {
    const LIMIT = 1000;
    const r = await mcp('agent_history', { token_id: String(tokenId), limit: LIMIT });
    const events = r.events ?? [];
    if (events.length >= LIMIT) throw new Error('registry history is longer than this verifier reads; refusing to give a partial answer');
    const idBytes = tokenIdBytes(tokenId);
    const out = [];
    for (const e of events) {
        if (e.event_name !== 'MetadataSet') continue;
        const raw = e.payload?.raw_hex;
        if (typeof raw !== 'string' || raw.length % 2 !== 0 || !/^[0-9a-f]*$/.test(raw)) throw new Error('registry event payload is not hex');
        if (!Number.isInteger(e.block_height)) throw new Error('registry event has no block height');
        const b = Buffer.from(raw, 'hex');
        if (b.length < 18 || b[0] !== 0xf3 || !b.subarray(1, 10).equals(idBytes)) throw new Error('unexpected MetadataSet event layout');
        const klen = b.readUInt32LE(10);
        if (b.length < 18 + klen) throw new Error('unexpected MetadataSet event layout');
        const vlen = b.readUInt32LE(14 + klen);
        // The deployed contract appends an 8-byte timestamp after the value; anything else is not a layout this verifier knows.
        if (b.length !== 18 + klen + vlen + 8) throw new Error('unexpected MetadataSet event layout');
        const key = b.subarray(14, 14 + klen).toString('utf8');
        const value = b.subarray(18 + klen, 18 + klen + vlen).toString('utf8');
        if (key === ANCHOR_KEY) out.push({ txHash: value, setIn: e.tx_hash, height: e.block_height });
    }
    return out.map((p, i) => ({ ...p, i })).sort((x, y) => x.height - y.height || x.i - y.i);
}

/** Reads every anchor the entry has pointed at. Throws if a pointer was ever set to something that is not an anchor. */
async function loadAnchors(tokenId) {
    const anchors = [];
    for (const p of await anchorPointerHistory(tokenId)) {
        if (!TX_RE.test(p.txHash)) throw new Error(`the pointer was once set to a value that is not a transaction hash (in ${p.setIn})`);
        const tx = await readRegisterData(p.txHash);
        anchors.push({ txHash: p.txHash, ...decodeAnchor(tx.data), sender: tx.sender, blockTime: tx.blockTime });
    }
    return anchors;
}

const chainIsUnbroken = (anchors) => anchors.every((a, i) => a.prevAnchorTx === (i === 0 ? null : anchors[i - 1].txHash));
const coverageGrows = (anchors) => anchors.every((a, i) => a.toSeq > (i === 0 ? 0 : anchors[i - 1].toSeq));

const commands = {
    /** Mint a registry entry whose on-chain metadata names the agent's UNITARES UUID. */
    async register({ uuid }) {
        if (!UUID_RE.test(uuid ?? '')) throw new Error('--uuid <agent uuid> is required');
        const who = loadSigner();
        const before = new Set(((await mcp('agents_by_owner', { owner_account: who.address }))?.agents ?? []).map((a) => String(a.token_id)));
        const built = await mcp('build_register', { sender: who.address, initial_metadata: [{ key: UUID_KEY, value_hex: hex(uuid) }] });
        const { hash } = await sendRegistryUpdate(built, who, { receiveName: 'CIS-8004.register' });
        console.log('registered:', EXPLORER_TX(hash));
        for (let i = 0; i < 20; i++) {
            const mine = ((await mcp('agents_by_owner', { owner_account: who.address }))?.agents ?? []).map((a) => String(a.token_id));
            const fresh = mine.filter((t) => !before.has(t));
            if (fresh.length === 1) {
                console.log('token_id:', fresh[0], 'badge:', await badgeOf(fresh[0]));
                return;
            }
            if (fresh.length > 1) throw new Error(`several new entries appeared (${fresh.join(', ')}); find yours by transaction ${hash}`);
            await sleep(3000);
        }
        console.log('registered, but the indexer has not listed the new token yet; look it up with agents_by_owner');
    },

    /** Build the Agent Card through the registry server and write the exact bytes to host. */
    async card({ token, name, description, url, out, uuid }) {
        const who = loadSigner();
        const r = await mcp('build_agent_card', {
            name,
            description,
            agent_uri: url,
            owner_account: who.address,
            token_id: String(token),
            documentation_url: 'https://github.com/cirwel/countersign',
            skills: [
                { id: 'countersigned-trail', name: 'Countersigned trail', description: `Check-in record anchored on Concordium testnet; UNITARES agent ${uuid}.`, tags: ['audit', 'unitares'] },
            ],
        });
        const local = sha256hex(Buffer.from(r.agent_card_json));
        if (local !== r.metadata_hash_hex) throw new Error('the registry server reported a different hash for the card it returned');
        fs.writeFileSync(out, r.agent_card_json);
        console.log('wrote', out, 'sha256', local);
    },

    /** Pin the hosted card's URL and hash on chain. Run after the card is publicly served. */
    async 'pin-card'({ token, url, file }) {
        const who = loadSigner();
        const local = sha256hex(fs.readFileSync(file));
        const served = sha256hex(Buffer.from(await (await fetch(url, { redirect: 'error' })).arrayBuffer()));
        if (local !== served) throw new Error(`the bytes served at ${url} differ from ${file}; host the file verbatim first`);
        const built = await mcp('build_set_agent_uri', { token_id: String(token), agent_uri: url, metadata_hash_hex: local, sender: who.address });
        const { hash } = await sendRegistryUpdate(built, who, { receiveName: 'CIS-8004.setAgentURI' });
        console.log('card pinned:', EXPLORER_TX(hash));
    },

    /** Operator side: read an agent's checkpoints from the UNITARES database (read-only) into a canonical trail file. */
    async export({ uuid, token, out, psql = 'psql -d governance' }) {
        if (!UUID_RE.test(uuid ?? '')) throw new Error('--uuid is required');
        if (!/^[0-9]+$/.test(token ?? '')) throw new Error('--token <id> is required');
        const sql = `copy (select json_build_object(
            'seq', c.seq, 'checkpoint_id', c.checkpoint_id, 'prev_checkpoint_id', c.prev_checkpoint_id,
            'recorded_at', to_char(c.recorded_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
            'report_excerpt', c.report_excerpt, 'provenance', c.provenance)
          from core.checkpoints c join core.identities i using (identity_id)
          where i.agent_id = '${uuid}' order by c.seq) to stdout`;
        const [bin, ...args] = psql.split(' ');
        // COPY text format doubles backslashes; json_build_object emits no raw control characters, so that is the only escape to undo.
        const rows = execFileSync(bin, [...args, '-At', '-c', sql], { encoding: 'utf8', maxBuffer: 1 << 30, env: { ...process.env, PGCLIENTENCODING: 'UTF8' } })
            .split('\n')
            .filter(Boolean)
            .map((l) => JSON.parse(l.replace(/\\\\/g, '\\')));
        const header = { schema: SCHEMA, source: 'unitares core.checkpoints', agent_uuid: uuid, token_id: String(token), registry: { network: NETWORK, ...REGISTRY } };
        writeTrail(out, header, rows);
        const { last, count } = commitments(header, rows);
        console.log(`exported ${count} records to ${out}; commitment ${last.toString('hex')}`);
    },

    /** Write the trail's current commitment to testnet and point the registry entry at it. */
    async anchor({ trail, tx }) {
        const who = loadSigner();
        const { header, records } = readTrail(trail);
        const tokenId = header.token_id;
        const existing = await loadAnchors(tokenId);
        const { last, count, at } = commitments(header, records, new Set(existing.map((a) => a.toSeq)));
        // Never extend a chain this trail no longer agrees with: a new anchor over a drifted record would break every earlier one.
        if (!chainIsUnbroken(existing)) throw new Error('the existing anchors do not form one chain; refusing to add to it');
        for (const a of existing) {
            if (at.get(a.toSeq)?.toString('hex') !== a.commitment) throw new Error(`this trail does not match the anchor covering records 1..${a.toSeq} (${a.txHash}); refusing to anchor`);
        }
        const prev = existing.at(-1) ?? null;
        if ((await anchorPointer(tokenId)) !== (prev?.txHash ?? null)) throw new Error('the current pointer is not the last one in the event history yet; retry shortly');
        if (prev && prev.toSeq >= count) throw new Error(`the latest anchor already covers seq ${prev.toSeq}; nothing new to anchor`);

        let hash = tx; // --tx <hash>: an anchor that was sent but whose pointer update did not land
        if (hash) {
            if (!TX_RE.test(hash)) throw new Error('--tx must be a transaction hash');
            const sent = await readRegisterData(hash);
            const d = decodeAnchor(sent.data);
            const ok = sent.sender === who.address && d.tokenId === tokenId && d.toSeq === count && d.commitment === last.toString('hex') && d.prevAnchorTx === (prev?.txHash ?? null);
            if (!ok) throw new Error('--tx is not the next anchor for this trail');
        } else {
            const data = encodeAnchor({ tokenId, toSeq: count, commitment: last, prevAnchorTx: prev?.txHash ?? null });
            ({ hash } = await sendRegisterData(data, who));
            console.log(`anchored seq 1..${count}: ${EXPLORER_TX(hash)}`);
        }
        const built = await mcp('build_set_metadata', { token_id: tokenId, key: ANCHOR_KEY, value_hex: hex(hash), sender: who.address });
        const set = await sendRegistryUpdate(built, who, { receiveName: 'CIS-8004.setMetadata', parameterHex: setMetadataParam(tokenId, ANCHOR_KEY, hash) });
        console.log('registry entry now points at the anchor:', EXPLORER_TX(set.hash));
    },

    /** Anyone: check a badge and a trail file against the chain. Needs no keys. */
    async verify({ badge, trail }) {
        process.exitCode = 1; // only a completed, fully passing run resets this
        const checks = [];
        let covered = 0;
        const check = (name, ok, detail = '') => {
            checks.push(ok);
            console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  ' + detail : ''}`);
            return ok;
        };
        let header, records;
        try {
            ({ header, records } = readTrail(trail));
        } catch (e) {
            check('trail file is in canonical form', false, e.message);
            return finish(checks);
        }

        const parsed = await mcp('parse_token_address', { token_address: badge });
        const tokenId = String(parsed.token_id);
        const onTrustedRegistry = Number(parsed.contract_index) === REGISTRY.index && Number(parsed.contract_subindex) === REGISTRY.subindex;
        if (!check('badge resolves to the trusted testnet registry', onTrustedRegistry, `<${parsed.contract_index},${parsed.contract_subindex}> token ${tokenId}`)) return finish(checks);

        const v = await mcp('check_badge', { id: badge });
        const failed = Object.entries(v.checks ?? {}).filter(([, ok]) => ok === false).map(([k]) => k);
        check('badge check (registered, active, card matches on-chain hash)', v.badge_valid === true && String(v.token_id) === tokenId, failed.length ? `failed: ${failed.join(', ')}` : `${Object.keys(v.checks ?? {}).length} registry checks`);

        const owner = (await mcp('agent_of', { token_id: tokenId }))?.owner_account;
        const r = header.registry ?? {};
        check('trail header names this registry token', header.token_id === tokenId && r.network === NETWORK && r.index === REGISTRY.index && r.subindex === REGISTRY.subindex);

        const onChainUuid = await metadataText(tokenId, UUID_KEY);
        check('on-chain metadata names the same UNITARES agent as the trail', UUID_RE.test(onChainUuid ?? '') && onChainUuid === header.agent_uuid, onChainUuid ?? 'not set');

        const current = await anchorPointer(tokenId);
        if (!check('registry entry points at an anchor', Boolean(current))) return finish(checks);

        // Check every anchor the entry has ever pointed at, not only the current one.
        // Otherwise the owner could repoint the entry at a fresh anchor over an edited trail.
        let anchors;
        try {
            anchors = await loadAnchors(tokenId);
        } catch (e) {
            check('every pointer the entry has held is an anchor transaction', false, e.message);
            return finish(checks);
        }
        check('the current pointer is the last one in the registry event history', anchors.at(-1)?.txHash === current, `${anchors.length} pointer updates`);
        check('every anchor was sent by the registry entry owner', Boolean(owner) && anchors.every((a) => a.sender === owner), owner);
        check('every anchor names this registry token', anchors.every((a) => a.tokenId === tokenId));
        check('anchors form one unbroken chain (each names the one before it, none was skipped or replaced)', chainIsUnbroken(anchors));
        check('each anchor covers more records than the one before', coverageGrows(anchors));

        let computed;
        try {
            computed = commitments(header, records, new Set(anchors.map((a) => a.toSeq)));
        } catch (e) {
            check('trail is well formed', false, e.message);
            return finish(checks);
        }
        for (const a of anchors) {
            const got = computed.at.get(a.toSeq)?.toString('hex');
            check(`records 1..${a.toSeq} match the commitment anchored ${a.blockTime}`, got === a.commitment, got ? EXPLORER_TX(a.txHash) : `trail has only ${computed.count} records`);
        }
        covered = anchors.at(-1)?.toSeq ?? 0;
        if (computed.count > covered) console.log(`note  records ${covered + 1}..${computed.count} are newer than the latest anchor and are not covered by it`);
        return finish(checks, covered);
    },
};

function finish(checks, covered = 0) {
    const ok = checks.length > 0 && checks.every(Boolean) && covered > 0;
    console.log(ok ? `\nVERIFIED: records 1..${covered} match what was anchored.` : '\nNOT VERIFIED.');
    process.exitCode = ok ? 0 : 1;
}

const [name, ...rest] = process.argv.slice(2);
if (!commands[name]) {
    console.log(`usage: countersign <${Object.keys(commands).join(' | ')}> [--options]`);
    process.exit(name ? 2 : 0);
}
const { values } = parseArgs({
    args: rest,
    options: Object.fromEntries(['uuid', 'token', 'name', 'description', 'url', 'out', 'file', 'trail', 'badge', 'psql', 'tx'].map((k) => [k, { type: 'string' }])),
});
commands[name](values).catch((e) => {
    console.error('error:', e.message);
    process.exit(1);
});
