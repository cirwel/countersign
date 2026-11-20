#!/usr/bin/env node
// countersign: register an agent, export its trail, anchor a commitment, verify.
import crypto from 'node:crypto';
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { parseArgs } from 'node:util';
import { EXPLORER_TX, loadSigner, readRegisterData, sendRegisterData, sendRegistryUpdate } from './chain.mjs';
import { NETWORK, REGISTRY, assertRegistry, mcp } from './registry.mjs';
import { SCHEMA, commitments, decodeAnchor, encodeAnchor, readTrail, writeTrail } from './trail.mjs';

const UUID_KEY = 'unitares.agent_uuid';
const ANCHOR_KEY = 'countersign.anchor';
const hex = (s) => Buffer.from(s, 'utf8').toString('hex');
const sha256hex = (b) => crypto.createHash('sha256').update(b).digest('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function badgeOf(tokenId) {
    const r = await mcp('token_address', { contract_index: REGISTRY.index, contract_subindex: REGISTRY.subindex, token_id: String(tokenId) });
    return r.token_address ?? r.short ?? r;
}

/** The pointer is stored as 64 hex characters of text; the registry rejects values that are not valid text. */
async function anchorPointer(tokenId) {
    const v = await metadata(tokenId, ANCHOR_KEY);
    if (!v) return null;
    const text = Buffer.from(v, 'hex').toString('utf8');
    if (!/^[0-9a-f]{64}$/.test(text)) throw new Error(`metadata ${ANCHOR_KEY} is not a transaction hash`);
    return text;
}

async function metadata(tokenId, key) {
    const r = await mcp('get_metadata', { token_id: String(tokenId), key });
    return r?.value_hex ?? r?.hex ?? null;
}

const commands = {
    /** Mint a registry entry whose on-chain metadata names the agent's UNITARES UUID. */
    async register({ uuid }) {
        if (!/^[0-9a-f-]{36}$/.test(uuid ?? '')) throw new Error('--uuid <agent uuid> is required');
        const who = loadSigner();
        const before = new Set(((await mcp('agents_by_owner', { owner_account: who.address }))?.agents ?? []).map((a) => String(a.token_id)));
        const built = await mcp('build_register', { sender: who.address, initial_metadata: [{ key: UUID_KEY, value_hex: hex(uuid) }] });
        assertRegistry(built.contract_address);
        const { hash } = await sendRegistryUpdate(built, who);
        console.log('registered:', EXPLORER_TX(hash));
        for (let i = 0; i < 20; i++) {
            const mine = ((await mcp('agents_by_owner', { owner_account: who.address }))?.agents ?? []).map((a) => String(a.token_id));
            const fresh = mine.filter((t) => !before.has(t));
            if (fresh.length) {
                const tokenId = fresh.sort((a, b) => Number(b) - Number(a))[0];
                console.log('token_id:', tokenId, 'badge:', await badgeOf(tokenId));
                return;
            }
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
        const json = r.agent_card_json;
        const bytes = typeof json === 'string' ? json : JSON.stringify(json, null, 2);
        fs.writeFileSync(out, bytes);
        console.log('wrote', out, 'sha256', sha256hex(Buffer.from(bytes)), '(server hash', r.metadata_hash_hex, ')');
    },

    /** Pin the hosted card's URL and hash on chain. Run after the card is publicly served. */
    async 'pin-card'({ token, url, file }) {
        const who = loadSigner();
        const local = sha256hex(fs.readFileSync(file));
        const served = sha256hex(Buffer.from(await (await fetch(url)).arrayBuffer()));
        if (local !== served) throw new Error(`the bytes served at ${url} differ from ${file}; host the file verbatim first`);
        const built = await mcp('build_set_agent_uri', { token_id: String(token), agent_uri: url, metadata_hash_hex: local, sender: who.address });
        assertRegistry(built.contract_address);
        const { hash } = await sendRegistryUpdate(built, who);
        console.log('card pinned:', EXPLORER_TX(hash));
    },

    /** Operator side: read an agent's checkpoints from the UNITARES database (read-only) into a canonical trail file. */
    async export({ uuid, token, out, psql = 'psql -d governance' }) {
        if (!/^[0-9a-f-]{36}$/.test(uuid ?? '')) throw new Error('--uuid is required');
        const sql = `copy (select json_build_object(
            'seq', c.seq, 'checkpoint_id', c.checkpoint_id, 'prev_checkpoint_id', c.prev_checkpoint_id,
            'recorded_at', to_char(c.recorded_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
            'report_excerpt', c.report_excerpt, 'provenance', c.provenance)
          from core.checkpoints c join core.identities i using (identity_id)
          where i.agent_id = '${uuid}' order by c.seq) to stdout`;
        const [bin, ...args] = psql.split(' ');
        const rows = execFileSync(bin, [...args, '-At', '-c', sql], { encoding: 'utf8', maxBuffer: 1 << 30 })
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
        const { last, count } = commitments(header, records);
        const prevAnchorTx = await anchorPointer(header.token_id);
        if (prevAnchorTx) {
            const prev = decodeAnchor((await readRegisterData(prevAnchorTx)).data);
            if (prev.toSeq >= count) throw new Error(`the latest anchor already covers seq ${prev.toSeq}; nothing new to anchor`);
        }
        let hash = tx; // --tx <hash>: an anchor that was sent but whose pointer update did not land
        if (hash) {
            const sent = decodeAnchor((await readRegisterData(hash)).data);
            if (sent.commitment !== last.toString('hex') || sent.toSeq !== count) throw new Error('--tx does not match this trail');
        } else {
            const data = encodeAnchor({ tokenId: header.token_id, toSeq: count, commitment: last, prevAnchorTx });
            ({ hash } = await sendRegisterData(data, who));
            console.log(`anchored seq 1..${count}: ${EXPLORER_TX(hash)}`);
        }
        const built = await mcp('build_set_metadata', { token_id: header.token_id, key: ANCHOR_KEY, value_hex: hex(hash), sender: who.address });
        assertRegistry(built.contract_address);
        const set = await sendRegistryUpdate(built, who);
        console.log('registry entry now points at the anchor:', EXPLORER_TX(set.hash));
    },

    /** Anyone: check a badge and a trail file against the chain. Needs no keys. */
    async verify({ badge, trail }) {
        const checks = [];
        const check = (name, ok, detail = '') => {
            checks.push(ok);
            console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  ' + detail : ''}`);
            return ok;
        };
        const { header, records } = readTrail(trail);

        const parsed = await mcp('parse_token_address', { token_address: badge });
        const tokenId = String(parsed.token_id);
        check('badge resolves to the trusted testnet registry', Number(parsed.contract_index ?? parsed.contract?.index) === REGISTRY.index, `<${REGISTRY.index},${REGISTRY.subindex}> token ${tokenId}`);

        const verdict = await mcp('check_badge', { id: badge });
        const v = verdict.badges?.[0] ?? verdict;
        const failed = Object.entries(v.checks ?? {}).filter(([, ok]) => ok === false).map(([k]) => k);
        check('badge check (registered, active, card matches on-chain hash)', v.badge_valid === true, failed.length ? `failed: ${failed.join(', ')}` : `${Object.keys(v.checks ?? {}).length} registry checks`);

        const agent = await mcp('agent_of', { token_id: tokenId });
        const owner = agent?.owner_account ?? agent?.agent?.owner_account;
        check('trail header names this registry token', String(header.token_id) === tokenId && header.registry?.index === REGISTRY.index);

        const onChainUuid = Buffer.from((await metadata(tokenId, UUID_KEY)) ?? '', 'hex').toString('utf8');
        check('on-chain metadata names the same UNITARES agent as the trail', onChainUuid === header.agent_uuid, onChainUuid);

        let txHash = await anchorPointer(tokenId);
        if (!check('registry entry points at an anchor', Boolean(txHash))) return finish(checks);

        // Walk the anchor chain newest to oldest, then compare every anchor against the recomputed chain.
        const anchors = [];
        while (txHash) {
            const tx = await readRegisterData(txHash);
            const a = decodeAnchor(tx.data);
            anchors.push({ txHash, ...a, sender: tx.sender, blockTime: tx.blockTime });
            txHash = a.prevAnchorTx;
        }
        check('every anchor was sent by the registry entry owner', anchors.every((a) => a.sender === owner), owner);
        check('every anchor names this registry token', anchors.every((a) => a.tokenId === tokenId));

        let computed;
        try {
            computed = commitments(header, records, new Set(anchors.map((a) => a.toSeq)));
        } catch (e) {
            check('trail is well formed', false, e.message);
            return finish(checks);
        }
        for (const a of anchors.reverse()) {
            const got = computed.at.get(a.toSeq)?.toString('hex');
            check(`records 1..${a.toSeq} match the commitment anchored ${a.blockTime}`, got === a.commitment, got ? EXPLORER_TX(a.txHash) : `trail has only ${computed.count} records`);
        }
        const covered = Math.max(...anchors.map((a) => a.toSeq));
        if (computed.count > covered) console.log(`note  records ${covered + 1}..${computed.count} are newer than the latest anchor and are not covered by it`);
        return finish(checks);
    },
};

function finish(checks) {
    const ok = checks.every(Boolean);
    console.log(ok ? '\nVERIFIED: the trail matches what was anchored.' : '\nNOT VERIFIED.');
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
