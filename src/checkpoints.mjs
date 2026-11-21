// Read-only UNITARES checkpoint stream reader (core.checkpoint_outbox + core.checkpoints).
import { execFileSync } from 'node:child_process';
import { checkRecord } from './trail.mjs';

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const utf8Fatal = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/**
 * Splits a psql command string into argv using POSIX shell-style quoting ('...', "...", and backslash escapes).
 * Defaults to ['psql', '-d', 'governance'] unless DATABASE_URL or PGDATABASE is set in env (then ['psql']).
 */
export function parsePsqlCommand(psqlSpec, env = process.env) {
    if (psqlSpec === undefined || psqlSpec === null) {
        return env?.DATABASE_URL || env?.PGDATABASE ? ['psql'] : ['psql', '-d', 'governance'];
    }
    if (typeof psqlSpec !== 'string') {
        throw new Error('psql command must be a string');
    }

    const argv = [];
    let current = '';
    let inToken = false;
    let quote = null;

    for (let i = 0; i < psqlSpec.length; i += 1) {
        const ch = psqlSpec[i];
        if (quote === "'") {
            if (ch === "'") quote = null;
            else current += ch;
            continue;
        }
        if (quote === '"') {
            if (ch === '"') {
                quote = null;
            } else if (ch === '\\') {
                if (i + 1 >= psqlSpec.length) throw new Error('unbalanced escape in psql command');
                const next = psqlSpec[i + 1];
                if (next === '"' || next === '\\' || next === '$' || next === '`') {
                    current += next;
                    i += 1;
                } else {
                    current += ch;
                }
            } else {
                current += ch;
            }
            continue;
        }
        if (/\s/.test(ch)) {
            if (inToken) {
                argv.push(current);
                current = '';
                inToken = false;
            }
            continue;
        }
        inToken = true;
        if (ch === "'" || ch === '"') {
            quote = ch;
        } else if (ch === '\\') {
            if (i + 1 >= psqlSpec.length) throw new Error('unbalanced escape in psql command');
            current += psqlSpec[i + 1];
            i += 1;
        } else {
            current += ch;
        }
    }

    if (quote !== null) throw new Error('unbalanced quotes in psql command');
    if (inToken) argv.push(current);
    if (argv.length === 0 || argv[0].length === 0) {
        throw new Error('psql command must not be empty');
    }
    return argv;
}

/** Builds a read-only SQL query over core.checkpoint_outbox joined with core.checkpoints for one agent after `afterSeq`. */
export function buildCheckpointStreamSql({ uuid, afterSeq = 0 }) {
    if (typeof uuid !== 'string' || !UUID_RE.test(uuid)) {
        throw new Error(`invalid agent UUID: ${uuid}`);
    }
    if (!Number.isSafeInteger(afterSeq) || afterSeq < 0) {
        throw new Error(`afterSeq must be a non-negative safe integer, got ${afterSeq}`);
    }
    return [
        'SELECT json_build_object(',
        "'seq', c.seq,",
        "'checkpoint_id', c.checkpoint_id,",
        "'prev_checkpoint_id', c.prev_checkpoint_id,",
        "'recorded_at', to_char(c.recorded_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),",
        "'report_excerpt', COALESCE(c.report_excerpt, ''),",
        "'provenance', c.provenance",
        ')::text',
        'FROM core.checkpoint_outbox o',
        'JOIN core.checkpoints c ON c.checkpoint_id = o.event_id AND c.identity_id = o.identity_id AND c.seq = o.seq',
        'JOIN core.identities i ON i.identity_id = o.identity_id',
        `WHERE i.agent_id = '${uuid}' AND o.event_schema = 'checkpoint.recorded.v1' AND o.seq > ${afterSeq}`,
        'ORDER BY o.seq ASC',
    ].join(' ');
}

function parseAndValidateRows(raw, afterSeq, prevCheckpointId) {
    let text;
    if (typeof raw === 'string') {
        text = raw;
    } else if (Buffer.isBuffer(raw) || raw instanceof Uint8Array) {
        text = utf8Fatal.decode(raw);
    } else if (raw === null || raw === undefined) {
        text = '';
    } else {
        throw new Error('psql output must be a string or Buffer');
    }

    if (text.length === 0) return [];
    const trimmed = text.endsWith('\n') ? text.slice(0, -1) : text;
    if (trimmed.length === 0) {
        throw new Error('unexpected empty row from psql');
    }

    const lines = trimmed.split('\n');
    const rows = [];
    let expectedPrevId = afterSeq === 0 ? null : prevCheckpointId;

    for (let i = 0; i < lines.length; i += 1) {
        const line = lines[i];
        if (line.length === 0) {
            throw new Error(`empty JSON row at line ${i + 1}`);
        }
        let row;
        try {
            row = JSON.parse(line);
        } catch (err) {
            throw new Error(`invalid JSON row at line ${i + 1}: ${err.message}`);
        }

        const expectedSeq = afterSeq + i + 1;
        if (!row || typeof row !== 'object' || Array.isArray(row)) {
            throw new Error(`row ${i + 1} must be a JSON object`);
        }
        if (!Number.isSafeInteger(row.seq) || row.seq <= afterSeq) {
            throw new Error(`row ${i + 1}: seq ${row.seq} must be strictly greater than ${afterSeq}`);
        }
        if (i === 0 && expectedSeq > 1 && expectedPrevId === undefined) {
            if (typeof row.prev_checkpoint_id !== 'string' || row.prev_checkpoint_id.length === 0) {
                throw new Error(`seq ${expectedSeq}: prev_checkpoint_id must be a non-empty string`);
            }
            expectedPrevId = row.prev_checkpoint_id;
        }

        checkRecord(row, expectedSeq, expectedPrevId);
        rows.push(row);
        expectedPrevId = row.checkpoint_id;
    }

    return rows;
}

/**
 * Executes the checkpoint stream SQL query via `psql` and parses/validates strictly contiguous,
 * link-continuous trail records after `afterSeq`.
 */
export function fetchCheckpointsAfter({
    uuid,
    afterSeq = 0,
    prevCheckpointId,
    psql,
    execFile = execFileSync,
    timeoutMs = 30000,
    env = process.env,
}) {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
        throw new Error(`timeoutMs must be a positive safe integer, got ${timeoutMs}`);
    }
    const sql = buildCheckpointStreamSql({ uuid, afterSeq });
    const [bin, ...psqlArgs] = parsePsqlCommand(psql, env);
    const out = execFile(bin, [...psqlArgs, '-v', 'ON_ERROR_STOP=1', '-At', '-c', sql], {
        encoding: 'utf8',
        maxBuffer: 1 << 30,
        timeout: timeoutMs,
        env: { ...env, PGCLIENTENCODING: 'UTF8' },
    });
    if (out && typeof out.then === 'function') {
        return out.then((resolved) => parseAndValidateRows(resolved, afterSeq, prevCheckpointId));
    }
    return parseAndValidateRows(out, afterSeq, prevCheckpointId);
}
