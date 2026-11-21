// Read-only UNITARES checkpoint stream reader (core.checkpoint_outbox + core.checkpoints).
import { execFileSync } from 'node:child_process';
import { checkRecord } from './trail.mjs';

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const utf8Fatal = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

const LIBPQ_URI_PARAM_MAP = new Map([
    ['host', 'PGHOST'],
    ['port', 'PGPORT'],
    ['user', 'PGUSER'],
    ['password', 'PGPASSWORD'],
    ['dbname', 'PGDATABASE'],
    ['sslmode', 'PGSSLMODE'],
    ['sslrootcert', 'PGSSLROOTCERT'],
    ['sslcert', 'PGSSLCERT'],
    ['sslkey', 'PGSSLKEY'],
    ['connect_timeout', 'PGCONNECT_TIMEOUT'],
    ['application_name', 'PGAPPNAME'],
]);

/** Extracts libpq PG* environment variables from a postgres:// or postgresql:// DATABASE_URL without leaking secrets to argv. */
export function parseDatabaseUrlToPgEnv(databaseUrl, baseEnv = {}) {
    let u;
    try {
        u = new URL(databaseUrl);
    } catch (err) {
        throw new Error(`invalid DATABASE_URL: ${err.message}`);
    }
    if (u.protocol !== 'postgres:' && u.protocol !== 'postgresql:') {
        throw new Error(`unsupported DATABASE_URL scheme ${u.protocol}; expected postgres:// or postgresql://`);
    }
    if (u.hostname.includes(',') || (u.searchParams.get('host') ?? '').includes(',')) {
        throw new Error('multi-host DATABASE_URL is not supported');
    }

    const pgEnv = {};
    const hostname = u.hostname ? u.hostname.replace(/^\[(.*)\]$/, '$1') : '';
    if (hostname) pgEnv.PGHOST = hostname;
    if (u.port) pgEnv.PGPORT = u.port;
    if (u.username) pgEnv.PGUSER = decodeURIComponent(u.username);
    if (u.password) pgEnv.PGPASSWORD = decodeURIComponent(u.password);
    const pathDb = u.pathname.startsWith('/') ? u.pathname.slice(1) : u.pathname;
    if (pathDb) pgEnv.PGDATABASE = decodeURIComponent(pathDb);

    const seenParams = new Set();
    for (const [k, v] of u.searchParams.entries()) {
        const envKey = LIBPQ_URI_PARAM_MAP.get(k);
        if (!envKey) {
            throw new Error(`unsupported DATABASE_URL query parameter: ${k}`);
        }
        if (seenParams.has(k)) {
            throw new Error(`duplicate DATABASE_URL query parameter: ${k}`);
        }
        seenParams.add(k);
        if (v !== '') pgEnv[envKey] = v;
    }

    if (!pgEnv.PGDATABASE && !baseEnv?.PGDATABASE) {
        pgEnv.PGDATABASE = 'governance';
    }
    return pgEnv;
}

/**
 * Splits a psql command string into argv using POSIX shell-style quoting ('...', "...", and backslash escapes).
 * Defaults to ['psql', '-d', 'governance'] unless DATABASE_URL or PGDATABASE is set in env (then ['psql']).
 */
export function parsePsqlCommand(psqlSpec, env = process.env) {
    if (psqlSpec === undefined || psqlSpec === null) {
        if (env?.DATABASE_URL) {
            parseDatabaseUrlToPgEnv(env.DATABASE_URL, env);
            return ['psql'];
        }
        return env?.PGDATABASE ? ['psql'] : ['psql', '-d', 'governance'];
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
export function buildCheckpointStreamSql({ uuid, afterSeq = 0, limit = null }) {
    if (typeof uuid !== 'string' || !UUID_RE.test(uuid)) {
        throw new Error(`invalid agent UUID: ${uuid}`);
    }
    if (!Number.isSafeInteger(afterSeq) || afterSeq < 0) {
        throw new Error(`afterSeq must be a non-negative safe integer, got ${afterSeq}`);
    }
    if (limit !== null && limit !== undefined && (!Number.isSafeInteger(limit) || limit <= 0)) {
        throw new Error(`limit must be a positive safe integer or null, got ${limit}`);
    }
    const parts = [
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
    ];
    if (limit !== null && limit !== undefined) {
        parts.push(`LIMIT ${limit}`);
    }
    return parts.join(' ');
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
 * Executes the checkpoint stream SQL query via `psql` in keyset-paginated batches and parses/validates
 * strictly contiguous, link-continuous trail records after `afterSeq`.
 */
export function fetchCheckpointsAfter({
    uuid,
    afterSeq = 0,
    prevCheckpointId,
    psql,
    execFile = execFileSync,
    timeoutMs = 30000,
    batchSize = 5000,
    env = process.env,
}) {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
        throw new Error(`timeoutMs must be a positive safe integer, got ${timeoutMs}`);
    }
    if (!Number.isSafeInteger(batchSize) || batchSize <= 0) {
        throw new Error(`batchSize must be a positive safe integer, got ${batchSize}`);
    }
    const [bin, ...psqlArgs] = parsePsqlCommand(psql, env);
    const childEnv = { ...env };
    if ((psql === undefined || psql === null) && env?.DATABASE_URL) {
        Object.assign(childEnv, parseDatabaseUrlToPgEnv(env.DATABASE_URL, env));
    }
    childEnv.PGCLIENTENCODING = 'UTF8';
    const basePgOptions = String(childEnv.PGOPTIONS ?? '').trim();
    const readOnlyFlag = '-c default_transaction_read_only=on';
    childEnv.PGOPTIONS = basePgOptions
        ? (basePgOptions.includes('default_transaction_read_only=on') ? basePgOptions : `${basePgOptions} ${readOnlyFlag}`)
        : readOnlyFlag;
    const execOpts = {
        encoding: 'utf8',
        maxBuffer: 1 << 30,
        timeout: timeoutMs,
        env: childEnv,
    };

    const allRows = [];
    const runBatch = (cursor, expectedPrev) => {
        const sql = buildCheckpointStreamSql({ uuid, afterSeq: cursor, limit: batchSize });
        const out = execFile(bin, [...psqlArgs, '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-At', '-c', sql], execOpts);
        const handleResult = (raw) => {
            const batch = parseAndValidateRows(raw, cursor, expectedPrev);
            allRows.push(...batch);
            if (batch.length < batchSize) return allRows;
            const last = batch.at(-1);
            return runBatch(last.seq, last.checkpoint_id);
        };
        if (out && typeof out.then === 'function') {
            return out.then(handleResult);
        }
        return handleResult(out);
    };
    return runBatch(afterSeq, afterSeq === 0 ? null : prevCheckpointId);
}
