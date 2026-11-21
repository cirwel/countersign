import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import https from 'node:https';
import { test } from 'node:test';
import zlib from 'node:zlib';
import { AccountAddress, ContractAddress, tokenAddressToBase58 } from '@concordium/web-sdk';
import {
    decodeAgentOf,
    decodeBadge,
    decodeGetAdmin,
    decodeGetMetadata,
    decodeGetMetadataUtf8,
    encodeBadge,
    encodeGetMetadataParam,
    encodeSetMetadataParam,
    encodeTokenId,
    fetchAgentCard,
    isDisallowedIp,
    parseCis2Event,
    parseMetadataSetEvent,
    verifyAgentCardBytes,
} from '../src/cis8004.mjs';
import { REGISTRY } from '../src/registry.mjs';

const WATCHER_BADGE = 'JyP9UYjHZ84JsGq5rAC2F';
const WATCHER_OWNER = '4NAnnhZUSYiyJLM9k6H7dVPn1uuPGStu2LZEety7zmp1LBYw41';
const WATCHER_CARD_HASH = '52666d54c7e076ff29adcc58dcd6b3c5deb55f06e1e2c4df9e29a64e0179e695';

// Captured verbatim from CIS-8004.agentOf(1315) on <12802,0> testnet.
const WATCHER_AGENT_OF_HEX =
    '01082305000000000000' +
    'bb2793c76eea40efa19981902c47b71d607be55f0581581bfff18e65aeec2a62' +
    '015100000068747470733a2f2f7261772e67697468756275736572636f6e74656e742e636f6d2f63697277656c2f636f756e7465727369676e2f6d61696e2f6167656e742d636172642f776174636865722e6a736f6e' +
    '0152666d54c7e076ff29adcc58dcd6b3c5deb55f06e1e2c4df9e29a64e0179e695' +
    '00' +
    '01bb2793c76eea40efa19981902c47b71d607be55f0581581bfff18e65aeec2a62' +
    '00' +
    'a1208cf7a1010000' +
    '00' +
    '00' +
    '02000000' +
    '13000000756e6974617265732e6167656e745f757569642400000039303765333139352d633634392d343964622d623735332d316564633161313035663333' +
    '12000000636f756e7465727369676e2e616e63686f724000000065316138636165346337656162323363653666313833363234356566663338623331393235373937326337373735356161353430333162306262343562396638';

// Captured verbatim from CIS-8004.agentOf(5) on <12802,0> testnet (includes externalReference).
const TOKEN5_AGENT_OF_HEX =
    '010805000000000000005b22021a5a27dc3a25d9cde2887e208f818b5a55dcfc6b2c3c0271634ab331c9' +
    '014f00000068747470733a2f2f74697070696e67736572766963652e636f2e756b2f6167656e74732f71756965745f6c65646765725f36332f2e77656c6c2d6b6e6f776e2f6167656e742d636172642e6a736f6e' +
    '01f1a0b9059a3be9606a38e7703a7ff9fba737fbee83782caede58f50be4e62498' +
    '010132000000000000000000000000000000080000006569703135353a3116000000736563703235366b312d756e636f6d707265737365644100000004e7ade1eb21bdd4f9d77a231fa84befcb6969271af2c0883c60e6338fe575d630c4ee0bb55b383de7b5b88f15f2a8ff3970c5178d5d538d856b31eac269bfc3a2' +
    '015b22021a5a27dc3a25d9cde2887e208f818b5a55dcfc6b2c3c0271634ab331c9' +
    '00e6eb596a9e010000000000000000';

// Captured verbatim from Watcher's registration tx 4ea50cb8... and latest anchor pointer update.
const WATCHER_MINT_HEX = 'fe0823050000000000000100bb2793c76eea40efa19981902c47b71d607be55f0581581bfff18e65aeec2a62';
const WATCHER_REGISTERED_HEX = 'f0082305000000000000bb2793c76eea40efa19981902c47b71d607be55f0581581bfff18e65aeec2a62000000a1208cf7a1010000';
const WATCHER_WALLET_SET_HEX = 'f508230500000000000001bb2793c76eea40efa19981902c47b71d607be55f0581581bfff18e65aeec2a62a1208cf7a1010000';
const WATCHER_METADATA_SET_HEX =
    'f308230500000000000012000000636f756e7465727369676e2e616e63686f72' +
    '4000000065316138636165346337656162323363653666313833363234356566663338623331393235373937326337373735356161353430333162306262343562396638' +
    '0f2e96faa1010000';

const u16le = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n, 0);
    return b;
};

const u32le = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n, 0);
    return b;
};

const u64le = (n) => {
    const b = Buffer.alloc(8);
    b.writeBigUInt64LE(BigInt(n), 0);
    return b;
};

const strU32 = (s) => {
    const b = Buffer.from(s, 'utf8');
    return Buffer.concat([u32le(b.length), b]);
};

function makeMockRequestFn({ statusCode = 200, headers = {}, chunks = [], delayMs = 0, abortBeforeEnd = false, lookupOpts = { all: true } } = {}) {
    return (_url, opts, onRes) => {
        const req = new EventEmitter();
        req.destroyed = false;
        req.destroy = (err) => {
            if (req.destroyed) return;
            req.destroyed = true;
            if (err) process.nextTick(() => req.emit('error', err));
        };
        req.end = () => {
            opts.lookup('card.example', lookupOpts, (err, resolved) => {
                if (req.destroyed) return;
                if (err) {
                    req.emit('error', err);
                    return;
                }
                assert.ok(resolved);
                if (delayMs > 0) return; // let timeout fire
                const res = new EventEmitter();
                res.statusCode = statusCode;
                res.headers = headers;
                res.resume = () => {};
                res.destroy = (dErr) => {
                    req.destroyed = true;
                    if (dErr) process.nextTick(() => res.emit('error', dErr));
                };
                onRes(res);
                process.nextTick(() => {
                    for (const c of chunks) {
                        if (req.destroyed) return;
                        res.emit('data', Buffer.from(c));
                    }
                    if (!req.destroyed) {
                        if (abortBeforeEnd) res.emit('aborted');
                        else res.emit('end');
                    }
                });
            });
        };
        return req;
    };
}

test('badge encode/decode round-trips Watcher and rejects bad token_id encodings', () => {
    assert.equal(encodeBadge('1315'), WATCHER_BADGE);
    assert.deepEqual(decodeBadge(WATCHER_BADGE), {
        contract: { index: 12802, subindex: 0 },
        tokenId: '1315',
    });

    const other = encodeBadge('42', { index: 99, subindex: 1 });
    assert.deepEqual(decodeBadge(other), { contract: { index: 99, subindex: 1 }, tokenId: '42' });

    const shortIdBadge = tokenAddressToBase58({ contract: ContractAddress.create(12802n, 0n), id: '01' });
    assert.throws(() => decodeBadge(shortIdBadge), /token id encoding/);
    assert.throws(() => decodeBadge('not-a-badge'));
    assert.throws(() => decodeBadge(''), /non-empty/);
});

test('parameter encoders produce exact CIS-8004 layouts', () => {
    assert.equal(encodeTokenId('1315').toString('hex'), '082305000000000000');
    assert.equal(
        encodeGetMetadataParam('1315', 'countersign.anchor').toString('hex'),
        '08230500000000000012000000636f756e7465727369676e2e616e63686f72',
    );
    assert.equal(
        encodeSetMetadataParam('1315', 'k', 'val').toString('hex'),
        '082305000000000000010000006b0300000076616c',
    );
    assert.throws(() => encodeTokenId('-1'));
    assert.throws(() => encodeTokenId(2n ** 64n));
});

test('decodeAgentOf decodes real Watcher and Token 5 bytes, None, Revoked, and rejects malformed bytes', () => {
    const watcher = decodeAgentOf(Buffer.from(WATCHER_AGENT_OF_HEX, 'hex'));
    assert.equal(watcher.tokenId, '1315');
    assert.equal(watcher.ownerAccount, WATCHER_OWNER);
    assert.equal(watcher.agentUri, 'https://raw.githubusercontent.com/cirwel/countersign/main/agent-card/watcher.json');
    assert.equal(watcher.metadataHashHex, WATCHER_CARD_HASH);
    assert.equal(watcher.externalReference, null);
    assert.equal(watcher.agentWallet, WATCHER_OWNER);
    assert.equal(watcher.status, 'Active');
    assert.equal(watcher.registeredAtMs, Date.parse('2026-11-20T06:01:58.177Z'));
    assert.equal(watcher.revokedAtMs, null);
    assert.equal(watcher.revocationReason, null);
    assert.equal(watcher.onChainMetadata.length, 2);
    assert.equal(watcher.onChainMetadata[0].key, 'unitares.agent_uuid');
    assert.equal(watcher.onChainMetadata[0].value.toString('utf8'), '907e3195-c649-49db-b753-1edc1a105f33');
    assert.equal(watcher.onChainMetadata[1].key, 'countersign.anchor');

    const t5 = decodeAgentOf(Buffer.from(TOKEN5_AGENT_OF_HEX, 'hex'));
    assert.equal(t5.tokenId, '5');
    assert.deepEqual(t5.externalReference.contractAddress, { index: 12801, subindex: 0 });
    assert.equal(t5.externalReference.kind, 'Cis8');
    assert.equal(t5.externalReference.namespace, 'eip155:1');
    assert.equal(t5.externalReference.keyType, 'secp256k1-uncompressed');
    assert.equal(t5.externalReference.publicKeyHex.length, 130);

    assert.equal(decodeAgentOf(Buffer.from([0])), null);

    const ownerBytes = Buffer.from(AccountAddress.fromBase58(WATCHER_OWNER).decodedAddress);
    const reason = Buffer.from('compromised key', 'utf8');
    const revokedBuf = Buffer.concat([
        Buffer.from([1]),
        encodeTokenId('7'),
        ownerBytes,
        Buffer.from([0, 0, 0, 0]),
        Buffer.from([1]),
        u64le(1700000000000n),
        Buffer.from([1]),
        u64le(1700000005000n),
        Buffer.from([1]),
        u32le(reason.length),
        reason,
        u32le(0),
    ]);
    const rev = decodeAgentOf(revokedBuf);
    assert.equal(rev.status, 'Revoked');
    assert.equal(rev.revokedAtMs, 1700000005000);
    assert.equal(rev.revocationReason, 'compromised key');

    const watcherBuf = Buffer.from(WATCHER_AGENT_OF_HEX, 'hex');
    assert.throws(() => decodeAgentOf(Buffer.concat([watcherBuf, Buffer.from([0])])), /trailing/);
    assert.throws(() => decodeAgentOf(watcherBuf.subarray(0, -1)), /truncated/);
    assert.throws(() => decodeAgentOf(Buffer.from([0, 0])), /trailing/);
    assert.throws(() => decodeAgentOf(Buffer.from([2])), /Option tag/);
    const badStatus = Buffer.from(revokedBuf);
    badStatus[1 + 9 + 32 + 4] = 9;
    assert.throws(() => decodeAgentOf(badStatus), /status tag/);
});

test('decodeGetMetadata, parseMetadataSetEvent, and decodeAgentOf preserve UTF-8 BOMs without stripping', () => {
    const bom = Buffer.from([0xef, 0xbb, 0xbf]);
    const bomKey = Buffer.concat([bom, Buffer.from('countersign.anchor', 'utf8')]);
    const bomHash = Buffer.concat([bom, Buffer.from('a'.repeat(64), 'utf8')]);

    // decodeGetMetadataUtf8 must NOT strip leading UTF-8 BOM into valid 64-hex hash.
    const metaPayload = Buffer.concat([Buffer.from([1]), u32le(bomHash.length), bomHash]);
    const decodedHash = decodeGetMetadataUtf8(metaPayload);
    assert.equal(decodedHash.codePointAt(0), 0xfeff);
    assert.equal(decodedHash.length, 65);
    assert.equal(/^[0-9a-f]{64}$/.test(decodedHash), false);

    // parseMetadataSetEvent must preserve BOM in key so it never aliases 'countersign.anchor'.
    const evHex = Buffer.concat([
        Buffer.from([0xf3]),
        encodeTokenId('1315'),
        u32le(bomKey.length),
        bomKey,
        u32le(bomHash.length),
        bomHash,
        u64le(1700000000000n),
    ]).toString('hex');
    const ev = parseMetadataSetEvent(evHex, '1315');
    assert.equal(ev.key, '\uFEFFcountersign.anchor');
    assert.notEqual(ev.key, 'countersign.anchor');

    // decodeAgentOf preserves BOM in agentUri and metadata keys.
    const ownerBytes = Buffer.from(AccountAddress.fromBase58(WATCHER_OWNER).decodedAddress);
    const bomUri = Buffer.concat([bom, Buffer.from('https://example.com/card.json', 'utf8')]);
    const agentBuf = Buffer.concat([
        Buffer.from([1]),
        encodeTokenId('1315'),
        ownerBytes,
        Buffer.from([1]),
        u32le(bomUri.length),
        bomUri,
        Buffer.from([0, 0, 0, 0]),
        u64le(1700000000000n),
        Buffer.from([0, 0]),
        u32le(1),
        u32le(bomKey.length),
        bomKey,
        u32le(0),
    ]);
    const agent = decodeAgentOf(agentBuf);
    assert.equal(agent.agentUri.codePointAt(0), 0xfeff);
    assert.equal(agent.onChainMetadata[0].key, '\uFEFFcountersign.anchor');
});

test('decodeGetMetadata and decodeGetMetadataUtf8 strictly decode Option<Vec<u8>>', () => {
    assert.equal(decodeGetMetadata(Buffer.from([0])), null);
    assert.equal(decodeGetMetadataUtf8(Buffer.from([0])), null);

    const payload = Buffer.from('hello', 'utf8');
    const some = Buffer.concat([Buffer.from([1]), u32le(payload.length), payload]);
    assert.deepEqual(decodeGetMetadata(some), payload);
    assert.equal(decodeGetMetadataUtf8(some), 'hello');

    const badUtf8 = Buffer.concat([Buffer.from([1]), u32le(2), Buffer.from([0xff, 0x80])]);
    assert.deepEqual(decodeGetMetadata(badUtf8), Buffer.from([0xff, 0x80]));
    assert.throws(() => decodeGetMetadataUtf8(badUtf8));

    assert.throws(() => decodeGetMetadata(Buffer.concat([some, Buffer.from([0])])), /trailing/);
    assert.throws(() => decodeGetMetadata(some.subarray(0, -1)), /truncated/);
    assert.throws(() => decodeGetMetadata(Buffer.from([0, 0])), /trailing/);
});

test('parseMetadataSetEvent parses matching tokenId, skips others, and throws on malformed target events', () => {
    const parsed = parseMetadataSetEvent(WATCHER_METADATA_SET_HEX, '1315');
    assert.equal(parsed.tokenId, '1315');
    assert.equal(parsed.key, 'countersign.anchor');
    assert.equal(parsed.value.toString('utf8'), 'e1a8cae4c7eab23ce6f1836245eff38b319257972c77755aa54031b0bb45b9f8');
    assert.equal(parsed.timestampMs, Date.parse('2026-11-20T20:11:48.623Z'));

    assert.equal(parseMetadataSetEvent(WATCHER_MINT_HEX, '1315'), null);
    assert.equal(parseMetadataSetEvent(WATCHER_METADATA_SET_HEX, '1316'), null);
    assert.equal(parseMetadataSetEvent('', '1315'), null);

    assert.throws(() => parseMetadataSetEvent(WATCHER_METADATA_SET_HEX + '00', '1315'), /trailing/);
    assert.throws(() => parseMetadataSetEvent(WATCHER_METADATA_SET_HEX.slice(0, -2), '1315'), /truncated/);
    assert.throws(() => parseMetadataSetEvent('f308', '1315'), /truncated/);
    assert.throws(() => parseMetadataSetEvent(WATCHER_METADATA_SET_HEX.toUpperCase(), '1315'), /lowercase hex/);
    assert.throws(() => parseMetadataSetEvent('f30', '1315'), /lowercase hex/);

    const badKeyEvent = Buffer.concat([
        Buffer.from([0xf3]),
        encodeTokenId('1315'),
        u32le(2),
        Buffer.from([0xff, 0xfe]),
        u32le(0),
        u64le(1000n),
    ]).toString('hex');
    assert.throws(() => parseMetadataSetEvent(badKeyEvent, '1315'));
});

test('parseCis2Event decodes all CIS-8004/CIS-2 tags explicitly and returns Unknown for unrecognized tags', () => {
    assert.deepEqual(parseCis2Event(WATCHER_MINT_HEX), {
        type: 'Mint',
        tokenId: '1315',
        tokenIdHex: '2305000000000000',
        amount: 1n,
        owner: WATCHER_OWNER,
    });

    const regEv = parseCis2Event(WATCHER_REGISTERED_HEX);
    assert.equal(regEv.type, 'Registered');
    assert.equal(regEv.tokenId, '1315');
    assert.equal(regEv.ownerAccount, WATCHER_OWNER);
    assert.equal(regEv.agentUri, null);

    const walletEv = parseCis2Event(WATCHER_WALLET_SET_HEX);
    assert.equal(walletEv.type, 'AgentWalletSet');
    assert.equal(walletEv.tokenId, '1315');
    assert.equal(walletEv.newWallet, WATCHER_OWNER);

    const ownerBytes = Buffer.from(AccountAddress.fromBase58(WATCHER_OWNER).decodedAddress);
    const otherAcct = '3dt3UMPzRASZndjmKpSWgCP2HhmoxZrgs8FDPtZjNHZzj13hhB';
    const otherBytes = Buffer.from(AccountAddress.fromBase58(otherAcct).decodedAddress);

    const uriEv = parseCis2Event(
        Buffer.concat([
            Buffer.from([0xf1]),
            encodeTokenId('1315'),
            Buffer.from([1]),
            strU32('https://example.com/a.json'),
            Buffer.from([1]),
            Buffer.alloc(32, 0x11),
            u64le(1700000000000n),
        ]).toString('hex'),
    );
    assert.equal(uriEv.type, 'URIUpdated');
    assert.equal(uriEv.agentUri, 'https://example.com/a.json');

    const extRefEv = parseCis2Event(
        Buffer.concat([Buffer.from([0xf2]), encodeTokenId('1315'), Buffer.from([0]), u64le(1700000000000n)]).toString('hex'),
    );
    assert.equal(extRefEv.type, 'ExternalReferenceSet');
    assert.equal(extRefEv.externalReference, null);

    const revEv = parseCis2Event(
        Buffer.concat([Buffer.from([0xf4]), encodeTokenId('1315'), ownerBytes, Buffer.from([1]), strU32('done'), u64le(1700000000000n)]).toString('hex'),
    );
    assert.equal(revEv.type, 'Revoked');
    assert.equal(revEv.reason, 'done');

    const adminEv = parseCis2Event(
        Buffer.concat([Buffer.from([0xf7]), Buffer.from([1]), ownerBytes, Buffer.from([1]), otherBytes, u64le(1700000000000n)]).toString('hex'),
    );
    assert.equal(adminEv.type, 'AdminTransferred');
    assert.equal(adminEv.previous, WATCHER_OWNER);
    assert.equal(adminEv.next, otherAcct);

    const extRegEv = parseCis2Event(
        Buffer.concat([Buffer.from([0xf8]), u64le(10n), u64le(0n), u64le(11n), u64le(0n)]).toString('hex'),
    );
    assert.equal(extRegEv.type, 'ExternalRegistriesUpdated');
    assert.deepEqual(extRegEv.newCis8Contract, { index: 11, subindex: 0 });

    const urlBuf = Buffer.from('https://example.com/meta', 'utf8');
    const tokMetaEv = parseCis2Event(
        Buffer.concat([Buffer.from([0xfb]), encodeTokenId('1315'), u16le(urlBuf.length), urlBuf, Buffer.from([0])]).toString('hex'),
    );
    assert.equal(tokMetaEv.type, 'TokenMetadata');
    assert.equal(tokMetaEv.url, 'https://example.com/meta');
    assert.equal(tokMetaEv.hashHex, null);

    const burnEv = parseCis2Event(
        Buffer.concat([Buffer.from([0xfd]), encodeTokenId('1315'), Buffer.from([1, 0]), ownerBytes]).toString('hex'),
    );
    assert.equal(burnEv.type, 'Burn');
    assert.equal(burnEv.owner, WATCHER_OWNER);

    const xferHex = Buffer.concat([
        Buffer.from([0xff]),
        encodeTokenId('1315'),
        Buffer.from([1, 0]),
        ownerBytes,
        Buffer.from([0]),
        otherBytes,
    ]).toString('hex');
    assert.deepEqual(parseCis2Event(xferHex), {
        type: 'Transfer',
        tokenId: '1315',
        tokenIdHex: '2305000000000000',
        amount: 1n,
        from: WATCHER_OWNER,
        to: otherAcct,
    });

    const addOpHex = Buffer.concat([Buffer.from([0xfc, 1, 0]), ownerBytes, Buffer.from([0]), otherBytes]).toString('hex');
    assert.deepEqual(parseCis2Event(addOpHex), {
        type: 'UpdateOperator',
        update: 'Add',
        owner: WATCHER_OWNER,
        operator: otherAcct,
    });

    assert.deepEqual(parseCis2Event(WATCHER_METADATA_SET_HEX), {
        type: 'MetadataSet',
        rawHex: WATCHER_METADATA_SET_HEX,
    });

    assert.deepEqual(parseCis2Event('ea0102'), {
        type: 'Unknown',
        tag: 0xea,
        rawHex: 'ea0102',
    });

    assert.throws(() => parseCis2Event('fc0200' + ownerBytes.toString('hex') + '00' + otherBytes.toString('hex')), /update tag/);
    assert.throws(() => parseCis2Event(WATCHER_MINT_HEX + '00'), /trailing/);
    assert.throws(() => parseCis2Event(WATCHER_MINT_HEX.slice(0, -2)), /truncated/);
    assert.throws(() => parseCis2Event(''), /empty/);
});

test('verifyAgentCardBytes validates Watcher card and rejects tampered hash or extension fields', () => {
    const cardBytes = fs.readFileSync(new URL('../agent-card/watcher.json', import.meta.url));
    const verified = verifyAgentCardBytes(cardBytes, {
        badge: WATCHER_BADGE,
        ownerAccount: WATCHER_OWNER,
        metadataHashHex: WATCHER_CARD_HASH,
        registry: REGISTRY,
    });
    assert.equal(verified.sha256, WATCHER_CARD_HASH);
    assert.equal(verified.card.name, 'Watcher');

    assert.throws(
        () =>
            verifyAgentCardBytes(Buffer.from(cardBytes.toString('utf8').replace('Watcher', 'WatcheR')), {
                badge: WATCHER_BADGE,
                ownerAccount: WATCHER_OWNER,
                metadataHashHex: WATCHER_CARD_HASH,
            }),
        /SHA-256 mismatch/,
    );

    const mutateCard = (fn) => {
        const obj = JSON.parse(cardBytes.toString('utf8'));
        fn(obj);
        const bytes = Buffer.from(JSON.stringify(obj), 'utf8');
        const metadataHashHex = crypto.createHash('sha256').update(bytes).digest('hex');
        return () => verifyAgentCardBytes(bytes, { badge: WATCHER_BADGE, ownerAccount: WATCHER_OWNER, metadataHashHex });
    };

    assert.throws(mutateCard((c) => { c.capabilities.extensions[0].params.tokenAddress += 'x'; }), /tokenAddress mismatch/);
    assert.throws(mutateCard((c) => { c.capabilities.extensions[0].params.owner.account += 'x'; }), /owner\.account mismatch/);
    assert.throws(mutateCard((c) => { c.capabilities.extensions[0].params.contracts.cis8004 = 'ccd:4221332d34e1694168c2a0c0b3fd0f27:99999.0'; }), /contracts\.cis8004 mismatch/);
    assert.throws(mutateCard((c) => { c.capabilities.extensions = []; }), /exactly one/);
});

test('isDisallowedIp blocks loopback, private, link-local, CGNAT, ULA, and IPv4-mapped IPv6 addresses', () => {
    for (const bad of [
        '127.0.0.1',
        '127.255.0.1',
        '10.0.0.1',
        '172.16.0.1',
        '172.31.255.254',
        '192.168.1.1',
        '169.254.169.254',
        '100.64.0.1',
        '0.0.0.0',
        '224.0.0.1',
        '::',
        '::1',
        '::ffff:127.0.0.1',
        '::ffff:169.254.169.254',
        '::ffff:7f00:1',
        'fe80::1',
        'fe80::1%eth0',
        'fc00::1',
        'fd12:3456:789a::1',
        'ff02::1',
        '64:ff9b::10.0.0.1',
    ]) {
        assert.equal(isDisallowedIp(bad), true, `expected ${bad} to be disallowed`);
    }
    for (const good of ['93.184.216.34', '140.82.121.4', '2606:4700:4700::1111', '2001:4860:4860::8888']) {
        assert.equal(isDisallowedIp(good), false, `expected ${good} to be allowed`);
    }
});

test('fetchAgentCard enforces https, SSRF IP/DNS guards, no redirects, timeout, and maxBytes', async () => {
    await assert.rejects(() => fetchAgentCard('http://example.com/card.json'), /non-HTTPS/);
    await assert.rejects(() => fetchAgentCard('https://user:pass@example.com/card.json'), /credentials/);
    await assert.rejects(() => fetchAgentCard('not a url'), /invalid agentUri/);

    // IP-literal SSRF blocks before socket connect.
    for (const badUri of [
        'https://127.0.0.1/card.json',
        'https://10.0.0.1/card.json',
        'https://169.254.169.254/latest/meta-data/',
        'https://[::1]/card.json',
        'https://[::ffff:127.0.0.1]/card.json',
        'https://[fe80::1]/card.json',
    ]) {
        await assert.rejects(
            () => fetchAgentCard(badUri, { requestFn: () => { throw new Error('must not connect'); } }),
            /private or non-public IP/,
            badUri,
        );
    }

    // DNS resolution SSRF guard in both single-IP and { all: true } modes.
    await assert.rejects(
        () =>
            fetchAgentCard('https://rebind.example/card.json', {
                lookupFn: (_h, _o, cb) => cb(null, '127.0.0.1', 4),
                requestFn: makeMockRequestFn({ chunks: ['{}'], lookupOpts: {} }),
            }),
        /private or non-public IP/,
    );
    await assert.rejects(
        () =>
            fetchAgentCard('https://rebind.example/card.json', {
                lookupFn: (_h, _o, cb) =>
                    cb(null, [
                        { address: '93.184.216.34', family: 4 },
                        { address: '::ffff:10.0.0.1', family: 6 },
                    ]),
                requestFn: makeMockRequestFn({ chunks: ['{}'], lookupOpts: { all: true } }),
            }),
        /private or non-public IP/,
    );

    // allowPrivate: true permits loopback when explicitly opted in.
    const privateOk = await fetchAgentCard('https://127.0.0.1/card.json', {
        allowPrivate: true,
        lookupFn: (_h, _o, cb) => cb(null, [{ address: '127.0.0.1', family: 4 }]),
        requestFn: makeMockRequestFn({ chunks: ['{"private":true}'] }),
    });
    assert.equal(privateOk.toString('utf8'), '{"private":true}');

    const publicLookup = (_h, opts, cb) =>
        opts?.all ? cb(null, [{ address: '93.184.216.34', family: 4 }]) : cb(null, '93.184.216.34', 4);

    // Redirect rejection.
    await assert.rejects(
        () =>
            fetchAgentCard('https://example.com/card.json', {
                lookupFn: publicLookup,
                requestFn: makeMockRequestFn({ statusCode: 302, headers: { location: 'https://other.example/' } }),
            }),
        /redirect/,
    );

    // Content-Length cap rejection.
    await assert.rejects(
        () =>
            fetchAgentCard('https://example.com/card.json', {
                maxBytes: 1000,
                lookupFn: publicLookup,
                requestFn: makeMockRequestFn({ headers: { 'content-length': '2048' } }),
            }),
        /exceeds 1000 byte limit/,
    );

    // Streaming chunk cap rejection without Content-Length.
    await assert.rejects(
        () =>
            fetchAgentCard('https://example.com/card.json', {
                maxBytes: 1000,
                lookupFn: publicLookup,
                requestFn: makeMockRequestFn({ chunks: [Buffer.alloc(600), Buffer.alloc(600)] }),
            }),
        /exceeds 1000 byte limit/,
    );

    // Timeout rejection.
    await assert.rejects(
        () =>
            fetchAgentCard('https://example.com/card.json', {
                timeoutMs: 25,
                lookupFn: publicLookup,
                requestFn: makeMockRequestFn({ delayMs: 200 }),
            }),
        /timed out/,
    );

    // Happy path under cap.
    const ok = await fetchAgentCard('https://example.com/card.json', {
        maxBytes: 1000,
        lookupFn: publicLookup,
        requestFn: makeMockRequestFn({ chunks: ['{"ok":', 'true}'] }),
    });
    assert.equal(ok.toString('utf8'), '{"ok":true}');

    // Rejected responses (302, 404, huge Content-Length) with unclosed body must destroy res+req immediately without hanging.
    for (const [label, opts] of [
        ['302 redirect', { statusCode: 302, headers: { location: 'https://other.example/' }, re: /redirect/ }],
        ['404 status', { statusCode: 404, headers: {}, re: /HTTP 404/ }],
        ['oversized Content-Length', { statusCode: 200, headers: { 'content-length': '5000' }, re: /exceeds 1000 byte limit/ }],
    ]) {
        let resDestroyed = false;
        let reqDestroyed = false;
        const unclosedRequestFn = (_url, reqOpts, onRes) => {
            const req = new EventEmitter();
            req.destroy = () => { reqDestroyed = true; };
            req.end = () => {
                reqOpts.lookup('card.example', { all: true }, () => {
                    const res = new EventEmitter();
                    res.statusCode = opts.statusCode;
                    res.headers = opts.headers;
                    res.resume = () => { throw new Error('must not drain unclosed rejected body'); };
                    res.destroy = () => { resDestroyed = true; };
                    onRes(res);
                    // Intentionally never emit 'end' or 'close' on res.
                });
            };
            return req;
        };
        await assert.rejects(
            () => fetchAgentCard('https://example.com/card.json', { maxBytes: 1000, timeoutMs: 5000, lookupFn: publicLookup, requestFn: unclosedRequestFn }),
            opts.re,
            label,
        );
        assert.equal(resDestroyed, true, `${label}: res.destroy() must be called`);
        assert.equal(reqDestroyed, true, `${label}: req.destroy() must be called`);
    }
});

test('decodeGetAdmin strictly decodes Option<AccountAddress>', () => {
    assert.equal(decodeGetAdmin(Buffer.from([0])), null);
    const adminBytes = Buffer.from(AccountAddress.fromBase58(WATCHER_OWNER).decodedAddress);
    assert.equal(decodeGetAdmin(Buffer.concat([Buffer.from([1]), adminBytes])), WATCHER_OWNER);
    assert.throws(() => decodeGetAdmin(Buffer.from([0, 0])), /trailing/);
    assert.throws(() => decodeGetAdmin(Buffer.concat([Buffer.from([1]), adminBytes.subarray(0, 16)])), /truncated/);
    assert.throws(() => decodeGetAdmin(Buffer.from([2])), /Option tag/);
});

// Test-only self-signed certificate for localhost HTTPS tests; not a production credential.
const TEST_KEY_PEM = [
    '-----BEGIN PRIVATE KEY-----',
    'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgF56XJ48FMRYsOHWC',
    'NqDoL0loPvvngib80k1KXAEJQWOhRANCAASq8DjbtP/qJrkzCqiwKBXnr2GAhdDU',
    'HaiT68RNTyJmeg+I/lovawjxEKKpd0r3H9/kRWZAMfXMcpxAmfn4NNNM',
    '-----END PRIVATE KEY-----',
].join('\n');

// Test-only self-signed certificate for localhost HTTPS tests; not a production credential.
const TEST_CERT_PEM = [
    '-----BEGIN CERTIFICATE-----',
    'MIIBbzCCARWgAwIBAgIUXJzlUtgO20ilH++PuBHv7koafY0wCgYIKoZIzj0EAwIw',
    'FDESMBAGA1UEAwwJMTI3LjAuMC4xMCAXDTI2MTEyMTE0MzYyMVoYDzIxMjYxMDI4',
    'MTQzNjIxWjAUMRIwEAYDVQQDDAkxMjcuMC4wLjEwWTATBgcqhkjOPQIBBggqhkjO',
    'PQMBBwNCAASq8DjbtP/qJrkzCqiwKBXnr2GAhdDUHaiT68RNTyJmeg+I/lovawjx',
    'EKKpd0r3H9/kRWZAMfXMcpxAmfn4NNNMo0MwQTAdBgNVHQ4EFgQUBdYptiuVtIxf',
    '4oc8EqRMIRb/eK8wDwYDVR0TAQH/BAUwAwEB/zAPBgNVHREECDAGhwR/AAABMAoG',
    'CCqGSM49BAMCA0gAMEUCIBOhPq01U+jAOVCq+oRdlAxuQkMymwVNS3rz8G6v9N66',
    'AiEAi6IDMAT7eEHRhRJq2ApJSuVK7BzY9SH+QdqlMoaJURg=',
    '-----END CERTIFICATE-----',
].join('\n');

test('fetchAgentCard decodes gzip/br/deflate via real node:https and rejects zip bombs and unsupported encodings', async () => {
    const key = Buffer.from(TEST_KEY_PEM);
    const cert = Buffer.from(TEST_CERT_PEM);

    const cardBytes = fs.readFileSync(new URL('../agent-card/watcher.json', import.meta.url));
    const bombBytes = Buffer.alloc(4096, 0x41); // compresses to <100 bytes, expands >1000 bytes

    let sawAcceptEncoding = null;
    const server = https.createServer({ key, cert }, (req, res) => {
        sawAcceptEncoding = req.headers['accept-encoding'];
        if (req.url === '/gzip') {
            res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'gzip' });
            res.end(zlib.gzipSync(cardBytes));
        } else if (req.url === '/br') {
            res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'br' });
            res.end(zlib.brotliCompressSync(cardBytes));
        } else if (req.url === '/deflate') {
            res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'deflate' });
            res.end(zlib.deflateSync(cardBytes));
        } else if (req.url === '/bomb') {
            const gz = zlib.gzipSync(bombBytes);
            res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'gzip', 'content-length': String(gz.length) });
            res.end(gz);
        } else if (req.url === '/zstd') {
            res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'zstd' });
            res.end('raw');
        } else {
            res.writeHead(404);
            res.end();
        }
    });

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();
    const base = `https://127.0.0.1:${port}`;
    try {
        const gzOut = await fetchAgentCard(`${base}/gzip`, { allowPrivate: true, ca: cert });
        assert.deepEqual(gzOut, cardBytes);
        assert.equal(crypto.createHash('sha256').update(gzOut).digest('hex'), WATCHER_CARD_HASH);
        assert.match(sawAcceptEncoding, /gzip/);
        assert.match(sawAcceptEncoding, /br/);
        assert.match(sawAcceptEncoding, /deflate/);

        const brOut = await fetchAgentCard(`${base}/br`, { allowPrivate: true, ca: cert });
        assert.deepEqual(brOut, cardBytes);
        assert.equal(crypto.createHash('sha256').update(brOut).digest('hex'), WATCHER_CARD_HASH);

        const defOut = await fetchAgentCard(`${base}/deflate`, { allowPrivate: true, ca: cert });
        assert.deepEqual(defOut, cardBytes);

        // Zip bomb: compressed < 100B, decompressed 4096B > maxBytes=1000 must fail closed!
        await assert.rejects(
            () => fetchAgentCard(`${base}/bomb`, { allowPrivate: true, ca: cert, maxBytes: 1000 }),
            /exceeds 1000 byte limit/,
        );

        await assert.rejects(
            () => fetchAgentCard(`${base}/zstd`, { allowPrivate: true, ca: cert }),
            /unsupported Content-Encoding: zstd/,
        );
    } finally {
        server.closeAllConnections?.();
        await new Promise((resolve) => server.close(resolve));
    }
});
