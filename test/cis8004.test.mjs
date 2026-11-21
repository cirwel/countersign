import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { test } from 'node:test';
import { AccountAddress, ContractAddress, tokenAddressToBase58 } from '@concordium/web-sdk';
import {
    decodeAgentOf,
    decodeBadge,
    decodeGetMetadata,
    decodeGetMetadataUtf8,
    encodeBadge,
    encodeGetMetadataParam,
    encodeSetMetadataParam,
    encodeTokenId,
    fetchAgentCard,
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

// Captured verbatim from Watcher's registration tx and latest anchor pointer update.
const WATCHER_MINT_HEX = 'fe0823050000000000000100bb2793c76eea40efa19981902c47b71d607be55f0581581bfff18e65aeec2a62';
const WATCHER_METADATA_SET_HEX =
    'f308230500000000000012000000636f756e7465727369676e2e616e63686f72' +
    '4000000065316138636165346337656162323363653666313833363234356566663338623331393235373937326337373735356161353430333162306262343562396638' +
    '0f2e96faa1010000';

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

test('badge encode/decode round-trips Watcher and rejects bad token_id encodings', () => {
    assert.equal(encodeBadge('1315'), WATCHER_BADGE);
    assert.deepEqual(decodeBadge(WATCHER_BADGE), {
        contract: { index: 12802, subindex: 0 },
        tokenId: '1315',
    });

    const other = encodeBadge('42', { index: 99, subindex: 1 });
    assert.deepEqual(decodeBadge(other), { contract: { index: 99, subindex: 1 }, tokenId: '42' });

    // Non-8-byte token ID inside a valid CIS-2 Base58Check address must be rejected.
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

    // Construct a minimal Revoked agentOf struct.
    const ownerBytes = Buffer.from(AccountAddress.fromBase58(WATCHER_OWNER).decodedAddress);
    const reason = Buffer.from('compromised key', 'utf8');
    const revokedBuf = Buffer.concat([
        Buffer.from([1]),
        encodeTokenId('7'),
        ownerBytes,
        Buffer.from([0]), // agentUri None
        Buffer.from([0]), // metadataHash None
        Buffer.from([0]), // externalReference None
        Buffer.from([0]), // agentWallet None
        Buffer.from([1]), // status = Revoked
        u64le(1700000000000n),
        Buffer.from([1]),
        u64le(1700000005000n),
        Buffer.from([1]),
        u32le(reason.length),
        reason,
        u32le(0), // onChainMetadata empty
    ]);
    const rev = decodeAgentOf(revokedBuf);
    assert.equal(rev.status, 'Revoked');
    assert.equal(rev.revokedAtMs, 1700000005000);
    assert.equal(rev.revocationReason, 'compromised key');

    // Malformed variants.
    const watcherBuf = Buffer.from(WATCHER_AGENT_OF_HEX, 'hex');
    assert.throws(() => decodeAgentOf(Buffer.concat([watcherBuf, Buffer.from([0])])), /trailing/);
    assert.throws(() => decodeAgentOf(watcherBuf.subarray(0, -1)), /truncated/);
    assert.throws(() => decodeAgentOf(Buffer.from([0, 0])), /trailing/);
    assert.throws(() => decodeAgentOf(Buffer.from([2])), /Option tag/);
    const badStatus = Buffer.from(revokedBuf);
    badStatus[1 + 9 + 32 + 4] = 9;
    assert.throws(() => decodeAgentOf(badStatus), /status tag/);
    const badUtf8Reason = Buffer.concat([
        Buffer.from([1]),
        encodeTokenId('7'),
        ownerBytes,
        Buffer.from([0, 0, 0, 0, 0]),
        u64le(1000n),
        Buffer.from([0]),
        Buffer.from([1]),
        u32le(2),
        Buffer.from([0xff, 0xfe]),
        u32le(0),
    ]);
    assert.throws(() => decodeAgentOf(badUtf8Reason));
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

    // Non-0xf3 or 0xf3 for a different tokenId must return null.
    assert.equal(parseMetadataSetEvent(WATCHER_MINT_HEX, '1315'), null);
    assert.equal(parseMetadataSetEvent(WATCHER_METADATA_SET_HEX, '1316'), null);
    assert.equal(parseMetadataSetEvent('', '1315'), null);

    // Targeting expectedTokenId and malformed must throw.
    assert.throws(() => parseMetadataSetEvent(WATCHER_METADATA_SET_HEX + '00', '1315'), /trailing/);
    assert.throws(() => parseMetadataSetEvent(WATCHER_METADATA_SET_HEX.slice(0, -2), '1315'), /truncated/);
    assert.throws(() => parseMetadataSetEvent('f308', '1315'), /truncated/);
    assert.throws(() => parseMetadataSetEvent(WATCHER_METADATA_SET_HEX.toUpperCase(), '1315'), /lowercase hex/);
    assert.throws(() => parseMetadataSetEvent('f30', '1315'), /lowercase hex/);

    // Invalid UTF-8 key on matching tokenId must throw.
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

test('parseCis2Event decodes Mint, Transfer, UpdateOperator, MetadataSet, Burn, Other and rejects malformed', () => {
    const mint = parseCis2Event(WATCHER_MINT_HEX);
    assert.deepEqual(mint, {
        type: 'Mint',
        tokenId: '1315',
        tokenIdHex: '2305000000000000',
        amount: 1n,
        owner: WATCHER_OWNER,
    });

    const ownerBytes = Buffer.from(AccountAddress.fromBase58(WATCHER_OWNER).decodedAddress);
    const otherAcct = '3dt3UMPzRASZndjmKpSWgCP2HhmoxZrgs8FDPtZjNHZzj13hhB';
    const otherBytes = Buffer.from(AccountAddress.fromBase58(otherAcct).decodedAddress);

    const xferHex = Buffer.concat([
        Buffer.from([0xff]),
        encodeTokenId('1315'),
        Buffer.from([1]), // uleb128 1
        Buffer.from([0]),
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

    // Transfer to Contract address
    const xferContractHex = Buffer.concat([
        Buffer.from([0xff]),
        encodeTokenId('1315'),
        Buffer.from([1]),
        Buffer.from([0]),
        ownerBytes,
        Buffer.from([1]),
        u64le(900n),
        u64le(2n),
    ]).toString('hex');
    assert.deepEqual(parseCis2Event(xferContractHex).to, { index: 900, subindex: 2 });

    const addOpHex = Buffer.concat([
        Buffer.from([0xfc, 1]),
        Buffer.from([0]),
        ownerBytes,
        Buffer.from([0]),
        otherBytes,
    ]).toString('hex');
    assert.deepEqual(parseCis2Event(addOpHex), {
        type: 'UpdateOperator',
        update: 'Add',
        owner: WATCHER_OWNER,
        operator: otherAcct,
    });

    const remOpHex = Buffer.concat([
        Buffer.from([0xfc, 0]),
        Buffer.from([0]),
        ownerBytes,
        Buffer.from([0]),
        otherBytes,
    ]).toString('hex');
    assert.equal(parseCis2Event(remOpHex).update, 'Remove');

    assert.deepEqual(parseCis2Event(WATCHER_METADATA_SET_HEX), {
        type: 'MetadataSet',
        rawHex: WATCHER_METADATA_SET_HEX,
    });
    assert.equal(parseCis2Event('f00102').type, 'Other');

    assert.throws(() => parseCis2Event('fc02' + '00' + ownerBytes.toString('hex') + '00' + otherBytes.toString('hex')), /update tag/);
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

    // Hash mismatch
    assert.throws(
        () => verifyAgentCardBytes(Buffer.from(cardBytes.toString('utf8').replace('Watcher', 'WatcheR')), {
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

test('fetchAgentCard enforces https-only, no redirects, timeout, and maxBytes streaming cap', async () => {
    await assert.rejects(() => fetchAgentCard('http://example.com/card.json'), /non-HTTPS/);
    await assert.rejects(() => fetchAgentCard('not a url'), /invalid agentUri/);

    const origFetch = globalThis.fetch;
    try {
        // Streaming cap test (even without Content-Length header).
        globalThis.fetch = async () => new Response(new ReadableStream({
            start(controller) {
                controller.enqueue(new Uint8Array(600));
                controller.enqueue(new Uint8Array(600));
                controller.close();
            },
        }), { status: 200 });
        await assert.rejects(() => fetchAgentCard('https://example.com/card.json', { maxBytes: 1000 }), /exceeds 1000 byte limit/);

        // Happy path under cap.
        globalThis.fetch = async (_url, opts) => {
            assert.equal(opts.redirect, 'error');
            return new Response(Buffer.from('{"ok":true}'), { status: 200 });
        };
        const out = await fetchAgentCard('https://example.com/card.json', { maxBytes: 1000 });
        assert.equal(out.toString('utf8'), '{"ok":true}');

        // Abort timeout test.
        globalThis.fetch = async (_url, opts) => new Promise((_, reject) => {
            opts.signal.addEventListener('abort', () => reject(opts.signal.reason));
        });
        await assert.rejects(() => fetchAgentCard('https://example.com/card.json', { timeoutMs: 25 }), /timed out/);
    } finally {
        globalThis.fetch = origFetch;
    }
});
