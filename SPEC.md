# countersign.trail.v1

## Trail file

UTF-8 text, one JSON value per line, each line in canonical form, terminated by `\n`.

**Line 1, the header:**

| Field | Meaning |
|---|---|
| `schema` | `"countersign.trail.v1"` |
| `source` | free text naming where the records came from |
| `agent_uuid` | the agent's identifier in the source system |
| `token_id` | the agent's CIS-8004 token id, as a decimal string |
| `registry` | `{ "network": "testnet", "index": 12802, "subindex": 0 }` |

**Lines 2..n+1, the records,** in sequence order starting at 1. Each record has exactly these fields:

| Field | Meaning |
|---|---|
| `seq` | integer, starting at 1, no gaps |
| `checkpoint_id` | the source system's identifier for this record |
| `prev_checkpoint_id` | `checkpoint_id` of record `seq - 1`, or `null` for record 1 |
| `recorded_at` | UTC time, `YYYY-MM-DDTHH:MM:SS.ffffffZ` |
| `report_excerpt` | the agent's check-in text as stored |
| `provenance` | object describing how the record was produced |

A verifier rejects a trail with a missing or extra field, a gap or repeat in `seq`, or a `prev_checkpoint_id` that does not name the preceding record.

## Canonical JSON

- Object keys sorted by Unicode code point.
- No whitespace between tokens.
- Strings escaped as ECMAScript `JSON.stringify` escapes them.
- Numbers must be integers within ±(2^53 − 1), written in decimal. Any other number is an error.

## Commitment

```
h_0 = SHA-256( "countersign.trail.v1" || 0x0A || canonical(header) )
h_i = SHA-256( h_{i-1} || SHA-256( canonical(record_i) ) )
```

The commitment to records 1..n is `h_n`.

## Anchor

A Concordium register-data transaction whose data is exactly 85 bytes:

| Offset | Length | Content |
|---|---|---|
| 0 | 4 | ASCII `CSGN` |
| 4 | 1 | version, `0x01` |
| 5 | 8 | token id, unsigned big-endian |
| 13 | 8 | last sequence number covered, unsigned big-endian |
| 21 | 32 | `h_n` |
| 53 | 32 | hash of the previous anchor transaction, or 32 zero bytes for the first anchor |

After each anchor, the registry entry's metadata key `countersign.anchor` is set to the hash of that anchor transaction, written as 64 lowercase hexadecimal characters of UTF-8 text (the registry rejects metadata values that are not valid text). The entry's metadata key `unitares.agent_uuid` holds the agent UUID as UTF-8 text.

Optionally, the entry owner may authorize a separate witness account via metadata key `countersign.witness`:

- `countersign.witness` holds a canonical Base58Check Concordium account address that is not an alias of `owner_account`, or the empty string `""` to clear the witness authorization and return anchoring authority to `owner_account`.
- Setting or clearing `countersign.witness` MUST occur via a `CIS-8004.setMetadata` transaction (`MetadataSet` event `0xf3`) emitted by `owner_account`. Any `countersign.witness` value injected via registration `initial_metadata` without a `MetadataSet` event, any malformed or non-canonical Base58Check address, or any value equal (canonically) to `owner_account` fails closed.

## Witnessing & Protocol 10 Fee-Sponsored Pointer Updates

When a separate witness service is active:

1. **x402 v2 payment binding:** Before writing an anchor, the witness verifies the agent's active status, Agent Card integrity, unbroken `MetadataSet` history, `countersign.witness` authorization, and monotonic `(prevAnchorTx, toSeq)` alignment. It responds `402 Payment Required` with a `PAYMENT-REQUIRED` header (`x402Version: 2`, `scheme: "exact"`, CAIP-2 network `ccd:4221332d34e1694168c2a0c0b3fd0f27`) binding the payment memo to:
   ```
   memo = SHA-256("countersign.x402.v1\n" || tokenId || "\n" || toSeq || "\n" || commitment || "\n" || (prevAnchorTx ?? "genesis"))
   ```
2. **Witness-signed anchor:** After verifying payment (direct finalized Concordium `transferWithMemo` or SSRF-hardened x402 facilitator `/verify` + `/settle`) and atomically claiming the payment ID in `PaymentLedger` (`claimed -> broadcasted -> committed`, never releasing `broadcasted` or `committed` entries), the witness submits the 85-byte `CSGN` `registerData` transaction signed by the witness account.
3. **Protocol 10 fee-sponsored `CIS-8004.setMetadata`:** Because `CIS-8004.setMetadata` requires `owner_account` as the contract invoker (`ctx.sender()`), the owner signs a Protocol 10 V1 sponsorable transaction (`version: 1`, `header.sponsor = witnessAccount`, zero attached CCD, target `<12802,0>`, entrypoint `CIS-8004.setMetadata`, exact parameter bytes for `(tokenId, "countersign.anchor", anchorTxHash)`, bounded execution energy and expiry) and submits it to `/v1/sponsor-pointer`. The witness verifies all transaction invariants, verifies the owner's Ed25519 signature against on-chain `AccountInfo` credentials, dry-runs `invokeContract`, co-signs as sponsor, finalizes, and submits the V1 transaction so the owner account needs zero CCD for transaction fees.

## Verification

Given a badge (a CIS-2 Base58Check token address) and a trail file, a verifier must connect directly to a Concordium testnet node (making zero calls to any hosted registry API or indexer) and:

1. decode the badge locally, enforce an 8-byte little-endian `u64` token id, and accept only the pinned testnet registry instance (`<12802,0>`) and testnet genesis (`4221332d34e1694168c2a0c0b3fd0f273809612cb13d000d5c2e00e85f50f796`);
2. pin a single finalized tip block `(tipBlockHash, tipBlockHeight)` and read `CIS-8004.agentOf` and `CIS-8004.getMetadata` directly via `invokeContract` at `tipBlockHash`;
3. confirm the entry is registered (`Some`) and `Active`, fetch the Agent Card over HTTPS (no redirects, pre-connect public-IP SSRF check, 1 MiB streaming cap) or read a local `--card` file, confirm its SHA-256 equals the on-chain `metadata_hash`, and validate the `concordium-badge/v1` extension (`tokenAddress`, `owner.account`, `contracts.cis8004`);
4. confirm the trail header's `token_id` and `registry` match the badge, and that `unitares.agent_uuid` on chain equals the header's `agent_uuid` (using BOM-preserving strict UTF-8);
5. reconstruct the complete `MetadataSet` history directly from finalized blocks between registration and `tipBlockHeight` (fail-closed continuity):
   - locate the registration block from `agent.registeredAtMs` and confirm a unique `Mint` (`0xfe`) event for `token_id` whose `owner` matches the current `owner_account`;
   - confirm the contract's `sourceModule.moduleRef` at both registration and `tipBlockHash` equals the pinned module reference `0e57473715d1c2a364fa626b8783688db32b7fac9d0e2fc97043da91e1a7d3eb`, and confirm `CIS-8004.getAdmin` is consistent (either `None` at both heights or the same account at both heights);
   - confirm zero pre-existing CIS-2 operators for `owner_account` at the registration block via contract state lookup (`0500000000000000 || owner_account_bytes`);
   - confirm neither `owner_account` nor the registry admin exceeds `maxOwnerTxs` / `maxAdminTxs` (`2000`), exhaustively locate every block in `(regHeight, tipBlockHeight]` where either `owner_account`'s or the admin's `accountNonce` increased, stream `getBlockTransactionEvents` in ascending height order (plus any post-`Mint` events in `regHeight` and any `Upgraded` event in `regHeight`), fail closed on any `Upgraded`, `AdminTransferred`, `Transfer`, `Burn`, `UpdateOperator(Add)`, non-owner `MetadataSet` sender, or unknown `<12802,0>` contract event tag, and collect every `MetadataSet` (`0xf3`) event targeting `token_id`;
6. replay `countersign.witness` events chronologically from the collected `MetadataSet` events (validating canonical non-owner Base58Check or `""` to clear) and confirm the resulting active witness matches on-chain `CIS-8004.getMetadata(token_id, "countersign.witness")` at `tipBlockHash` (where a cleared key reads as `""`);
7. list every `countersign.anchor` pointer update chronologically alongside the `activeWitness` that held authority at the time of that `MetadataSet` event (`authorizedWitness`), and confirm the last pointer equals the current value at `tipBlockHash`;
8. confirm every listed anchor transaction is finalized at `blockHeight <= tipBlockHeight`, was sent by `authorizedWitness ?? owner_account` (canonically including account aliases), and names the same token id (and if `--require-witness` or `--witness <account>` is specified, confirm an active witness is set and countersigned the latest anchor);
9. confirm the anchors form one chain: the first has no previous anchor, each later one names the anchor listed immediately before it, and the last sequence number covered strictly increases;
10. recompute `h` from the trail file and confirm it equals the anchored value at every anchor's sequence number.

Records after the latest anchor's sequence number are outside the commitment.

Notes:

- An anchor counts only once a `MetadataSet` event names it. The deployed registry does not emit that event for metadata supplied at registration, so a pointer set that way is not an anchor: the verifier fails while it is current and ignores it afterwards. A register-data transaction that the entry never pointed at is likewise not an anchor.
- Anchors and `MetadataSet` updates must come from the entry's current owner, and uninterrupted exclusive ownership since `Mint` is enforced: any `Transfer`, `Burn`, or `Mint` to a non-owner fails closed.
- A verifier reports the highest sequence number covered. A trail may carry newer records; they are outside the commitment until the next anchor.
- The trail file and on-chain UTF-8 metadata must be valid UTF-8, decoded with BOM preservation (leading `U+FEFF` is never silently stripped), and every trail line must equal the canonical serialization of the value it parses to.

## Test vector

Header:

```
{"agent_uuid":"00000000-0000-4000-8000-000000000001","registry":{"index":12802,"network":"testnet","subindex":0},"schema":"countersign.trail.v1","source":"test","token_id":"7"}
```

The unit tests in `test/trail.test.mjs` build a three-record trail on this header and check the properties above.
