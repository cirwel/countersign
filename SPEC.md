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

## Verification

Given a badge (a CIS-8004 token address) and a trail file, a verifier must:

1. accept only the registry instance it has pinned;
2. confirm the entry is registered and active and that its Agent Card matches the on-chain hash;
3. confirm the trail header's `token_id` and `registry` match the badge, and that `unitares.agent_uuid` on chain equals the header's `agent_uuid`;
4. list every value `countersign.anchor` has held, in order, from the registry's `MetadataSet` events, and confirm the last one equals the current value;
5. confirm every listed anchor transaction is finalized, was sent by the entry's current owner account, and names the same token id;
6. confirm the anchors form one chain: the first has no previous anchor, each later one names the anchor listed immediately before it, and the last sequence number covered strictly increases;
7. recompute `h` from the trail file and confirm it equals the anchored value at every anchor's sequence number.

Records after the latest anchor's sequence number are outside the commitment.

Notes:

- An anchor counts only once a `MetadataSet` event names it. The deployed registry does not emit that event for metadata supplied at registration, so a pointer set that way is not an anchor: the verifier fails while it is current and ignores it afterwards. A register-data transaction that the entry never pointed at is likewise not an anchor.
- Anchors must come from the entry's current owner. If the token is transferred, anchors sent by the previous owner stop verifying. That is deliberate: the verifier does not reconstruct ownership history.
- A verifier reports the highest sequence number covered. A trail may carry newer records; they are outside the commitment until the next anchor.
- The trail file must be valid UTF-8, and every line must equal the canonical serialization of the value it parses to.

## Test vector

Header:

```
{"agent_uuid":"00000000-0000-4000-8000-000000000001","registry":{"index":12802,"network":"testnet","subindex":0},"schema":"countersign.trail.v1","source":"test","token_id":"7"}
```

The unit tests in `test/trail.test.mjs` build a three-record trail on this header and check the properties above.
