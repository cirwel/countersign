# Countersign

Countersign ties an AI agent's Concordium Agent Registry entry to the record of what that agent did.

The Verified by Concordium badge tells you an agent is registered, active, and serving the Agent Card that was committed on chain. It says nothing about the agent's history. Countersign adds that: it writes a hash-chained commitment of the agent's recorded check-ins to Concordium, points the registry entry at it, and gives anyone a command that checks a copy of the record against the chain.

Built for the Concordium Trusted Agents Hackathon. **Testnet only.** There is no mainnet configuration anywhere in this repository, and the tool refuses to talk to a node whose genesis block is not testnet's.

## The agent in this repository

I run [UNITARES](https://github.com/cirwel/unitares), an open-source (Apache-2.0) server that gives long-running agents a persistent identity and stores their check-ins. One of the agents on my deployment is Watcher, a review agent that scans code changes and tracks its findings. It has been checking in every few minutes since 2 November 2026.

| | |
|---|---|
| Registry entry | CIS-8004 `<12802,0>` on testnet, token `1315` |
| Badge | `JyP9UYjHZ84JsGq5rAC2F` ([check it](https://agent-registry-mcp.concordium.com/v1/check-badge/JyP9UYjHZ84JsGq5rAC2F)) |
| Agent Card | [`agent-card/watcher.json`](agent-card/watcher.json) |
| UNITARES agent | `907e3195-c649-49db-b753-1edc1a105f33` (also stored in the entry's on-chain metadata, key `unitares.agent_uuid`) |
| Record | [`trail/watcher.jsonl`](trail/watcher.jsonl) |
| Registration | [transaction](https://ccdexplorer.io/testnet/transaction/4ea50cb82986fbbf7ec12644d389f7e491328514cbbba60d6b4b2c716d702447) |

Anchors so far:

| Records | Anchor transaction |
|---|---|
| 1..1617 | [`b71c9294…`](https://ccdexplorer.io/testnet/transaction/b71c9294303b7bb59b5ec985c2717c89af5e8e47de42f0d7edf7d2d687e7483e) |
| 1..1619 | [`bc267531…`](https://ccdexplorer.io/testnet/transaction/bc267531b36609a919caa84234a8741cab31c658a28f258ebe211c5b9e69d281) |
| 1..1621 | [`08d82155…`](https://ccdexplorer.io/testnet/transaction/08d8215581c60910597b30313ca076333d1f06e92791ff12c661a1be41e93fb6) |

The registry entry's `countersign.anchor` metadata always names the latest one, and each anchor names the one before it. Later anchors are not listed here; `verify` finds them.

## Verify it yourself

Needs Node 20 or later. No keys, no account.

```sh
git clone https://github.com/cirwel/countersign && cd countersign && npm install
node src/cli.mjs verify --badge JyP9UYjHZ84JsGq5rAC2F --trail trail/watcher.jsonl
```

The command:

1. resolves the badge through Concordium's hosted Agent Registry MCP server and refuses any registry other than `<12802,0>` on testnet;
2. runs the server's badge check (registered, active, card bytes match the on-chain hash);
3. reads the entry's on-chain metadata and confirms it names the same UNITARES agent as the trail file;
4. reads every value the entry's `countersign.anchor` metadata has ever held from the registry's event history, and reads each anchor transaction from a testnet node;
5. confirms each anchor was sent by the account that owns the registry entry, that the anchors form one unbroken chain with none skipped or replaced, and that each covers more records than the last;
6. recomputes the commitment chain from the trail file and compares it with every anchor.

Now change one character in any anchored line of `trail/watcher.jsonl` and run it again. It fails.

## How it works

Each record is serialized as canonical JSON. The commitment is a hash chain:

```
h_0 = SHA-256("countersign.trail.v1\n" || canonical(header))
h_i = SHA-256(h_{i-1} || SHA-256(canonical(record_i)))
```

The header names the registry contract, the token and the agent UUID, so a trail cannot be presented under a different registry entry. An anchor is an 85-byte register-data transaction carrying the token id, the last sequence number covered, `h_n`, and the hash of the previous anchor transaction. Because the chain always starts at record 1, every new anchor re-commits to everything the earlier anchors covered. The verifier checks every anchor the entry has ever pointed at, taken from the registry's event history rather than only from the current pointer, so the owner cannot make an anchored record disappear by pointing the entry at a fresh anchor. The full format is in [SPEC.md](SPEC.md).

Operator commands (these need a funded testnet account key in a file outside the repository):

```sh
node src/cli.mjs register --uuid <unitares agent uuid>      # mint the registry entry
node src/cli.mjs card --token <id> --name ... --url ... --out agent-card/<name>.json
node src/cli.mjs pin-card --token <id> --url ... --file agent-card/<name>.json
node src/cli.mjs export --uuid <uuid> --token <id> --out trail/<name>.jsonl
node src/cli.mjs anchor --trail trail/<name>.jsonl
```

Registry transactions are built by the hosted MCP server, which holds no keys and returns unsigned payloads. This tool signs one only if it targets the pinned registry contract on testnet and calls the entrypoint the command expects; for the anchor pointer it also rebuilds the parameter locally and requires the server's bytes to match.

## What this proves, and what it does not

- A passing check proves that the trail file is byte-for-byte the record that was committed at each anchor's block time, by the account that owns the registry entry.
- It does not prove the record was true or complete before it was first anchored. I operate both the UNITARES server and the registry entry. The first anchor here was written after the fact, over records going back to 2 November.
- The badge check proves registration, active status and card integrity. It is not an endorsement of the agent and involves no review of its behaviour.
- The account that owns this entry was created with the testnet identity provider's placeholder identity. Nothing here links the agent to a real, identified owner.
- The canonical format is defined by this project, not by UNITARES. The exporter reads the server's `core.checkpoints` table; the server's own checkpoint digests are keyed and cannot be checked by outsiders, which is why Countersign defines its own.
- Records newer than the latest anchor are not covered until the next anchor.
- The verifier reads the entry's metadata, owner and event history through Concordium's hosted Agent Registry server and its indexer, and reads the anchor transactions from a public testnet node. It trusts both to answer honestly. A stricter verifier would read the contract's state and events from its own node.
- This is a prototype. It has had no security audit, and it is not a compliance tool.

## Path to production

- **Anchoring on a schedule, from the server.** UNITARES already emits an immutable event for each recorded checkpoint. A subscriber on that stream can anchor every N records or every hour, which shrinks the window in which a record could be changed unseen.
- **Someone else holds the pen.** The weakness above is that the operator anchors their own agent's record. The fix is a witness: a separately owned service that checks the agent's badge and writes the anchor, paid per anchor over x402 with the transaction fee sponsored so the agent's account needs no CCD of its own.
- **A real owner.** On mainnet the registry entry's account comes from an identity provider that has verified a person or company, which is what gives the badge its meaning.
- **Portable records.** A trail file plus its anchors can be checked long after the server that produced it is gone.

## Licence

Apache-2.0.
