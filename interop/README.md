# BoneMesh interop harness

Cross-implementation tests. A client must not care what implementation answers
on the other side — only that the protocol is obeyed — so nothing here is
written in terms of specific languages. The harness discovers drivers and runs
every implementation against every other.

## Corpus conformance checks (`check-*.sh`)

Each script confirms one implementation reproduces a shared corpus artifact
byte-for-byte (canonicalization, key schedule, framing, message schema,
transport frame, post-quantum vectors). Run on the driver, where the whole repo
is present. These prove agreement on the *deterministic* wire contract.

## The interop matrix (`run-matrix.sh`)

The end-to-end proof: a live BMX handshake, encrypted transport, and message
delivery between two independent implementations.

- It provisions **one shared mesh** (a root and two member certificates) using
  the bundled `bonemesh-ca`, whose output is neutral and consumed identically by
  every driver.
- It **discovers implementations** by listing `drivers/*.sh` and runs the full
  `(responder × initiator)` matrix. One driver listens as node `one`; the other
  connects as node `two` and sends a message; the harness checks it arrived.
- There is **no implementation-specific logic** in the runner. Adding a language
  is dropping a new `drivers/<name>.sh` — nothing else changes.

## The driver contract

A driver is any executable that accepts these two invocations. All key and
certificate files are neutral, shared formats (base64 for raw keys, JSON for
certificates and messages), so an artifact produced for one driver works for
every driver.

```
<driver> listen  --port P --mesh M --root-pub F --cert F --id-pub F --id-priv F --out F --seconds N
<driver> connect --mesh M --root-pub F --cert F --id-pub F --id-priv F --host H --port P --to L --message F --seconds N
```

- `listen`: start a node on port `P` with the given identity; for each
  application payload delivered to this node, append its JSON on one line to
  `--out`; run for `--seconds` then exit.
- `connect`: start a node, dial `H:P`, send the `--message` payload to node
  `--to`, then exit after `--seconds`.
- The node's own label is read from its certificate. Files: `root-pub` is
  base64 of the raw ML-DSA-87 root public key; `cert` is the JSON membership
  certificate; `id-pub`/`id-priv` are base64 of the raw ML-DSA-65 node keys;
  `message` is a JSON payload object.

Current drivers: `drivers/java.sh`, `drivers/elixir.sh`, `drivers/rust.sh`,
`drivers/go.sh`. The matrix confirms all sixteen pairs (each of the four
implementations as both responder and initiator, cross and same) interoperate.

## Status and future work

Run on the driver today (it has every toolchain). Making this a reaper tenant
needs a guest carrying every implementation's runtime — the open "polyglot
guest vs. per-language guests" question — and is the home of the methodology's
tiers 5–9 (fault injection, containerized meshes, seeded fuzzing, convergence,
simulated meshes) as more implementations land.
