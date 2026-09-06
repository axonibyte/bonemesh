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
- `mesh` is a third mode used by the convergence tier: it dials several
  `--peers` (`host:port,host:port`), optionally streams `--message` to
  `--send-to`, and dumps its routing table to `--routes`.

### Observability flags (all optional; tier 10)

Every driver additionally accepts a `caps` subcommand and these flags on
`listen`/`connect`/`mesh`; a driver that does not support a feature simply omits
its token from `caps`, and a tier that needs it skips that driver loudly.

```
<driver> caps                 # prints the space-separated feature tokens it supports
--acks F                      # append each received ack/nak inner message as one JSON line
--sessions F                  # rewrite {peer: {"epoch": N, "th": "<hex prefix>"}} as sessions change
--capture F                   # (Go only) tee every transport carrier as {"dir","frame"} NDJSON
```

`--acks` observes ack/NAK delivery; `--sessions` exposes the rekey epoch and the
transcript-hash label (both ends of a session agree on `th`, so a dial collision
that converged shows one entry with a shared `th`); `--capture` feeds
`bonemesh-inspect` for the key-log round-trip. `--out` continues to carry
application payloads only. `BONEMESH_KEYLOG=<path>` makes a node write its
directional transport keys (security.md §8).

Current drivers: `drivers/java.sh`, `drivers/elixir.sh`, `drivers/rust.sh`,
`drivers/go.sh`, `drivers/js.sh`, `drivers/php.sh`. The matrix confirms all
thirty-six pairs (each of the six implementations as both responder and
initiator, cross and same) interoperate.

## Tiers

- **`run-matrix.sh`** — the N×N live handshake/transport/delivery matrix (above).
- **`tier5.sh`** — methodology tier 5, node vs. fake peer. A Go fault peer
  (`tier5/`, reusing the Go port's stack to craft genuinely valid messages it
  then corrupts) drives every implementation's listener through a battery of
  deterministic faults — non-JSON, oversize, and unterminated frames; wrong-mesh
  bmx1; handshake aborted after bmx1; garbage and tampered bmx3; a corrupted
  transport frame. Oracle, two-sided: after the battery nothing was delivered,
  and a final valid send *does* deliver (self-testing that the oracle can see a
  delivery, and that the node survived every fault). It proves passivity under
  faults and survival — not the absence of per-connection error logging.
- **`tier6.sh`** — methodology tier 6, full mesh under a hostile network.
  Part A re-runs the matrix while loopback carries netem latency + loss; Part B
  cuts a listener off with an iptables DROP and asserts a send is *not* delivered
  (connect fails and the output stays empty), then heals and asserts an identical
  send *does* deliver. Needs Linux `tc`/netem + iptables as root, so it runs on
  the interop guest; on any other host it no-ops loudly.
- **`tier7.sh`** — methodology tier 7, seeded fuzzing. A Go fuzzer (`tier7/`)
  drives each node's listener through many randomized, replayable mutation
  strategies over frames, handshake messages, and transport payloads; the seed
  is printed and accepted back via `BONEMESH_FUZZ_SEED` (`BONEMESH_FUZZ_ITERS`
  sets the count), so a failure reproduces exactly. Same two-sided oracle as
  tier 5. This tier found and drove fixes for two robustness defects: the Go node
  panicked (crashing the process) on malformed handshake input, and the PHP node
  emitted warnings on a bmx1 missing a field — both now reject cleanly.
- **`tier8.sh`** — methodology tier 8, concurrency/convergence. Only Java and
  Elixir route (the others do direct delivery), so this tier is scoped to them
  and needs both — it runs on the driver and skips loudly where either is
  missing. It builds a diamond (Java endpoints, Elixir relays) with two disjoint
  paths, drives continuous sends, then kills the relay the sender is using, and
  asserts convergence with two oracles: no live node keeps a route through the
  dead relay (via the nodes' new route-table accessors) and delivery heals over
  the alternate path. The convergence oracle is self-tested first against a
  known-bad routing dump.
- **`tier9.sh`** — methodology tier 9, simulated meshes. From a single seed
  (printed, replayable via `BONEMESH_SIM_SEED`) it churns a fleet of listener
  nodes — one per usable implementation — through a sequence of nemesis actions:
  authenticated sends, intrusion attempts (a peer holding a certificate from a
  different mesh root), kills, and stale-identity restarts. It then checks the
  security-critical invariants that must hold regardless: authenticated-only
  delivery (no intruder payload ever delivered), no fabrication (every delivered
  tag was one the sim sent), delivery of every authenticated send to a live node,
  and survival across the churn. The invariant checker is self-tested first
  against synthetic logs. Dedup and routing convergence are routing-layer
  properties covered by tier 8 and are not re-asserted here.

The runners **discover drivers and health-probe each one**, keeping only the
implementations whose toolchain is present and logging every skip. So the same
scripts run six-wide on the driver and, on the interop guest (which lacks
Erlang/OTP 28), five-wide with Elixir logged as skipped — never silently.

## The interop reaper tenant

`../.reaper.toml` (project `bonemesh-interop`) is the root tenant: host execution
on an `ubuntu-26.04` guest, syncing the whole repo. `interop/guest-setup.sh`
provisions the toolchains — Java 25, Go 1.26, Rust, PHP 8.5, and Node 24 (from
NodeSource; apt's Node 22 bundles an OpenSSL without ML-KEM/ML-DSA), all over the
guest's system OpenSSL 3.5 — plus `tc`/netem and iptables. The run gates the
matrix, tiers 5, 6, and 7. Elixir is not provisioned here: its node needs
Erlang/OTP 28 for the native PQC API, which ubuntu-26.04 does not package; its
interop is covered by the six-language matrix on the driver (which has OTP 28).

## Status and future work

Runs on the driver (six languages) and as the `bonemesh-interop` reaper tenant
(five languages under netem; tier 8 needs both Java and Elixir, so it runs on
the driver and skips on the guest). Methodology tiers 5–9 are all implemented.
Tiers 10–11 (long-horizon soak, human-reviewed transcripts) remain future work,
as the plan states.
