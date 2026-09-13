# BoneMesh Testing Guide

How this repository is tested, and how to run any part of it. The philosophy is
reaper's: a *portfolio of oracles*, where every tier earns its place by a defect
no cheaper tier can catch. This guide is the operator's map — the tiers, the
reaper tenants, the seeds that make failures reproducible, and the environment
knobs. For how the code is built, see [`architecture.md`](architecture.md); for
the normative wire it is all checked against, see
[`../spec/protocol.md`](../spec/protocol.md) and
[`../spec/security.md`](../spec/security.md).

---

## 1. The tier map

| Tier | What it proves | Where it runs |
|---|---|---|
| 1, 2, 4 | Per-implementation unit behavior, contract and state-machine tests; corpus vectors mirrored in-code | each `<lang>/` tenant |
| 2 (byte-exact) | Byte-exact agreement with the shared corpus — canonicalization, key schedule, hybrid agreement, framing, message schema, transport frame, PQC vectors, key-log capture — for every implementation, and again under a hostile non-UTF-8 charset | `interop/run-corpus-checks.sh`, root tenant and CI |
| 3 | Source-as-data: the spec read as markdown, every implementation's constants, tunables and message types checked against it both ways | `interop/check-spec.sh` (one shared tool), root tenant and CI |
| 5 | Node vs. a fault peer: survives a battery of malformed input and delivers nothing spurious | root interop tenant |
| 6 | A mesh under a hostile network (netem latency + loss; iptables partition and heal) | root tenant, Linux guest only |
| 7 | Seeded, replayable fuzzing over frames / handshake / transport | root tenant |
| 8 | Concurrency & routing convergence: kill a relay, assert the mesh reroutes | root tenant |
| 9 | Seeded nemesis churn (sends, intrusions, kills, restarts) with security invariants | root tenant |
| 10 | The 3.1 features on the wire, cross-language: ack, NAK/D4, rekey, idle teardown, probe-timeout death, key-log round-trip | root tenant |
| 11 | Long-horizon soak — sustained churn with the features cycling, run once per release | **gated**, never in the standard battery |

Tiers 1, 2 and 4 live with each implementation; the byte-exact corpus comparison
and tier 3 are shared but need the whole repository, so they live in `interop/`
beside tiers 5–10 — the **interop battery** written once and run against every
implementation as a black box. Tier 11 is a deliberate, opt-in soak.

Why the corpus comparison is not inside a `<lang>/` tenant: a tenant syncs only its
own subtree and cannot see `spec/corpus` at all. Each implementation's unit suite
therefore *mirrors* the vectors in code, with a header naming the corpus file, and
the byte-exact comparison runs where the whole tree is present.

---

## 2. Reaper tenants

Each tenant is a `.reaper.toml` that builds and tests one thing hermetically in a
digest-pinned container (or, for the root tenant, directly on a networked guest).

| Tenant (`project`) | Manifest | Runs |
|---|---|---|
| `bonemesh-gonode` | `go/.reaper.toml` | `go test ./...` |
| `bonemesh-rust` | `rust/.reaper.toml` | `cargo test --offline` |
| `bonemesh-js` | `js/.reaper.toml` | `node --test` |
| `bonemesh-php` | `php/.reaper.toml` | `php tests/run.php` |
| `bonemesh-elixir` | `elixir/.reaper.toml` | `mix test` |
| `bonemesh-java` | `java/.reaper.toml` | `./gradlew --no-daemon test` |
| `bonemesh-python` | `python/.reaper.toml` | `uv run pytest -q` + the dependency-licence gate |
| `bonemesh-spec` | `spec/.reaper.toml` | the corpus conformance runner (`go test ./...` in `conformance/`) |
| `bonemesh-interop` | `.reaper.toml` (root) | the interop battery: matrix + tiers 5–10 |

Run any tenant from its directory (the root tenant from the repo root):

```sh
reaper up            # provision the ephemeral machine
reaper test          # sync the working tree, build, reset, run
reaper down          # destroy it
```

`reaper test` needs a live session, so `reaper up` first. Sessions expire (~2 h);
`reaper down` then `reaper up` recycles a stale one.

---

## 3. Running the interop battery

The battery discovers drivers under `interop/drivers/*.sh`, **health-probes each
one**, and keeps only the implementations whose toolchain is present — logging
every skip, never silently narrowing. So the same scripts run seven-wide on a
developer host that has all seven toolchains, and six-wide on the interop guest,
which is `ubuntu-26.04` and has no Erlang/OTP 28, so **Elixir is skipped there
and logged as `SKIP elixir`**; its interop is covered by the seven-wide runs on a
host that has OTP 28.

Locally you can run a single tier directly (the drivers build what they need on
first use):

```sh
sh interop/run-corpus-checks.sh   # every corpus family x implementation, twice
sh interop/check-spec.sh          # tier 3: the spec read as data, both directions
sh interop/check-spec.sh --self-test   # prove that checker can fail (11 cases)
sh interop/run-matrix.sh --self-test   # prove the matrix oracle separates its 3 verdicts
sh interop/run-matrix.sh          # the N×N live handshake/transport/delivery matrix
sh interop/tier5.sh               # ... through tier10.sh
```

Two things worth knowing about what these prove, both new in 3.3.0.

`check-spec.sh` now runs **both directions** on message types: an implementation that
emits an inner type the spec never listed fails, and a type the spec lists with no
corpus schema behind it fails. Before this, every axis except `BONEMESH_*` tunable
names ran spec -> code only, which is why a `broadcast()` that only one port had
survived the whole battery and needed a human to find it (decision #24).

`run-matrix.sh` sends a 96 KB payload in all 49 cells, with a marker at each end of
it. Two markers rather than one is what lets a single send separate three outcomes --
reassembled, a fragment delivered to the application, nothing delivered -- and the
middle one is the failure mode defect D11 actually produced. Both that oracle and
the spec checker have `--self-test` modes, because a gate never observed failing is
a gate of unmeasured value.

The first two are the deterministic wire contract and run ahead of the live tiers
in the root tenant's chain, so a corpus disagreement stops the battery before the
expensive parts. Both self-test: `run-corpus-checks.sh --self-test` proves it fails
on a broken *and* on a missing check, and `check-spec.sh --self-test` proves the
spec checker fails on a dropped constant, an undocumented tunable, spec drift,
corpus drift, and a reworded spec table.

Tier 6 needs Linux `tc`/netem + iptables as root, so off the guest it no-ops
loudly. **Tier 10 is capability-gated**: each driver answers a `caps` subcommand
with the feature tokens it supports, and a scenario skips (loudly) any driver
missing the capability it exercises — see [`../interop/README.md`](../interop/README.md)
for the driver contract and the `--acks` / `--sessions` / `--capture`
observability flags.

---

## 4. Reproducing a failure: seeds

Every randomized tier prints its seed and takes it back through the environment,
so a red run replays byte-for-byte.

| Tier | Seed variable | Also |
|---|---|---|
| 7 (fuzz) | `BONEMESH_FUZZ_SEED` | `BONEMESH_FUZZ_ITERS` sets the iteration count |
| 9 (churn) | `BONEMESH_SIM_SEED` | `BONEMESH_SIM_ROUNDS` sets the round count |
| 11 (soak) | `BONEMESH_SOAK_SEED` | `BONEMESH_SOAK_SECONDS` sets the duration |

```sh
BONEMESH_FUZZ_SEED=12345 sh interop/tier7.sh    # replay the exact fuzz sequence
```

---

## 5. Environment tunables

Node behavior knobs, read once at node start. They are **local behavior, not the
wire contract** — two nodes with different values still interoperate — so tests
set short values to make a slow behavior fire quickly. Defaults are chosen so no
standard tier trips them.

| Variable | Default | Effect |
|---|---|---|
| `BONEMESH_PROBE_TIMEOUT_MS` | `15000` | Declare a silent neighbor dead after this long |
| `BONEMESH_IDLE_MS` | `0` (off) | Tear down a data-idle link after this long |
| `BONEMESH_RETRY_BASE_MS` | `500` | Initial retry backoff |
| `BONEMESH_RETRY_CAP_MS` | `30000` | Retry backoff ceiling |
| `BONEMESH_RETRY_MAX_MS` | `60000` | Total retry lifetime before giving up (`0` disables retry) |
| `BONEMESH_REKEY_MS` | `3600000` | Rekey a session at this age |
| `BONEMESH_REKEY_FRAMES` | `65536` | Rekey when a direction's frame counter reaches this |
| `BONEMESH_REKEY_TIMEOUT_MS` | `10000` | Abandon a stalled rekey, keeping the old keys |
| `BONEMESH_KEYLOG` | unset | When set to a path, a node writes its transport keys there (§7) |

---

## 6. The long soak (tier 11)

Tier 11 is **not** in the standard battery — it costs real wall-clock and is run
once per release. It repeatedly drives the tier-9 churn engine for the whole soak
duration with the 3.1 features cycling underneath (a low rekey threshold, so
every session rekeys many times), and reuses tier 9's self-tested invariants as
its oracle.

```sh
BONEMESH_LONG_SOAK=1 BONEMESH_SOAK_SECONDS=14400 sh interop/tier11.sh
# or: sh interop/tier11.sh --long-soak
```

Without the gate it skips loudly. Each run writes a reviewable bundle to
`${REAPER_OUT:-interop/out}/tier11-<seed>-<timestamp>/` — a `summary.txt` (host,
seed, per-cycle PASS/FAIL) plus one log per churn cycle. Review the summary; a
single `FAIL` line names the cycle and its log.

---

## 7. Debugging encrypted traffic (key-log + inspector)

The protocol is JSON under channel encryption, so it stays inspectable in
development without a plaintext production mode. A node with `BONEMESH_KEYLOG`
set writes its per-session directional transport keys (loudly warning that
forward secrecy is forfeit for anyone holding the file); a Go node's `--capture`
flag tees the wire frames; and `bonemesh-inspect` joins the two to reproduce the
plaintext:

```sh
# 1. a node writes its key-log; a Go peer captures the wire
BONEMESH_KEYLOG=keys.log interop/drivers/<lang>.sh listen  ... &
interop/drivers/go.sh connect ... --capture capture.ndjson

# 2. decrypt the captured stream against the key-log
go/bonemesh-inspect --keylog keys.log --capture capture.ndjson
```

The key-log format is one implementation-neutral standard (security.md §8), so a
single inspector reads a log written by a node in any language. This is exactly
what tier 10's key-log scenario checks.
