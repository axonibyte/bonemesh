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
| 1–4 | Per-implementation unit behavior + byte-exact agreement with the shared corpus (canonicalization, key schedule, framing, message schema, transport frame, PQC vectors) | each `<lang>/` tenant; corpus vectors also in the `spec/` conformance tenant |
| 5 | Node vs. a fault peer: survives a battery of malformed input and delivers nothing spurious | root interop tenant |
| 6 | A mesh under a hostile network (netem latency + loss; iptables partition and heal) | root tenant, Linux guest only |
| 7 | Seeded, replayable fuzzing over frames / handshake / transport | root tenant |
| 8 | Concurrency & routing convergence: kill a relay, assert the mesh reroutes | root tenant |
| 9 | Seeded nemesis churn (sends, intrusions, kills, restarts) with security invariants | root tenant |
| 10 | The 3.1 features on the wire, cross-language: ack, NAK/D4, rekey, idle teardown, probe-timeout death, key-log round-trip | root tenant |
| 11 | Long-horizon soak — sustained churn with the features cycling, run once per release | **gated**, never in the standard battery |

Tiers 1–4 live with each implementation; tiers 5–10 are the shared **interop
battery** written once and run against every implementation as a black box; tier
11 is a deliberate, opt-in soak.

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
every skip, never silently narrowing. So the same scripts run six-wide on a
developer host that has all six toolchains, and five-wide on the interop guest,
which is `ubuntu-26.04` and has no Erlang/OTP 28, so **Elixir is skipped there
and logged as `SKIP elixir`**; its interop is covered by the six-wide runs on a
host that has OTP 28.

Locally you can run a single tier directly (the drivers build what they need on
first use):

```sh
sh interop/run-matrix.sh     # the N×N live handshake/transport/delivery matrix
sh interop/tier5.sh          # ... through tier10.sh
```

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
