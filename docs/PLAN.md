# BoneMesh Expansion Plan

**Status:** draft for review · **Date:** 2026-09-04

BoneMesh grows from a single Java library into a multi-language mesh protocol
project: a specification, six conforming implementations (Java, Go, Rust, PHP,
Elixir, JavaScript/Node), a real security layer built on NIST post-quantum
cryptography, and a testing regime built on reaper and its
testing-methodology.md — per-implementation tenants plus a top-level
multiprotocol interop suite.

---

## 1. Decisions already made

These were settled in planning discussion and are treated as fixed unless
revisited deliberately:

| Topic | Decision |
|---|---|
| Product shape | The protocol spec is the product; implementations conform to it. No port begins before the v3 spec exists. |
| Repo shape | One super-repo. Top level: `docs/`, `spec/`, `interop/`, plus one folder per language (`java/`, `go/`, `rust/`, `php/`, `elixir/`, `js/` — no `bonemesh-` prefix; the repo name already says it). |
| Wire format | JSON everywhere. Readability of the objects is a design value; no binary serialization. |
| Security | Noise-framework-style authenticated handshake using **NIST PQC where possible** (ML-KEM / FIPS 203 for key establishment, ML-DSA / FIPS 204 for identity), hybridized with X25519 per current practice. |
| "Readable in flight" | Plain JSON at the protocol layer under channel encryption, plus a spec'd session-key logging hook (à la `SSLKEYLOGFILE`) and a bundled inspector tool that decodes live traffic during development. |
| PHP scope | Full routing node, same peer status as the other five. |
| Testing | Each language folder is its own reaper tenant (verified: reaper's CLI treats the manifest's directory as the project tree, so subdirectory tenants work today with no reaper changes). A root-level tenant runs the multiprotocol interop suite. All testing follows reaper's testing-methodology.md. |
| Baseline | Fast-forward `main` to `dev` (d807d83). It is strictly ahead (Java 17, NPE fix #3, crypto prototype). The Kyber/AES prototype is superseded by the v3 security layer, not extended. |
| Docs | A parallel workstream from day one, not a phase. |

## 2. Branch triage (current state of the repo)

- `main` @ ad684ca (2022-01-02) — 10 commits **behind** dev. Not the newest work.
- `dev` @ d807d83 (2023-04-04) — strictly ahead of main; contains the Java 17
  bump, the #3 NPE fix, removal of the Maven Central upload workflow, and the
  encrypted-messages prototype (round-3 Kyber-1024 via BouncyCastle PQC + AES/GCM).
- `feature/sync-topology-overhaul` @ d807d83 — identical to dev, zero unique
  commits. Stale pointer; flag for deletion (remote branch deletion needs
  owner sign-off).

Notes on the dev crypto prototype, for the record (these motivate replacing it
rather than extending it):

- Round-3 Kyber-1024 predates FIPS 203; its ciphertexts are incompatible with
  final ML-KEM. Every non-Java port would need the *draft* algorithm.
- Public keys are distributed over unsigned discovery messages: no identity
  binding, so the key exchange is MITM-able by anyone on the path.
- A stray editor backup (`CryptoEngine.java~`) is committed and should be removed.

## 3. Known-defect registry (v2, verified present on the dev baseline)

These become `docs/defects.md` in Phase 0. They serve double duty: the Phase 1
fix list, and later the **validation-gate corpus** — per the methodology, each
gets reverted once the harnesses exist to prove the suite rediscovers it.

| # | Defect | Where |
|---|---|---|
| D1 | `isAlive()` returns true for dead nodes (`> -1L` vs the `Long.MAX_VALUE` dead sentinel) | `NodeMap` |
| D2 | `Node` lacks `equals`/`hashCode` but is a map key → duplicate nodes per label, nondeterministic lookup | `Node`, `NodeMap` |
| D3 | "Latency" is time-since-last-heartbeat-bump, not RTT; starts at ~epoch ms; `MAX_VALUE + x` overflows negative so dead nodes can become best routes | `NodeMap` |
| D4 | NAK marks the message's final destination dead instead of the failed next hop | `BoneMesh.setNodeStatus` |
| D5 | Broadcast iterates the indirect-route table only: fresh direct neighbors missed; own label can appear as a route (self-broadcast) | `NodeMap.getAllKnownNodeLabels` |
| D6 | Single-threaded send queue + immediate requeue-on-failure + no connect timeout → one dead peer head-of-line blocks and busy-loops the whole mesh | `SocketClient` |
| D7 | Unbounded `readLine()` on untrusted input; no message size limit (protocol flaw, fixed in v3 spec) | `IncomingSocketHandler`, `SocketClient` |
| D8 | Unauthenticated key distribution in the crypto prototype (MITM) — superseded by v3 | `crypto/CryptoEngine` |

D1, D2, D5, D6 are Java implementation bugs fixed in Phase 1. D3, D4, D7, D8
are protocol flaws whose real fix lands in the v3 spec (Phase 2), with whatever
interim Java mitigation is cheap (e.g. a connect timeout for D6/D7).

## 4. Phases

Docs (§6) and reaper onboarding (§7) run through all of these; the phases below
are the dependency spine.

### Phase 0 — Repo groundwork (small)

1. Fast-forward `main` to `dev`; delete `feature/sync-topology-overhaul`
   (owner authorizes the remote operations).
2. Restructure into the super-repo layout via `git mv` (history preserved,
   `git log --follow` works):
   ```
   /docs/          project-wide documentation (see §6)
   /spec/          protocol spec + shared corpora + test vectors + conformance runner
   /interop/       multiprotocol harness (tiers 5–9) — also the root reaper tenant
   /java/          the existing implementation
   /go/ /rust/ /php/ /elixir/ /js/    created as ports begin
   ```
3. Rework `bitbucket-pipelines.yml` for the monorepo (path-filtered per-folder
   steps; the existing mirror logic updated).
4. Seed `docs/defects.md` from §3 and `docs/decisions.md` from §1.

### Phase 1 — Java reference hardening (medium)

Goal: make Java a trustworthy v2 reference before the spec freezes v2's
described behavior.

1. `NodeMap`/`Node` unit suite first (methodology tier 1) — no sockets needed;
   catches D1–D3, D5 directly.
2. Fix D1, D2, D5, D6 (+ cheap mitigations for D7). Every fix ships with the
   test that would have caught it; every new assertion is mutation-checked
   (break the code, watch it fail, restore).
3. Serialization round-trip tests for the message classes (tier 1/2 seed —
   these later become spec test vectors).
4. Build modernization: `jcenter()` → `mavenCentral()`, Gradle 7+/8 with
   `maven-publish` replacing the removed `maven`/`uploadArchives` plugins,
   current Shadow, current `org.json` (CVE), JUnit 5.
5. `java/.reaper.toml` — first tenant onboarded; `reaper test` green becomes
   the commit gate for Java work.

### Phase 2 — Protocol v3 spec + security design (large; the keystone)

Written in `spec/`, in two passes:

**Pass 1 — describe v2 as it is** (`spec/v2-behavior.md`): wire format,
discovery/ack semantics, routing rules, warts explicitly documented. This makes
the v3 delta reviewable and gives ports a map of legacy behavior they must
*not* replicate.

**Pass 2 — v3 proper** (`spec/protocol.md` + `spec/security.md`):

- **Identity.** A node *is* an ML-DSA keypair; the label is a display name
  bound to it. Fixes spoofing at the root.
- **Handshake.** Noise-framework pattern (XX-class: mutual authentication,
  neither side knows the other's static key in advance) extended with hybrid
  key establishment: X25519 **and** ML-KEM-768, both feeding the key schedule,
  following the PQNoise/hybrid-KEM construction that TLS (X25519MLKEM768),
  Signal PQXDH, and Rosenpass converged on. Hybrid rather than PQ-only so a
  flaw in the young ML-KEM implementations doesn't strand the mesh below
  classical security. AEAD: ChaCha20-Poly1305 (AES-GCM as an alternative suite
  if profiling demands it).
- **Trust/membership model** — open question §8.1, decided during this phase.
- **Framing.** Noise transport messages are already length-prefixed with a
  64 KiB ceiling; JSON objects ride inside them. Spec defines chunking for
  larger application payloads and a hard maximum message size (kills D7 by
  construction). The decrypted payload stream is pure JSON — the readability
  guarantee lives at the protocol layer.
- **Debuggability.** Session-key logging hook (env-var-triggered, off by
  default, loudly logged when on) + `spec/` defines the inspector tool's
  behavior so all implementations can emit compatible key logs.
- **Semantics fixed from v2:** message IDs + nonces (dedup, replay protection),
  NAK attribution to the failed hop (D4), honest latency measurement (D3),
  broadcast semantics including direct neighbors and excluding self (D5),
  protocol version field in the handshake, explicit retry/backoff guidance (D6).
- **Shared corpora** (`spec/corpus/`): canonical encodings, hostile/malformed
  message corpus, handshake transcripts (with fixed test keys), routing
  scenario vectors ("given this topology and these advertisements, A reaches D
  via B"). Consumed by every tenant — this is what makes six implementations
  one project.
- **Conformance runner** (`spec/conformance/`): language-agnostic black-box
  driver that speaks v3 over TCP to any node binary and executes the corpus.
  Written once, in one language (Rust or Go — decided at phase start).

### Phase 3 — Java to v3 (medium)

Java implements the v3 spec, becoming the reference implementation and the
spec's first implementability check (spec bugs found here are spec fixes, not
Java workarounds). PQC via BouncyCastle ≥ 1.79 (final ML-KEM/ML-DSA).
Migration notes for v2 users land in `docs/`. The conformance runner passes
against Java before any port starts.

### Phase 4 — The ports (large, parallelizable after the first)

Order: **Elixir → Rust → Go → JS → PHP.**

- Elixir first after Java: OTP is the best natural fit and the most *different*
  runtime — it stress-tests the spec's hidden Java assumptions early, when the
  spec is cheapest to fix.
- PHP last: full routing node as decided, built CLI-mode on ReactPHP/Amp or
  Swoole; it inherits a mature spec, corpus, and conformance suite, which is
  exactly the support the hardest port needs.

Each port must, before it's "in":

1. Pass the shared conformance runner and corpus.
2. Own tiers 1–4 natively (unit tests on routing/serialization, exact-encoding
   conformance vs vectors, source-vs-spec structural checks, protocol state
   machine as pure functions).
3. Onboard as a reaper tenant (`<lang>/.reaper.toml`).
4. Join the interop matrix (§5).

PQC per language (the "where possible" map):

| Language | ML-KEM / ML-DSA source | Risk |
|---|---|---|
| Java | BouncyCastle ≥ 1.79 (final FIPS 203/204) | low |
| Go | `crypto/mlkem` in stdlib (Go ≥ 1.24); ML-DSA via Cloudflare CIRCL | low |
| Rust | RustCrypto `ml-kem`/`ml-dsa` or liboqs-rust | low–medium (audit status varies) |
| JS/Node | `@noble/post-quantum` | low–medium |
| Elixir | NIF — Rustler wrapping the Rust impl, or liboqs NIF | medium (we maintain glue) |
| PHP | FFI to liboqs | medium–high (we maintain glue; weakest ecosystem) |

Elixir and PHP are the maintained-glue risk noted when Noise was chosen; the
plan accepts it, and the hybrid handshake plus conformance vectors bound the
blast radius of a bad binding.

### Phase 5 — Multiprotocol interop suite (large, grows continuously from Phase 3)

Lives in `interop/`, runs as the **root reaper tenant**, owns methodology
tiers 5–9 *written once, language-agnostic*, driving every implementation as a
black box over TCP:

- **Tier 5 — node vs. fake peer:** in-process fake peer with deterministic
  fault injection (malformed JSON, truncated frames, half-open sockets, slow
  reads, handshake abortion at each state).
- **Tier 6 — containerized full mesh:** mixed-language topologies under
  hostile defaults — netem latency/loss/partition, IPv6, mixed protocol
  versions, restarts mid-stream.
- **Tier 7 — seeded fuzzing:** replayable seeded fuzz of frames, handshake
  messages, and JSON payloads against every implementation; seed printed,
  accepted back via environment. Best defect-per-line ratio; starts early.
- **Tier 8 — concurrency/convergence:** N-way concurrent sends, partition and
  heal, asserting **converged routing state** (all live nodes agree, no route
  through a dead node), not response counts. Two oracles for the claims that
  matter — e.g. prove the sender queued nothing *and* the receiver got nothing.
- **Tier 9 — simulated meshes:** seeded node actors joining/leaving/sending
  over hundreds of actions with nemesis operations (kills, partitions,
  stale-identity reconnects, double-delivery). **Oracle self-tested first**:
  feed it the output of a broken mesh (modeled on D1–D8) and confirm it
  complains, before trusting a green run.
- **Validation gate:** revert each registry defect in a scratch branch and
  confirm the harness rediscovers it.

Tier 10 (feature-behavior) is delivered in 3.1.0 and runs in the standard
battery; tier 11 (long-running seeded soak over accumulated state, with a
human-reviewed transcript bundle) is delivered but gated behind an explicit
`BONEMESH_LONG_SOAK` flag, so the routine suite still names what it does not
prove — long-horizon stability is proven only on demand, per the "name what a
test does not prove" rule. See [testing.md](testing.md).

## 5. Testing ownership matrix

| Methodology tier | Owner | Where |
|---|---|---|
| 1 unit | each language | `<lang>/` |
| 2 exact-encoding conformance | each language, shared vectors | `<lang>/` ← `spec/corpus/` |
| 3 source-as-data | each language (impl↔spec coverage checks) | `<lang>/` |
| 4 contract / state machine | each language | `<lang>/` |
| 5 fake-peer fault injection | shared, written once | `interop/` |
| 6 containerized mesh | shared | `interop/` |
| 7 seeded fuzz | shared | `interop/` |
| 8 concurrency/convergence | shared | `interop/` |
| 9 simulated meshes | shared | `interop/` |
| 10 feature-behavior (3.1.0 lifecycle) | shared, in battery | `interop/tier10.sh` |
| 11 long-horizon soak | shared, gated (`BONEMESH_LONG_SOAK`) | `interop/tier11.sh` |

Per-tenant suites stay lean by the portfolio rule: a per-language test exists
only for defects the shared black-box suite cannot see (internal API misuse,
language-level concurrency).

## 6. Documentation workstream (parallel, from Phase 0)

`docs/` accretes continuously; nothing here waits for a phase:

- `decisions.md` — §1, kept current as decisions land (lightweight ADRs).
- `defects.md` — §3, the living registry: found → fixed → gate-verified.
- `spec/` documents (Phase 2) — the core deliverable.
- `security-model.md` — threat model: what is protected against whom; states
  plainly that mesh members trust each other (relays see plaintext payloads)
  unless/until end-to-end payload signing is added; replay, spoofing, DoS
  posture.
- `architecture.md` — routing algorithm, discovery, liveness, with diagrams.
- Per-language quickstarts, as each port lands.
- `testing.md` — how this repo applies reaper's methodology; tenant onboarding;
  how to run the interop suite; how to replay a fuzz seed.
- `migration-v2-v3.md`.

## 7. Reaper integration details

- Seven tenants: six `<lang>/.reaper.toml` + one root `.reaper.toml`
  (interop). Verified against reaper's source: the CLI resolves the tree from
  the manifest's directory (`--manifest` "points at a project rather than just
  at a file"), so this works with no reaper changes.
- Distinct `project` names per manifest (`bonemesh-java`, …, `bonemesh-interop`)
  so sessions never collide.
- Root tenant syncs the whole tree; per-language tenants exclude sibling
  folders via sync excludes.
- Guest strategy — open question §8.2 (one polyglot guest vs. per-language
  guests vs. one guest + per-tenant container images).

## 8. Open questions

1. **Trust/membership model for v3.** Who may join a mesh? Candidates:
   (a) pubkey allowlist distributed out of band — simplest, static;
   (b) mesh root key signing member credentials — CA-like without X.509;
   (c) TOFU with pinning — easiest ops, weakest guarantees. Decided in Phase 2;
   the handshake design accommodates all three.
2. **Guest strategy** for reaper (polyglot guest vs. per-language guests vs.
   container images) — a site-registry decision on the reaper side.
3. **Conformance-runner language** (Rust or Go) — decided at Phase 2 start.
4. **Publishing cadence**: dev removed the Maven Central workflow; decide
   per-ecosystem publishing (Maven, crates.io, npm, hex.pm, Packagist, Go
   module path) at first v3 release, not before.
5. **End-to-end payload protection** (signing/encrypting relayed payloads
   against untrusted relays): explicitly deferred; message format reserves
   room for it.

## 9. Milestone summary

| # | Milestone | Depends on | Size |
|---|---|---|---|
| M0 | Baseline + monorepo restructure + registries seeded | — | S |
| M1 | Java hardened: NodeMap suite, D1/D2/D5/D6 fixed, build modernized, Java tenant green | M0 | M |
| M2 | v2 behavior spec written | M0 | S |
| M3 | v3 spec + security design + corpora + conformance runner | M2 | L |
| M4 | Java on v3, conformant; inspector tool; migration docs | M1, M3 | M |
| M5 | Elixir port conformant + tenant | M4 | M |
| M6 | Interop suite tiers 5–7 running vs Java+Elixir; fuzz continuous | M4 | M |
| M7 | Rust, Go, JS ports (parallelizable) | M4 | L |
| M8 | PHP port | M4, ideally M6 | M |
| M9 | Interop tiers 8–9 + validation gate over all six | M6, M7, M8 | L |

The critical path is M0 → M2 → M3 → M4; everything else fans out from M4.
