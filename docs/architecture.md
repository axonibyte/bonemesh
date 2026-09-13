# BoneMesh Architecture & Technical Guide

This document explains how BoneMesh v3 is built: the repository shape, the
protocol stack, the cryptography, the routing algorithm, and the cross-language
testing regime. It is a map and a rationale, not the normative spec — where a
byte-level detail matters, [`spec/protocol.md`](../spec/protocol.md) and
[`spec/security.md`](../spec/security.md) are authoritative, and the shared
vectors in [`spec/corpus/`](../spec/corpus/) are the ground truth every
implementation is checked against.

For the roadmap and the fixed design decisions see
[`PLAN.md`](PLAN.md) and [`decisions.md`](decisions.md); for the v2→v3 defect
resolutions see [`defects.md`](defects.md) and
[`migration-v2-v3.md`](migration-v2-v3.md).

---

## 1. Shape of the project

BoneMesh is a super-repo: one specification, six conforming implementations, and
a shared test harness.

| Folder | Contents |
|---|---|
| `spec/` | The normative protocol (`protocol.md`), security design (`security.md`), the shared test corpus (`corpus/`), and a Go conformance runner (`conformance/`). |
| `java/` | The Java implementation — the original library and the v3 reference. |
| `go/`, `rust/`, `js/`, `php/`, `elixir/`, `python/` | The other six full implementations. |
| `interop/` | The multiprotocol test harness: the corpus-check runner, tier 3, the live matrix, tiers 5–10 (plus the gated tier 11 soak), and the neutral per-language node drivers. |
| `ci/` | `test-impl.sh`, the single source of truth for how each implementation is tested; driven by `bitbucket-pipelines.yml`. |
| `docs/` | This guide, the user guide, the plan, and the decision/defect registries. |

**The governing principle is wire-compatibility, not shared code.** Each
implementation is written natively in its language against the spec and the
corpus; nothing is generated or shared between them. A node must not care what
implementation answers on the other side, only that the protocol is obeyed — so
the harness drives every implementation as a black box and never contains
per-language logic.

Each language folder is its own [reaper](https://github.com/calebpower/reaper)
tenant (`<lang>/.reaper.toml`) that builds and tests it hermetically in a
digest-pinned container; a root tenant (`/.reaper.toml`, `bonemesh-interop`)
runs the whole interop suite on a networked Linux guest.

---

## 2. The protocol stack

A node is layered. Bottom to top:

**Framing** (`protocol.md` §2). One UTF-8 JSON object per line, newline
terminated, no interior newline, within a hard size cap (32 KiB handshake / 64
KiB transport — the cap is defect D7's fix against unbounded input). The frame
classifier's verdicts (accept, or a reason: `no-newline`, `empty`,
`invalid-json`, `trailing-data`, `not-an-object`, `invalid-utf8`, `oversize`)
are frozen in `spec/corpus/framing.json`.

**Handshake — BMX** (`security.md` §4). A three-message, mutually authenticated,
forward-secret exchange shaped like Noise XX:

- **bmx1** (initiator→responder, cleartext): ephemeral X25519 public key,
  ephemeral ML-KEM-768 encapsulation key, a nonce, the mesh id, version.
- **bmx2** (responder→initiator): responder's ephemeral X25519 key, the ML-KEM
  ciphertext, and an encrypted **auth** payload (the responder's membership
  certificate plus an ML-DSA-65 signature over the running transcript hash).
- **bmx3** (initiator→responder): the initiator's encrypted auth payload.

Forward secrecy is **hybrid**: the session key mixes both an X25519
Diffie-Hellman secret and an ML-KEM-768 encapsulated secret, so it stays secret
unless *both* the classical and the post-quantum problem are broken.
Authentication is a root-signed certificate plus a live-transcript signature,
which defeats certificate replay.

**Key schedule** (`security.md` §5). A Noise-style symmetric state carrying a
transcript hash `h` and chaining key `ck`, seeded from a pinned protocol name.
`mixHash` folds data into `h`; `mixKey` derives a fresh key + chaining key via
HKDF-SHA-256 (DH first, then KEM); `encryptAndHash`/`decryptAndHash` use
ChaCha20-Poly1305 with `h` as AAD and a 4-zero-byte + little-endian-64-bit-counter
nonce; `split` derives the two directional transport keys. Its known-answer
vector is `spec/corpus/transcripts/keyschedule.json` — every implementation
reproduces it byte-for-byte.

**Transport** (`protocol.md` §4). Over a completed handshake, each frame is a
sequence-numbered AEAD carrier `{"seq":n,"ct":"<base64>"}` whose plaintext is the
inner JSON message. The per-direction sequence is the nonce; reordered or
replayed frames are rejected.

**Messages** (`protocol.md` §4, Appendix A). Inner message types: `data` (with
`mid`, `from`, `to`, `ttl`, `payload`, optional `chunk`), `ack`, `disco` (route
advertisement), `probe`/`echo` (liveness/RTT), `bye`. Schema-validation verdicts
are frozen in `spec/corpus/messages.json`.

**Routing** (`protocol.md` §5–6). See §4 below.

---

## 3. Cryptography

All primitives use raw FIPS/RFC encodings so keys, ciphertexts, and signatures
are byte-identical across implementations:

| Purpose | Primitive |
|---|---|
| Node identity | ML-DSA-65 (FIPS 204) |
| Mesh root | ML-DSA-87 (FIPS 204) |
| Key establishment | X25519 + ML-KEM-768 (FIPS 203), hybrid |
| AEAD | ChaCha20-Poly1305 (RFC 8439, IETF/96-bit nonce) |
| Hash / KDF | SHA-256, HKDF-SHA-256 (RFC 5869) |

Each implementation sources these from what its ecosystem provides best; the
wire encodings are what matters, not the library:

| Impl | Classical + hash/AEAD | Post-quantum (ML-KEM / ML-DSA) |
|---|---|---|
| Java | BouncyCastle | BouncyCastle |
| Elixir | OTP `:crypto` | OTP `:crypto` (native, OTP 28) |
| Rust | RustCrypto / dalek | RustCrypto `ml-kem` / `ml-dsa` |
| Go | stdlib (`crypto/ecdh`, `crypto/mlkem`, `x/crypto`) | stdlib `crypto/mlkem` + Cloudflare CIRCL for ML-DSA |
| JS | Node built-in `crypto` (OpenSSL 3.5) | Node `crypto` (native ML-KEM/ML-DSA) |
| PHP | libsodium | the `openssl` 3.5 CLI, shelled out |
| Python | `cryptography` (OpenSSL 3.5) | `cryptography` (native ML-KEM/ML-DSA) |

**Private-key format is a non-issue by design.** Implementations store private
keys differently (BouncyCastle expands ML-DSA/ML-KEM keys; RustCrypto, Go, Node,
Python's `cryptography`, and OpenSSL keep the seed). It never affects interop because a private key never
crosses a node boundary — only public keys, ciphertexts, and signatures do, and
those are the standard encodings that all seven match. Cross-language PQC is proven
by the shared vector `spec/corpus/transcripts/pqc-interop.json` and, for the
seed-keyed implementations, by the live matrix.

**Certificate canonicalization** (`security.md` §11.1). The exact bytes the root
signs are a restricted JSON Canonicalization: members sorted by UTF-16 code unit,
`sig` removed, minimal string escaping, non-negative integers in shortest form.
Vectors: `spec/corpus/canon.json`.

---

## 4. Routing

All six nodes run the same distance-vector routing (`protocol.md` §5–6),
wire-compatible across languages.

**State.** Per node: a table of direct **neighbors**, each with an
EWMA-smoothed link latency (alpha 0.2), and a table of learned **routes**
(`destination → { via next-hop, cost in ms }`).

**Discovery.** Every 1 s a node sends each neighbor a `probe` carrying a
send-time timestamp; the neighbor echoes it back, and the difference is folded
into that link's latency. In the same heartbeat it sends each neighbor a `disco`
advertisement — a map of destination → path cost — computed per-neighbor with
**split-horizon poisoned reverse**: a route learned *via* a neighbor is
advertised back to that neighbor as unreachable, which prevents two-hop loops.

**Learning.** On a `disco`, for each advertised `(dest, cost)` a node either
installs the route (if new, a refresh from the current next hop, or strictly
cheaper), or — if the cost is the unreachable sentinel — withdraws its route to
`dest` if that route ran through the advertising neighbor. Cost is
`advertised + neighborLatency(via)`, saturating.

**Relay.** A `data` message addressed to another label is forwarded toward
`nextHop(to)` with its TTL decremented (default 16); it is dropped silently on
TTL exhaustion or if there is no route. A message addressed to the node itself is
delivered to the application listeners. A bounded **dedup** set (keyed by message
id + chunk index) drops duplicates and breaks loops. A dropped link withdraws all
routes through it, and the mesh re-converges onto any surviving path.

Two subtleties are worth calling out because they are easy to get wrong and both
were found and fixed during cross-language convergence testing:

- **Poison sentinel.** The "unreachable" cost that crosses the wire must be
  recognized by every receiver even though implementations emit different values
  (Java emits `Long.MAX_VALUE`; Elixir and JS emit `1_000_000_000` — a JS number
  cannot hold `MAX_VALUE` exactly). The convention is therefore: **emit the
  largest value your language holds, and on receipt treat any cost ≥ 1e9 as
  unreachable.** Real millisecond path costs never approach that.
- **Never shadow a direct neighbor with a learned route.** If a node installs a
  learned route to a destination that is also a direct neighbor, it will
  poisoned-reverse that neighbor back to the route's source and clobber the
  legitimate neighbor advertisement — so a diamond topology fails to heal after a
  relay is killed. `learnRoute` therefore ignores any destination that is already
  a direct neighbor.

---

## 5. Testing and interop

Testing follows a portfolio of oracles (reaper's `testing-methodology.md`): each
tier exists for a defect no cheaper tier can see.

**Per-implementation (tiers 1, 2, 4), in each `<lang>/`:** unit tests;
exact-encoding conformance mirrored from the shared corpus; contract /
state-machine tests. New assertions are mutation-checked (break the code, confirm
the test fails, restore).

The byte-exact corpus comparison cannot live in a `<lang>/` tenant, because a
tenant syncs one subtree and cannot see `spec/corpus` — it lives in
`interop/check-<family>[-<impl>].sh`, run by `interop/run-corpus-checks.sh`, which
also re-runs every family under a hostile non-UTF-8 default charset.

**Tier 3 (source-as-data) is shared, not per-language:** `spec/conformance/cmd/specsrc`
reads `spec/protocol.md` and `spec/security.md` as markdown and checks every
implementation's constants, tunable names and message types against them, in both
directions. One tool, all seven targets, because the question is identical in each
language — and it needs the whole repository, so it runs from
`interop/check-spec.sh`.

**Shared, in `interop/` (tiers 5–10, plus the gated tier 11 soak), written once and driving every
implementation as a black box:**

- **Matrix** (`run-matrix.sh`) — every (responder, initiator) pair, both
  directions, all languages, completing a real handshake + transport + delivery.
- **Tier 5** (`tier5.sh`) — node vs. a fake peer that injects deterministic
  faults (garbage, oversize, truncated frames, wrong-mesh bmx1, aborted/tampered
  handshakes, corrupted transport). Oracle: nothing spurious is delivered and the
  node survives (self-tested by a final valid control).
- **Tier 6** (`tier6.sh`) — a mesh under netem latency + loss, plus an
  iptables partition-and-heal. Linux/`tc`-only.
- **Tier 7** (`tier7.sh`) — replayable seeded fuzzing (seed printed, accepted via
  `BONEMESH_FUZZ_SEED`) over frames, handshake messages, and transport.
- **Tier 8** (`tier8.sh`) — concurrency/convergence: a mixed-language diamond,
  continuous sends, a relay killed, asserting the routing state converges off the
  dead relay and delivery heals over the alternate path. The oracle is
  self-tested against a known-bad routing dump first.
- **Tier 9** (`tier9.sh`) — a seeded simulated mesh with nemesis operations
  (kills, restarts, foreign-root intrusions), asserting authenticated-only
  delivery, no fabrication, delivery, and survival. Self-tested first.

**The neutral driver contract.** The harness discovers `interop/drivers/*.sh` and
pairs them without knowing which is which. Each driver speaks four subcommands —
`keygen`, `listen`, `connect`, `mesh` — over implementation-independent key and
certificate files. Adding an implementation to every shared test is just dropping
a new `drivers/<name>.sh`. Some tiers self-adapt: they health-probe each driver
and log any skip (e.g. the interop guest lacks Erlang/OTP 28, so Elixir is
skipped there and covered by the driver instead), never silently narrowing.

Tiers 10–11 (long-horizon soak, human-reviewed transcripts) are named future
work, per the plan.

---

## 6. Adding an implementation

The recipe, mirrored by the six non-reference ports — most recently Python, and
this is the order that actually worked:

1. Build the layers against the spec, tier by tier, checking each against the
   shared corpus as you go: canonicalization (`canon.json`), key schedule
   (`transcripts/keyschedule.json`), hybrid agreement
   (`transcripts/handshake-agreement.json`), framing (`framing.json`), message
   schema (`messages.json`), transport frame
   (`transcripts/transport-frame.json`), and PQC
   (`transcripts/pqc-interop.json`). Write the node last: handshake → transport →
   message → routing.
2. Follow the wire conventions exactly — the pinned constants, the poison
   sentinel rule, the neighbor-shadow guard, empty route maps encoded as `{}` not
   `[]`, labels compared case-insensitively. And follow the *shipped* wire where
   it diverges from the spec prose: `bmx2`/`bmx3` carry one sealed `auth` member
   rather than separate `cert` and `sig`, and the transcript absorbs individual
   field values in order rather than raw wire bytes.
3. Write the unit suite with the corpus vectors **mirrored in code** (a tenant
   cannot see `spec/`), each module's test file naming the corpus file it mirrors.
   Mutation-check every assertion.
4. Add a `<lang>/.reaper.toml` tenant (digest-pinned image, offline/vendored build
   where possible). If the port needs third-party dependencies, gate their
   licences too — BoneMesh is Apache-2.0, so a copyleft transitive dependency is
   disqualifying (see `python/tools/check_licenses.py`).
5. Add the seven `interop/check-<family>-<name>.sh` wrappers and the entry points
   they drive. `interop/run-corpus-checks.sh` discovers them and **fails** on a
   missing one, so there is no way to half-finish this step quietly.
6. Drop an `interop/drivers/<name>.sh` speaking the neutral contract; it joins the
   matrix and tiers 5–10 automatically. Put nothing else in `drivers/` — that
   directory is the implementation registry, and a helper dropped there is
   discovered as a language.
7. Add the language to `impls` in `spec/conformance/cmd/specsrc/main.go` (tier 3),
   a case to `ci/test-impl.sh` and a step to `bitbucket-pipelines.yml`, and its
   toolchain to `interop/guest-setup.sh` — or document the omission there the way
   Elixir's is documented.

---

## 7. Known limitations

- Trust is hop-by-hop; there is no end-to-end payload encryption in v3 (a
  deliberate non-goal — `security.md` §7, decision #13). This is explicit future
  scope, not a deficiency: the `data` envelope reserves room for a future
  end-to-end layer.
- Tier 6 requires Linux `tc`/netem + iptables, so it runs on the interop guest,
  not the FreeBSD driver; Tier 8 needs at least two routing implementations
  present. Both skip loudly where their prerequisites are absent.
- The long-horizon soak (tier 11) is gated behind `BONEMESH_LONG_SOAK` and run
  per release, not in the standard battery; see [`testing.md`](testing.md).
- **Splitting is specified and implemented in all seven** as of 3.3.0
  (`protocol.md` §6.1, defect D11 closed). An origin splits a payload larger than a
  transport frame into segments sharing one `mid`, each carrying `chunk: {i, n}` and
  a top-level `seg`, and the destination reassembles. Every bound is pinned in §0 and
  enforced before allocation. The 49-cell interop matrix sends a 96 KB payload in
  every cell, so the cuts are proven to land in the same places in all seven
  (`spec/corpus/chunk.json`) and the round trip is proven pair by pair.

  This row previously read "chunking is Java-only", which was wrong twice over:
  Elixir implemented it too, with the same undocumented encoding, and what the six
  non-Java ports actually did with a Java or Elixir segment was deliver the fragment
  to the application as a complete payload — silent corruption rather than the clean
  failure described here. Both facts are recorded in D11.
