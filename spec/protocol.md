# BoneMesh v3 — protocol

**Status: normative as of 3.1.0.** Companion to [`security.md`](security.md),
which owns identity, the BMX handshake, and the threat model. This document owns
framing, the connection/session model, message types, discovery, routing, and
the delivery semantics — including the real fixes for the protocol-level v2
defects (D3, D4, D7). The wire contract here is **frozen**: it is implemented by
all seven reference implementations and enforced by the shared corpus (`corpus/`).
Constants formerly marked **[PIN]** are resolved inline against that corpus. The
session-lifecycle and tooling behaviors that 3.0.0 specified but deferred —
simultaneous-dial resolution, retry/backoff, probe-timeout liveness, idle
teardown, session rekey, ack/NAK emission, and the key-log hook — are all
**delivered as of 3.1.0** across every implementation and exercised by interop
tier 10; each is described as live where it appears.

Read [`v2-behavior.md`](v2-behavior.md) first if you need the baseline; this
document is largely a delta against it.

---

## 0. Pinned constants (deterministic wire contract)

These are **frozen** and enforced by the conformance corpus + runner. They do
not depend on a two-party handshake, so they are testable and pinned now.

| Constant | Value |
|---|---|
| Protocol version (`v`) | `3` |
| Frame encoding | one UTF-8 JSON object per line, `\n`-terminated, no interior `\n` |
| Binary-in-JSON encoding | RFC 4648 **standard** Base64, **with** padding, **no** line breaks |
| Handshake frame max | 32768 bytes (including the terminating `\n`); post-quantum certs and signatures are large |
| Transport frame max | 65536 bytes (including the terminating `\n`) |
| `mid` (message id) | 128-bit value, lowercase hex, 32 chars |
| `ttl` default | 16; range 1–255; decremented per relay hop |
| Chunk segment max | 24000 bytes of the payload's UTF-8 serialization, cut on a character boundary (§6.1) |
| Chunk count max (`n`) | 1024 |
| Reassembly buffer max | 16777216 bytes, summed across every in-flight message |
| Concurrent reassemblies max | 256 in-flight messages |
| Reassembly timeout | 30000 ms |
| AEAD nonce | 96-bit: 4 zero bytes then the per-direction 64-bit **little-endian** sequence counter; starts at 0, +1 per frame, never reused (matches `security.md` §5 and corpus `transport-frame.json`) |

Operational tunables (local behavior, not the wire contract, so two nodes with
different values still interoperate): heartbeat/probe interval **1 s** (the value
all seven reference nodes use), latency EWMA **α = 0.2**, dedup window **4096**
recent `mid`s per peer. The 3.1.0 features add more, all read once from the
environment at node start and all with defaults chosen so a peer never has to
assume anything about them: `BONEMESH_PROBE_TIMEOUT_MS` (15000), `BONEMESH_IDLE_MS`
(0 = disabled), `BONEMESH_RETRY_BASE_MS`/`_CAP_MS`/`_MAX_MS` (500 / 30000 /
60000; 0 disables retry), `BONEMESH_REKEY_MS`/`_FRAMES`/`_TIMEOUT_MS`
(3600000 / 65536 / 10000), and `BONEMESH_KEYLOG` (unset = off).

**Delivered in 3.1.0.** The following were specified in 3.0.0 but deferred; they
are now implemented across all seven reference implementations and are backward-
compatible additions (they do not bump `v`): deterministic **simultaneous-dial**
resolution — keep the session whose initiator label is lexicographically lower
(§3); **retry/backoff** on undeliverable messages (§7); probe-timeout-based
**liveness death** and idle **session teardown** (§7, `security.md` §6); periodic
session **rekey** (`security.md` §6); **ack/NAK** emission with per-hop failure
attribution (§7); and the **key-log debug hook** with the `bonemesh-inspect`
tool (`security.md` §8). A peer that predates any of these still interoperates:
unknown inner types are ignored, and every new behavior degrades safely.

---

## 1. What changes from v2, in one breath

v2 opened one TCP connection per message, framed by a bare newline, unencrypted
except for an unauthenticated payload layer, with a self-declared `from`. v3
holds **one long-lived, mutually-authenticated, encrypted session per direct
neighbor**, reuses it for all traffic, bounds every frame, gives every
application message an id, and measures real round-trip latency. Identity and
the handshake are in `security.md`; everything else is here.

## 2. Framing

- The wire is a stream of **newline-terminated UTF-8 JSON lines**, one JSON
  object per line, no interior newline (Base64 fields carry no line breaks).
  This keeps the v2 property that the bytes on the wire are JSON.
- **Every frame has a hard maximum size** (defect **D7**). A reader that has not
  seen a newline within the limit closes the connection rather than growing an
  unbounded buffer. Limits (frozen, §0; corpus `framing.json`):
  - handshake frames: **32 KiB** (a bmx2 with ML-DSA cert + signatures runs near 20 KB);
  - transport frames: **64 KiB**.
- Application payloads larger than a transport frame are **split** by the
  origin into segments and reassembled by the destination (§6.1), so the frame
  cap never limits application data — it only bounds any single read.
- A frame that is not valid JSON, exceeds its limit, or violates the expected
  type for the connection state closes the connection. There is no partial
  recovery within a connection; the session re-handshakes.

## 3. Connections and sessions

- A node keeps at most **one session per neighbor label**. A session is a TCP
  connection plus the transport keys from a completed BMX handshake
  (`security.md` §4).
- On startup or when a route requires a neighbor it has no session to, a node
  **dials** and runs BMX as initiator. Simultaneous dials (both ends open at
  once) are resolved deterministically: the session whose initiator label is
  lexicographically lower is kept, the other torn down, so a pair converges on
  exactly one session. (Implemented across all seven as of 3.1.0; both ends
  compute the same winner, so they agree on which session to drop.)
- After the handshake, both directions send transport frames freely. There is
  no per-message connection setup — the v2 connect/handshake/teardown cost is
  paid once per session, not once per message.
- Sessions rekey and time out per `security.md` §6.

## 4. Transport messages

Every post-handshake frame has the same outer envelope: a sequence-numbered
AEAD-protected carrier. The plaintext inside is itself a JSON object (readable
via the key-log inspector, `security.md` §8):

```json
{ "seq": 42, "ct": "<base64 ChaCha20-Poly1305 ciphertext of the inner JSON>" }
```

`seq` is the per-direction nonce counter (also the AEAD nonce input). The inner
plaintext object always has a `type` and a `mid`:

| Inner `type` | Meaning |
|---|---|
| `data` | An application payload (or one chunk of one). |
| `ack` | Acknowledges a `mid` (delivery/receipt signal). |
| `disco` | Discovery: reachability + measured latencies (§5). |
| `probe` / `echo` | Latency measurement pair (§5). |
| `bye` | Graceful session close. |

`mid` is a **message id**: a 128-bit random value (lowercase hex, 32 chars; §0),
unique per application message (all chunks of one message share it). Message ids
give v3 what v2 never had — **dedup** (a re-delivered (`mid`, chunk index) pair
already seen is dropped; §6.1 says why the index is part of the key) and **ack
correlation** (an `ack` names the `mid` it answers). A replay window of 4096
recently-seen keys per peer (§0) bounds the dedup memory.

### 4.1 Application data

A whole message carries its payload directly:

```json
{ "type": "data", "mid": "<128-bit hex>", "to": "gamma", "from": "alpha",
  "ttl": 16, "chunk": { "i": 0, "n": 1 }, "payload": { ... } }
```

One segment of a split message carries `seg` in its place (§6.1):

```json
{ "type": "data", "mid": "<128-bit hex>", "to": "gamma", "from": "alpha",
  "ttl": 16, "chunk": { "i": 0, "n": 3 }, "seg": "{\"reading\":[1,2,3" }
```

- `to`/`from` are final destination and origin labels (as v2), authenticated —
  `from` is the certificate-bound label of the origin, not a free field.
- `ttl` is a hop limit, decremented at each relay; a message reaching `ttl == 0`
  is dropped and NAKed (§7). This bounds routing loops, which v2 had no guard
  against.
- `chunk` gives this segment's index and the total count. A whole message
  omits `chunk` or sends `n == 1`, and carries `payload`; one segment of a
  split message carries `chunk` with `n > 1` and carries `seg` in place of
  `payload`. **`payload` and `seg` never appear together, and exactly one of
  them is present** — so a node that does not reassemble cannot mistake a
  segment for a complete payload (§6.1).
- `seg` is this segment's slice of the payload's UTF-8 serialization, carried
  as a JSON string. It is not Base64: §0's Base64 rule covers binary fields,
  and a segment is text (decision #25).

## 5. Discovery and latency (defect D3)

v2's "latency" was time since the last heartbeat tick — meaningless (D3). v3
measures **real round-trip time**:

- Periodically, and on session open, a node sends `probe` carrying a local
  timestamp token; the neighbor immediately returns `echo` with the same token.
  The initiator's RTT sample is `now − token_send_time`. The reference nodes
  probe once per **1 s** heartbeat (§0).
- A neighbor's link latency is an **exponentially-weighted moving average** of
  RTT samples (**α = 0.2**, §0), not a single reading, so a transient spike does
  not dominate. It is a real duration in milliseconds.
- `disco` messages advertise, per known destination, the **path cost** = sum of
  per-hop EWMA latencies along the best known path. Because identity and public
  keys now come from the authenticated handshake (`security.md`), discovery no
  longer distributes public keys — it carries reachability and cost only, and it
  travels **inside the encrypted session**, not in cleartext as v2's `hello`
  did.

## 6. Routing and delivery

- **Tables.** As v2: direct neighbors (with measured link latency) and a
  routing table (destination → next-hop neighbor, path cost). Costs are real
  latencies (§5), so "best" is meaningful.
- **Distance-vector with loop guards.** Unlike v2, v3 applies **split-horizon
  with poisoned reverse** (a node does not advertise a route back to the
  neighbor it learned it from, and advertises it as unreachable instead) and the
  `ttl` hop limit (§4.1), together bounding the count-to-infinity behavior v2
  left open.
- **Send.** Look up the destination: a live session to it (direct) wins;
  otherwise forward to the best-cost next-hop neighbor over that session. No
  route and no direct session ⇒ the send fails locally and the caller is told
  (a real return, not a silent drop).
- **Relay** is hop-by-hop: a relaying node decrypts the transport frame from the
  previous hop, and re-encrypts the same inner message (decrementing `ttl`) to
  the next hop's session. This is the trust model of `security.md` §7 — members
  trust each other; a relay sees plaintext.
- **Broadcast** targets every known reachable label except the node's own (the
  v2 M1 fix, D5, now the specified behavior).

### 6.1 Splitting and reassembly

An application payload too large for one transport frame is split by the origin
and reassembled by the destination, so the frame cap (§0) bounds a single read
and never bounds application data (§2).

**Splitting.** The origin serializes `payload` to JSON, takes its UTF-8 bytes,
and cuts them into `n` segments of at most **24000 bytes** (§0), every cut made
on a UTF-8 character boundary so each segment is itself valid UTF-8 and can be
carried in a JSON string. Cutting on a byte budget rather than a character
count keeps the split identical in every language: UTF-8 has no surrogates, so a
code point is either wholly inside a segment or wholly outside it, and the
divergence between counting UTF-16 code units and counting code points — which
`security.md` §11.1 has to legislate for canonicalization — cannot arise here.

**Wire shape.** Every segment is a `data` message (§4.1) sharing one `mid`,
carrying `chunk` as `{"i": <index>, "n": <count>}` with `0 <= i < n`, and
carrying its slice in a top-level **`seg`** string. A segment has **no
`payload`**; a whole message has `payload` and no `seg`. The two are mutually
exclusive, which is what makes the failure mode structurally impossible rather
than merely forbidden: a node that does not reassemble sees a `data` with no
`payload` and rejects it, instead of handing a fragment to the application as
though it were a complete message.

**Reassembly.** The destination buffers segments under their `mid`, concatenates
their `seg` values as UTF-8 bytes in ascending `i`, and parses the result as the
payload. Segments may arrive in any order — §9 does not guarantee ordering, so
out-of-order arrival is the expected case and not an error.

**Dedup.** The duplicate-suppression key is the pair (`mid`, chunk index), not
`mid` alone. Every segment of one message shares that message's `mid`, so a
destination keying on `mid` would discard segments 1..n-1 as already-seen
duplicates and reassembly would never complete — §4's dedup rule read literally
defeats splitting outright. A whole message uses index 0.

**Bounds.** These are wire constants (§0), not local policy, so an origin knows
what every conforming destination will accept. Together they bound destination
memory absolutely, which is the point: splitting exists to lift the frame cap off
application data, and a feature that lifts one bound must not remove every other
one — that is how defect D7 (unbounded reads) would come back wearing a new hat.

A destination rejects a segment whose `chunk` is not an object, whose `i` or `n`
is not an integer, whose `n` is outside 1..1024, or whose `i` is outside 0..n-1,
and it rejects it **before reserving space for `n` segments**, so one frame
cannot make a destination allocate on a number its peer chose. Beyond that:

- **16777216 bytes** of segment data may be buffered at once, summed across
  every in-flight message — not per message. A segment that would carry the
  total past it is refused and its message abandoned. Since `n` cannot exceed
  1024, this is also the largest payload any conforming destination will
  reassemble, so an origin needs no second number.
- **256** messages may be in flight at once. Buffered bytes alone would not
  bound the bookkeeping, because a flood of distinct `mid`s each carrying an
  empty segment costs nothing against a byte budget and still costs memory.
- a partially-filled message is discarded once it is **30000 ms** old, so an
  abandoned message cannot pin memory for the life of the session.

An origin whose payload would need more than 1024 segments, or would exceed the
reassembly buffer, fails the send locally and tells the caller (§6, Send) rather
than emitting a message no conforming destination can accept.

**Relay.** A relay forwards segments individually, decrementing `ttl` at each
hop, and does not reassemble: reassembly is a destination behavior, so a relay
needs no per-message buffer and inherits none of the bounds above.

**Ack.** The destination acks the `mid` once, when reassembly completes — not
once per segment. An `ack` or `nak` (§7) therefore always refers to the whole
application message, never to part of one.

**What this does not provide.** There is no per-segment retransmission. A lost
segment means the message never completes: the destination discards the partial
at the timeout and sends no `ack`, and the origin learns of the failure exactly
as it learns of any unacknowledged message (§7). Reliability stronger than that
is the application's to build, and splitting deliberately does not pretend
otherwise.

## 7. Acknowledgement and liveness (defect D4)

Implemented across all seven as of 3.1.0. The `ack` and `nak` inner types
(schemas in `corpus/messages.json`) are emitted by the reference nodes; a peer
that does not recognize them ignores them (§8), so a mixed-version mesh degrades
safely. The origin observes them through an ack listener; the boolean return of
`send` is unchanged.

- **Receipt acks.** The destination of a `data` message returns an `ack` naming
  its `mid`, routed back toward `from`. Acks are correlated by `mid` (v2 could
  not correlate at all).
- **Failure attribution is per hop (defect D4).** Because each hop is its own
  authenticated session, a delivery failure is attributed to **the specific next
  hop that failed**, never to the final destination. When a relay cannot pass a
  message on it returns a **NAK naming the failing hop, a reason, and the
  `mid`**, which propagates back to the origin: `ttl` (hop limit exhausted, hop =
  the relay itself), `no-route` (no next hop, hop = the relay itself), or
  `link-dead` (the onward write failed, hop = the dead next-hop label). A dead
  relay marks *the relay* dead, not the destination it happened to be carrying a
  message toward. `ack`/`nak` are never themselves ack'd, nak'd, or retried.
- **Liveness.** A neighbor is alive while its session is up and its probes echo;
  it is marked dead when the session drops or when no authenticated frame
  arrives within `BONEMESH_PROBE_TIMEOUT_MS` (default 15 s) — so a peer whose
  socket stays open but has stopped responding is still declared dead. Dead
  neighbors are withdrawn from the routing tables and their routes poisoned to
  neighbors.
- **Retry/backoff.** All seven queue an undeliverable message (no route, or a
  failed first-hop write) per destination and retry it on each heartbeat with
  exponential backoff — 500 ms doubling to a 30 s cap — until it lands or its
  lifetime (`BONEMESH_RETRY_MAX_MS`, default 60 s; 0 disables) is spent, at which
  point the origin is told via a synthesized `nak{reason:"expired"}` on its ack
  listener. One dead peer never busy-loops or head-of-line-blocks the rest, and
  `send`'s boolean is unchanged (queueing is additive).

## 8. Versioning and negotiation

- The handshake carries `v: 3` (`security.md` §4). A node that receives a
  handshake with a `v` it does not implement rejects it, closing the connection,
  rather than failing opaquely. The machine-readable close reasons are the
  pinned enum on the `bye` control (`corpus/messages.json`): `shutdown`, `idle`,
  `rekey-failed`, `protocol-error`, plus `unsupported-version` for this
  version-mismatch case (reported in logs; a pre-session rejection carries no
  session in which to send a `bye`).
- Minor, backward-compatible additions (new optional inner `type`s, new optional
  fields) do **not** bump `v`; an implementation ignores inner types it does not
  recognize, except that an unrecognized `type` where a `data` message is
  expected is an error. Wire-breaking changes bump `v`.
- This is the thing v2 had no notion of; it exists so two implementations at
  different versions have defined behavior instead of undefined.

## 9. Explicit non-goals for v3 (carried from v2 §7, now decided)

- **Ordered delivery** is not guaranteed. `mid` gives dedup and correlation, not
  sequencing across different messages. Applications needing ordering layer it
  themselves.
- **End-to-end confidentiality across relays** is not provided (decision #13,
  `security.md` §7). The `data` envelope reserves room for a future end-to-end
  field, but v3 relays see plaintext.
- **Reliable delivery** is best-effort with acks and bounded retry, not a
  guarantee.

---

## Appendix A — message-type quick reference

| Context | Frame `t`/inner `type` | Encrypted | Direction |
|---|---|---|---|
| handshake | `bmx1` | no (ephemerals only) | initiator → responder |
| handshake | `bmx2` | identity fields encrypted | responder → initiator |
| handshake | `bmx3` | identity fields encrypted | initiator → responder |
| transport | `data` | yes | any, routed |
| transport | `ack` / `nak` | yes | back toward origin |
| transport | `rekey` | yes (a tunneled BMX exchange, phases 1–4) | initiator ↔ responder |
| transport | `disco` | yes | to neighbors |
| transport | `probe` / `echo` | yes | neighbor pair |
| transport | `bye` | yes | session close |

## Appendix B — v2 defect resolution

| Defect | v2 behavior | v3 resolution |
|---|---|---|
| D3 | latency = time since heartbeat tick | real EWMA RTT via probe/echo (§5) |
| D4 | NAK blames final destination | per-hop failure attribution (§7) |
| D7 | unbounded `readLine` | hard frame-size caps + chunking (§2) |
| D8 | self-declared `from`, unsigned keys | cert-bound identity (`security.md`) |
| — (new) | no message ids / dedup / versioning / loop guard | `mid` (§4), `v` negotiation (§8), `ttl` + poisoned reverse (§6) |
