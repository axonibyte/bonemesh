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
| Unreachable path cost | advertised as exactly **1000000000**; any advertised cost **≥ 1000000000** is treated as unreachable on receipt (§6) |
| AEAD nonce | 96-bit: 4 zero bytes then the per-direction 64-bit **little-endian** sequence counter; starts at 0, +1 per frame, never reused (matches `security.md` §5 and corpus `transport-frame.json`) |

Operational tunables (local behavior, not the wire contract, so two nodes with
different values still interoperate): heartbeat/probe interval **1 s** (the value
all seven reference nodes use), latency EWMA **α = 0.2**, dedup window **4096**
recent keys per peer, and a retry queue bounded at **64** messages per destination
(§7) so one unreachable peer cannot grow memory without limit. The 3.1.0 features add more, all read once from the
environment at node start and all with defaults chosen so a peer never has to
assume anything about them: `BONEMESH_PROBE_TIMEOUT_MS` (15000), `BONEMESH_IDLE_MS`
(0 = disabled), `BONEMESH_RETRY_BASE_MS`/`_CAP_MS`/`_MAX_MS` (500 / 30000 /
60000; 0 disables retry), `BONEMESH_REKEY_MS`/`_FRAMES`/`_TIMEOUT_MS`
(3600000 / 65536 / 10000), and `BONEMESH_KEYLOG` (unset = off).

A tunable's value is read strictly: an optional sign followed by decimal digits and
nothing else. Anything else — trailing text, digit separators, surrounding
whitespace — is ignored and the default used, rather than partially parsed. Two
implementations were lenient in different directions (one read `12abc` as 12, the
other read `1_000` as 1000), which is the kind of difference that makes an
operator's typo behave differently on different nodes.

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

`seq` is the per-direction nonce counter (also the AEAD nonce input).

**Frames are accepted strictly in order.** A receiver keeps the next expected
`seq` per direction and rejects anything else — including a `seq` ahead of it —
rather than buffering or reordering; the session is then torn down with a
`bye{reason:"protocol-error"}` (§8), because a gap means the stream is no longer
the one the nonce sequence describes. Dropping the frame and keeping the link is
not an option: the expected `seq` only advances on a frame that opens, so a
receiver that continues is left waiting for a `seq` the peer has already moved
past, and the link can never deliver again. The window is exactly one, not a
range. This relies on the ordering TCP already provides, and it is why §9's
"ordered delivery is not guaranteed" is a statement about the *mesh*,
where a message may take different paths between relays, and not about a link.

Every inner plaintext object has a `type`. The routed kinds — `data`, `ack` and
`nak` — also carry a `mid`, as does `rekey`, which uses one to correlate the four
phases of an exchange. The link-local kinds do not: `disco`, `probe` and `echo`
are between neighbours, are never relayed and are never acknowledged, so there is
nothing for an id to correlate, and none of the seven implementations emits one on
them (§4.2 gives each shape). `bye` carries none for the same reason.

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
recently-seen keys per peer (§0) bounds the dedup memory. How a node keys that
window internally — all seven prefix by message kind, so a relayed `ack` cannot be
mistaken for a duplicate of the `data` it answers — is an implementation matter and
not part of the wire contract.

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

### 4.2 Control messages

Every inner type other than `data` is a control message. Before 3.3.0 only `ack`,
`nak` and `bye` had a wire definition anywhere, and `disco`, `probe`, `echo` and
`rekey` had none at all — four of the nine kinds in Appendix A interoperated on a
shape that existed solely as seven agreeing implementations. These are those
shapes; none of them is new.

**`ack` — receipt, routed back toward the origin (§7).**

```json
{ "type": "ack", "mid": "<the id being acknowledged>",
  "to": "alpha", "from": "gamma", "ttl": 16 }
```

`to` is the origin the ack travels back to and `from` is the node sending it, so an
ack is routed exactly like a `data` message. §7 has always said acks are routed
back toward `from`; the routing fields that make that possible were not written
down. A destination sends one ack per application message, on completed reassembly
(§6.1).

**`nak` — non-delivery, naming the hop that failed (§7, defect D4).**

```json
{ "type": "nak", "mid": "<the id that failed>", "hop": "beta",
  "reason": "ttl", "to": "alpha", "from": "beta", "ttl": 16 }
```

`hop` is the node that actually failed — itself for a local drop, the dead
next-hop label for a broken onward link — never the final destination. `reason` is
a short token; `ttl`, `no-route` and `link-dead` are the ones the reference
implementations emit, and a receiver tolerates any other (§8).

**`disco` — reachability and cost, to neighbors (§5, §6).**

```json
{ "type": "disco", "routes": { "gamma": 42, "delta": 1000000000 } }
```

`routes` maps a destination label to this node's advertised path cost in
milliseconds. A cost at or above the unreachable sentinel (§0) withdraws the
route; that is how split-horizon with poisoned reverse is expressed on the wire
(§6). An empty advertisement is `{}`, never `[]`.

**`probe` / `echo` — round-trip measurement (§5).**

```json
{ "type": "probe", "token": 1788600000123 }
{ "type": "echo",  "token": 1788600000123 }
```

`token` is opaque to the responder, which copies it back unchanged in an `echo`.
The prober measures RTT by comparing the returned token against its own clock, so
the value is a local matter — the reference implementations use a millisecond
timestamp. A node echoes any probe; it never interprets the token.

**`rekey` — a tunneled BMX exchange, in four phases (`security.md` §6).**

```json
{ "type": "rekey", "mid": "<exchange id>", "phase": 1,
  "body": "<base64 of the BMX message for this phase>" }
```

The BMX messages of a fresh handshake ride inside transport frames on the live
session, so they arrive through the normal reader with no raw-stream race. `mid`
correlates the four phases of one exchange. `body` carries the BMX bytes and is
**absent on phase 4**, which carries no BMX message:

| Phase | Sender | `body` | Effect |
|---|---|---|---|
| 1 | initiator | `bmx1` | opens the exchange |
| 2 | responder | `bmx2` | replies; responder now holds the new session |
| 3 | initiator | `bmx3` | last frame under the old send key, then the initiator swaps its send key |
| 4 | responder | — | responder has swapped its receive key, sends this, then swaps its send key; on receipt the initiator swaps its receive key and the rekey is complete |

Each side swaps a key immediately after sealing its last old-key frame in that
direction, and swaps its receive key immediately after opening the peer's, so the
two directions cut over independently and no frame is ever sealed under a key the
peer has already discarded. A failed or abandoned exchange leaves the link on its
current keys; liveness (§7) tears it down if it has truly broken.

**`bye` — graceful close (§8).**

```json
{ "type": "bye", "reason": "idle" }
```

`reason` is optional. §8 defines the reasons a conforming sender uses when one
applies; it is not an exhaustive enum, and a receiver accepts any string and acts
on none of them.

## 5. Discovery and latency (defect D3)

v2's "latency" was time since the last heartbeat tick — meaningless (D3). v3
measures **real round-trip time**:

- Periodically, and on session open, a node sends `probe` carrying a local
  timestamp token; the neighbor immediately returns `echo` with the same token.
  The initiator's RTT sample is `now − token_send_time`. The reference nodes
  probe once per **1 s** heartbeat (§0).
- A neighbor's link latency is an **exponentially-weighted moving average** of
  RTT samples (**α = 0.2**, §0), not a single reading, so a transient spike does
  not dominate. It is a real duration in milliseconds, rounded to an integer
  **half away from zero** — so 2.5 ms becomes 3, never 2. That is pinned because
  the rounded value is what `disco.routes` puts on the wire (§4.2): six
  implementations rounded half away from zero and one used banker's rounding, so
  two nodes could advertise costs differing by 1 ms for the same measured link.
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

  The poison value is **exactly 1000000000** and is now pinned (§0), because it
  goes on the wire in `disco.routes` and four of the seven implementations used to
  advertise 2^63-1 instead. That interoperated only by luck of the receive-side
  threshold, and it is not safe luck: 2^63-1 exceeds the largest integer a
  double-precision number represents exactly, so a JSON parser backed by doubles
  reads it as 9223372036854775808 — a different number than the one sent. The
  threshold is set equal to the emitted value on purpose, so a saturated sum is
  indistinguishable from an explicit poison, and mixed-version meshes keep working
  because every receiver has always accepted anything at or above it.
- **Send.** Look up the destination: a live session to it (direct) wins;
  otherwise forward to the best-cost next-hop neighbor over that session. No route
  and no direct session ⇒ the call reports failure to the caller — a real return,
  not a silent drop — **and** the message is queued for bounded retry (§7). Those
  are not alternatives: the boolean answers "was this handed to a next hop now?",
  which is false, while the queue may still deliver it when a route appears. A
  caller that needs to know the outcome rather than the attempt uses the ack
  (§7).
- **Relay** is hop-by-hop: a relaying node decrypts the transport frame from the
  previous hop, and re-encrypts the same inner message (decrementing `ttl`) to
  the next hop's session. This is the trust model of `security.md` §7 — members
  trust each other; a relay sees plaintext.
- **Broadcast** targets every known reachable label except the node's own: every
  peer with a live session, plus every destination with a next hop, compared
  case-insensitively (`security.md` §2) so one peer is never targeted twice.

  It is **not a message type**. A broadcast is N ordinary `data` sends, and each
  destination gets its **own `mid`**. That is forced rather than stylistic: dedup
  keys on (`mid`, chunk index) (§6.1), so a shared `mid` would have the first
  relay that saw one copy suppress every other, and an `ack` names only a `mid`,
  so an origin could not tell which destination had answered. The call reports how
  many destinations the message was handed to a next hop for; each send then
  follows the Send rules above, retry included.

  Both halves of the exclusion are the D5 fix: the node's own label is never a
  target, and direct session peers always are. The v2 implementation iterated
  indirect routes only and could list itself among them.

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
  rather than failing opaquely.
- The **defined** close reasons on the `bye` control (§4.2) are `shutdown` (the
  node is stopping), `idle` (the idle timeout fired, §7) and `protocol-error`,
  plus `unsupported-version` for the version-mismatch case above — which is
  reported in logs rather than sent, because a pre-session rejection has no
  session in which to send a `bye`.

  `protocol-error` names a frame this session cannot carry on from: an oversize
  frame, bytes that are not one JSON object (§2), an AEAD tag that does not
  verify, or a `seq` out of order (§4). Each of those already closes the
  connection; the reason is what turns a dropped socket into a diagnosis. It is
  emitted **before** the close, which a receive-side fault does not prevent —
  keys and counters are per-direction, so the sending half is unaffected.

  It is deliberately **not** emitted for an inner `type` the receiver does not
  recognize, nor for an unknown field: the forward-compatibility rule below
  requires tolerating both, so treating them as errors would make every future
  addition a session-killer.

  There is no `rekey-failed` reason. A rekey that does not complete is specified
  to degrade safely and keep the old keys (`security.md` §6) precisely so that a
  peer which does not implement rekey keeps working; closing the session would
  contradict that guarantee, so no close reason describes it.

  "Defined" is not "exhaustive", and this previously read "the pinned enum …
  (`corpus/messages.json`)", which that file does not pin and deliberately does
  not: a validator that rejected an unknown reason would contradict the
  forward-compatibility rule in the next bullet, and case `bye-ok-unknown-reason`
  expects **valid** for exactly that reason. So a conforming sender uses one of
  the reasons above when one applies, and a conforming receiver accepts any
  string and acts on none of them — the reason is diagnostic, never control.
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
