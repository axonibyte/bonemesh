# BoneMesh v3 — protocol

**Status: DRAFT for review.** Companion to [`security.md`](security.md), which
owns identity, the BMX handshake, and the threat model. This document owns
framing, the connection/session model, message types, discovery, routing, and
the delivery semantics — including the real fixes for the protocol-level v2
defects (D3, D4, D7) that M1 could only guard against in Java. Constants marked
**[PIN]** freeze with the Go reference implementation and corpus.

Read [`v2-behavior.md`](v2-behavior.md) first if you need the baseline; this
document is largely a delta against it.

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
  unbounded buffer. Limits `[PIN]`:
  - handshake frames: **16 KiB** (ample for ML-DSA certs + signatures);
  - transport frames: default **64 KiB**, configurable up to a ceiling.
- Application payloads larger than a transport frame are **chunked** by the
  origin (§6) and reassembled by the destination, so the frame cap never limits
  application data — it only bounds any single read.
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
  lexicographically lower is kept `[PIN]`, the other torn down, so a pair
  converges on exactly one session.
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

`mid` is a **message id**: `[PIN]` a 128-bit random value, unique per
application message (all chunks of one message share it). Message ids give v3
what v2 never had — **dedup** (a re-delivered `mid` already seen is dropped) and
**ack correlation** (an `ack` names the `mid` it answers). A replay window of
recently-seen `mid`s per peer bounds the dedup memory `[PIN]`.

### 4.1 Application data

```json
{ "type": "data", "mid": "<128-bit hex>", "to": "gamma", "from": "alpha",
  "ttl": 16, "chunk": { "i": 0, "n": 1 }, "payload": { ... } }
```

- `to`/`from` are final destination and origin labels (as v2), authenticated —
  `from` is the certificate-bound label of the origin, not a free field.
- `ttl` is a hop limit, decremented at each relay; a message reaching `ttl == 0`
  is dropped and NAKed (§7). This bounds routing loops, which v2 had no guard
  against.
- `chunk` gives this chunk's index and the total count; `n == 1` for
  unchunked messages.

## 5. Discovery and latency (defect D3)

v2's "latency" was time since the last heartbeat tick — meaningless (D3). v3
measures **real round-trip time**:

- Periodically, and on session open, a node sends `probe` carrying a local
  timestamp token; the neighbor immediately returns `echo` with the same token.
  The initiator's RTT sample is `now − token_send_time`. `[PIN]` probe interval.
- A neighbor's link latency is an **exponentially-weighted moving average** of
  RTT samples `[PIN α]`, not a single reading, so a transient spike does not
  dominate. It is a real duration in milliseconds.
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

## 7. Acknowledgement and liveness (defect D4)

- **Receipt acks.** The destination of a `data` message returns an `ack` naming
  its `mid`, routed back toward `from`. Acks are correlated by `mid` (v2 could
  not correlate at all).
- **Failure attribution is per hop (defect D4).** Because each hop is its own
  authenticated session, a delivery failure is attributed to **the specific next
  hop that failed**, never to the final destination. When a relay cannot pass a
  message on (next-hop session dead, `ttl == 0`), it returns a **NAK naming the
  failing hop and the `mid`**, which propagates back to the origin. A dead relay
  now marks *the relay* dead, not the destination it happened to be carrying a
  message toward.
- **Liveness.** A neighbor is alive while its session is up and its probes echo;
  it is marked dead when the session drops or probes time out `[PIN]`. Dead
  neighbors are withdrawn from the routing tables and their routes poisoned to
  neighbors.
- **Retry/backoff.** Undeliverable messages with retry requested follow the
  exponential bounded backoff introduced in M1 (D6): 500 ms doubling to a 30 s
  cap `[PIN]`, per destination, so one dead peer never busy-loops or
  head-of-line-blocks the rest.

## 8. Versioning and negotiation

- The handshake carries `v: 3` (`security.md` §4). A node that receives a
  handshake with a `v` it does not implement rejects it with a defined
  `unsupported-version` close reason `[PIN]` rather than failing opaquely.
- Minor, backward-compatible additions (new optional inner `type`s, new optional
  fields) do **not** bump `v`; an implementation ignores inner types it does not
  recognize, except that an unrecognized `type` on a `data`-bearing frame is an
  error `[PIN]`. Wire-breaking changes bump `v`.
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
| transport | `ack` / NAK | yes | back toward origin |
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
