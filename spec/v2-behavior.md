# BoneMesh v2 — protocol as implemented

**Status:** descriptive, not normative. **Source of truth:** the `java/`
implementation at the current `main` (post-M1). **Audience:** anyone writing a
v3 spec or a port, who needs to know exactly what v2 does — including the parts
v3 will deliberately change.

This document describes the wire protocol and node behavior *as the code
actually does them today*. Where behavior is a defect, it is described as it
behaves and cross-referenced to [`../docs/defects.md`](../docs/defects.md); the
fix belongs to v3, not to this description. Nothing here should be read as an
endorsement of the design — it is a map of the territory so the v3 delta is
explicit.

> **One M1 caveat about "v2".** M1 left the wire format unchanged except in one
> respect: the key-encapsulation algorithm moved from draft CRYSTALS-Kyber-1024
> to final ML-KEM-1024 (FIPS 203). Their ciphertexts are not interchangeable, so
> a pre-M1 node and a post-M1 node cannot complete key exchange. Everything else
> below held before M1 too.

---

## 1. Transport

- **TCP.** Every message is delivered over its own freshly opened TCP
  connection: connect, write one line, read one line, close. There is no
  connection reuse, keepalive, or multiplexing.
- **Newline-framed.** The sender writes the message with `println` (a single
  `\n`-terminated line) and the receiver reads exactly one line with
  `readLine()`. The message is therefore **one line of UTF-8 JSON with no
  interior newline**. This is the entire framing: there is no length prefix and
  **no maximum size** — a receiver calls `readLine()` on unbounded input
  (defect **D7**).
- **Synchronous request/response.** On the same connection, immediately after
  sending, the client blocks on one `readLine()` for the response. That
  response is always an **ack** (§4.3). The client then closes the socket.
- **Connect timeout.** The client connects with a 5 s timeout (added in M1,
  partial mitigation of D7). There is no explicit read timeout on the response.
- **Server.** A single accept loop spawns one daemon handler thread per inbound
  connection. The handler reads one line, acts on it, writes one ack line back,
  and exits.

Base64 in this protocol uses the standard alphabet **without line breaks**
(BouncyCastle `Base64.encode`). Line breaks would corrupt the newline framing;
a port must ensure its Base64 emits none.

## 2. Message envelope

Every message is a JSON object with these top-level keys:

| Key | Type | Meaning |
|---|---|---|
| `from` | string | Sender's label (self-declared; see D8). |
| `to` | string | Final destination label — not the next hop. Survives rerouting. |
| `action` | string | One of `generic`, `hello`, `ack`. Dispatch key. |
| `payload` | object \| string | Application data. **Object** when cleartext, **string** when encrypted (see §5). |
| `kex` | string | *Optional.* Present only on the first `generic` message to a peer: a Base64 ML-KEM encapsulation establishing the symmetric key. |

`isEncrypted()` is defined structurally: the payload is encrypted iff
`payload` is a JSON **string** rather than an **object**. There is no explicit
flag.

Labels are the sole identity. They are compared **case-insensitively**
throughout, so `Alpha` and `alpha` are the same node.

## 3. Actions

### 3.1 `hello` — discovery / heartbeat

Sent by a node to each of its **direct** neighbors every 5 seconds, and once
immediately when a node is added. Its payload is **always cleartext** (discovery
never carries `kex` and is never encrypted):

```json
{
  "from": "alpha",
  "to": "beta",
  "action": "hello",
  "payload": {
    "port": 8455,
    "nodes": [
      { "node": "gamma", "pubkey": "<base64>", "latency": 12 },
      { "node": "delta", "pubkey": "<base64>", "latency": 40 }
    ]
  }
}
```

- `port` is the **sender's** listening port. The receiver combines it with the
  observed source IP of the connection to learn how to reach the sender back
  (the sender's own advertised address is *not* used; the TCP source address
  is, with a leading `/` stripped).
- `nodes` is what the sender knows — each entry carries the neighbor's label,
  its Base64 public key, and a latency figure (§6). This array is how public
  keys propagate through the mesh (see D8) and how indirect routes are learned.

### 3.2 `generic` — application data

Carries an application payload from `from` to `to`. The payload is **encrypted**
(§5); on the first such message to a given peer it also carries a `kex`:

```json
{
  "from": "alpha",
  "to": "gamma",
  "action": "generic",
  "kex": "<base64 ML-KEM encapsulation>",
  "payload": "<base64 AES-GCM ciphertext+IV>"
}
```

### 3.3 `ack` — response

The response written back on the same connection for **every** inbound message.
An ack is a `generic`-shaped message with `action: "ack"`, addressing flipped
(`from`/`to` swapped relative to the message it answers), and a payload that is
either empty `{}` or `{ "pubkey": "<base64>" }`.

- An ack answering a **discovery** carries the responder's own public key —
  this is how a node that receives a `hello` returns its key to the sender
  (the sender stores it against the responder's label; repaired in M1 as D9).
- An ack answering a relayed message is itself **re-sent onward** by the
  receiving node (`action == "ack"` in the handler triggers `sendDatum(ack)`),
  so acks propagate back along the path — best-effort, unordered, uncorrelated.

There is **no message ID** anywhere in the protocol. An ack cannot be matched to
the specific request that caused it beyond `from`/`to`/`action`; retried or
duplicated messages are indistinguishable (no dedup, no replay protection).

## 4. Node behavior on receipt

The inbound handler branches on the message:

1. **It's an ack** → re-send it onward toward its `to` (`sendDatum(ack)`).
2. **It's a `hello`** → record the sender: set its neighbors/routes from the
   `nodes` array, and either add it (using the observed source IP + advertised
   `port`) or update its address. Attach own pubkey to the ack.
3. **It's a `generic`**:
   - **addressed to us** → if it has `kex`, decapsulate to derive the symmetric
     key; if the payload is encrypted, decrypt it; dispatch the cleartext
     payload to registered `DataListener`s. Dispatch is **synchronous and
     potentially blocking** on the handler thread (a slow listener stalls that
     connection; noted `TODO fix later` in source).
   - **not addressed to us** → `sendDatum(message)`: look the target up and
     re-queue the message to the next hop. This is the relay path.
4. In cases 2–3 the handler then writes its ack back on the connection.

A message whose `to` is unknown both directly and via a route is **dropped**
(the send returns false; nothing is queued, no error propagates to the origin).

## 5. Cryptography (prototype)

v2 carries a working but **pre-standard-security** crypto layer. It is
functional, not trustworthy; v3 replaces the whole thing.

- **Key encapsulation:** ML-KEM-1024 (FIPS 203) via BouncyCastle. On the first
  `generic` message to a peer, the sender encapsulates against that peer's
  advertised public key, producing (a) a shared secret it keeps as an AES key
  under the peer's label and (b) a Base64 encapsulation it sends as `kex`. The
  peer decapsulates to derive the same AES key.
- **Symmetric encryption:** AES-256/GCM/NoPadding. A fresh **12-byte IV** is
  generated per message and **appended after** the ciphertext (which itself
  includes the GCM tag); the concatenation is Base64-encoded into `payload`. A
  reimplementer must match this layout exactly: `Base64( ciphertext‖tag ‖ iv )`,
  IV last, 12 bytes.
- **Key lifetime:** the derived AES key is stored per peer and **never rotated**.
  There is no forward secrecy and no re-keying.

Security properties it does **not** have, all deferred to v3:

- **No authentication of identity (D8).** A node *is* whatever label it claims
  in `from`. Public keys are distributed over **unsigned** discovery traffic and
  acks — trust-on-first-use at best, and MITM-able by anyone on the path, who
  can substitute their own key and relabel freely.
- **No transport confidentiality for discovery.** `hello` messages, including
  the full known-nodes table and every public key in it, travel in cleartext.
- **No replay or reorder protection**, no nonce beyond the per-message IV, no
  message IDs.

## 6. Routing and liveness

- **Two tables.** A node keeps *direct* nodes (label → latency, reachable by a
  socket it holds an address for) and *routes* (label → (via-node, cost)) for
  indirectly-reachable nodes, plus a label → public-key table.
- **Route learning.** Each `hello` a node receives advertises the sender's known
  nodes with latencies; the receiver installs/*improves* a route to each such
  label through the advertising neighbor, cost = advertised latency + latency to
  that neighbor. This is distance-vector-flavored but has no split-horizon,
  poison-reverse, or count-to-infinity guard.
- **Send target selection.** `sendDatum` tries the direct table first, then the
  route table's next-best hop; if neither has the target, the send fails.
- **"Latency" is not RTT (D3).** The stored figure is
  `System.currentTimeMillis() - lastDiscoveryBump`, i.e. time since the last
  5-second heartbeat tick, not a round-trip measurement. Before the first tick
  it is ~epoch-milliseconds-large. M1 added a saturating-sum guard so a dead
  hop's `Long.MAX_VALUE` sentinel can no longer overflow negative and rank as
  the best route; the underlying measure remains meaningless until v3 redefines
  it.
- **Liveness.** A node is marked dead (latency sentinel `Long.MAX_VALUE`) when a
  send to it NAKs. The NAK is attributed to the message's **final destination**,
  not the next hop that actually failed (defect **D4**): a dead *relay* gets the
  *destination* blamed.
- **Broadcast.** `broadcastDatum` sends to every label in the union of the
  direct and route tables, excluding the node's own label (M1 fix, D5).
- **Retry.** A failed send with requeue-on-failure is re-queued on a delay that
  grows exponentially (500 ms → 30 s cap) per consecutive failure (M1 fix, D6),
  via a `DelayQueue`. Pre-M1 it re-queued immediately and busy-looped.

## 7. What v2 has no notion of

Collected here because each is a thing a v3 spec must decide, and a port must
not accidentally invent:

- **Protocol version negotiation.** Nothing on the wire identifies the protocol
  version. Two implementations at different versions have no defined behavior.
- **Message identity / idempotency.** No IDs, no dedup, no replay window.
- **Ordered or reliable delivery.** Acks are best-effort and uncorrelated; there
  is no delivery guarantee and no ordering.
- **Authenticated membership.** Anyone who can open the port is a peer.
- **Bounded input.** No maximum message or field size (D7).
- **End-to-end payload protection across relays.** A relay decrypts nothing (it
  forwards the ciphertext blindly), but the trust model that makes that safe is
  unstated; v3 must decide whether relays are trusted.

---

## Appendix A — worked message examples

**Discovery, alpha → beta (cleartext):**

```json
{"from":"alpha","to":"beta","action":"hello","payload":{"port":8455,"nodes":[{"node":"gamma","pubkey":"MII…","latency":12}]}}
```

**Ack to that discovery, beta → alpha (carries beta's key):**

```json
{"from":"beta","to":"alpha","action":"ack","payload":{"pubkey":"MIIB…"}}
```

**First application message, alpha → gamma (kex + encrypted payload):**

```json
{"from":"alpha","to":"gamma","action":"generic","kex":"BAf…","payload":"3Jd…=="}
```

**Subsequent application message, alpha → gamma (key already established):**

```json
{"from":"alpha","to":"gamma","action":"generic","payload":"9kQ…=="}
```

## Appendix B — defect cross-reference

| Defect | Where it shows up above |
|---|---|
| D3 latency is not RTT | §6, latency bullet |
| D4 NAK mis-attribution | §6, liveness bullet |
| D7 unbounded input / no size limit | §1, §7 |
| D8 unauthenticated identity & key distribution | §3.1, §5 |
| D5, D6, D9 | fixed in M1; described in current (fixed) form in §6 and §3.3 |

See [`../docs/defects.md`](../docs/defects.md) for status and commits.
