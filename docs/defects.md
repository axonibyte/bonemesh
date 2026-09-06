# Known-defect registry

Every defect found by review or testing gets a row here, from discovery through
fix through gate verification. This registry serves double duty:

1. The fix list for hardening work.
2. The **validation-gate corpus** (testing-methodology): once the harness that
   should catch a defect exists, the defect is reverted on a scratch branch and
   the harness must rediscover it before its "gate" box is checked. A suite
   that cannot rediscover a known bug is a suite whose value is unmeasured.

Status: **open** → **fixed** (commit noted) → **gated** (rediscovery verified).

| # | Defect | Where | Kind | Status |
|---|---|---|---|---|
| D1 | `isAlive()` returns true for dead nodes: checks `> -1L` but the dead sentinel is `Long.MAX_VALUE`. | `java/.../node/NodeMap.java` | implementation | fixed (0e9bb5e) |
| D2 | `Node` lacks `equals`/`hashCode` yet is used as a map key: repeated `addNode` with one label leaks duplicate entries; label lookup is nondeterministic. | `java/.../node/Node.java`, `NodeMap.java` | implementation | fixed (eaa8d83) |
| D3 | "Latency" is time since the last global heartbeat bump, not RTT; initial values are ~epoch ms; `Long.MAX_VALUE + advertised` overflows negative, so a route through a dead node can rank best. | `java/.../node/NodeMap.java` | protocol (v3) + implementation | fixed: v3 measures real EWMA RTT (protocol.md §5), and routing withdraws dead neighbors + treats the poison sentinel (≥1e9) as unreachable across all six implementations, so a dead-node route can no longer rank best; gated by interop tiers 8–9. |
| D4 | A NAK marks the message's final destination dead instead of the next hop that actually failed. | `java/.../BoneMesh.java` (`setNodeStatus`) | protocol (v3) | fixed in 3.1.0: all six emit ack/NAK with per-hop failure attribution (protocol.md §7) — a relay that drops a message names itself (ttl/no-route) or the dead next hop (link-dead), never the destination. Unit-tested + mutation-checked in every language (the 3-node ttl NAK test asserts the relay is named), and gated cross-language by interop tier 10 scenario "nak / D4". |
| D5 | Broadcast iterates the indirect-route table only: fresh direct neighbors are missed, and the node's own label can appear as a route (self-broadcast). | `java/.../node/NodeMap.java` (`getAllKnownNodeLabels`) | implementation | fixed (ef8d1e6) |
| D6 | Single-threaded send queue, immediate requeue on failure, no connect timeout: one dead peer head-of-line blocks and busy-loops delivery to the whole mesh. | `java/.../socket/SocketClient.java` | implementation (+ retry/backoff spec'd in v3) | fixed (M1) |
| D7 | Unbounded `readLine()` on untrusted network input; no maximum message size anywhere in the protocol. | `java/.../socket/*` | protocol (v3) | fixed (M4): hard frame caps (16→32 KiB handshake, 64 KiB transport) in the v3 FrameCodec + chunking; M1 connect timeout was the interim mitigation |
| D8 | Crypto prototype distributes public keys over unsigned discovery messages: no identity binding, key exchange is MITM-able. Also used pre-standard round-3 Kyber; the draft algorithm was later removed from BouncyCastle entirely, leaving the engine unable to start. | `java/.../crypto/CryptoEngine.java` | superseded by v3 security layer | fixed: the v3 BMX handshake replaces the prototype entirely — cert-bound identity and mutually-authenticated, forward-secret key agreement (security.md §2–4), with public keys arriving only inside the authenticated handshake, never over unsigned discovery. The v2 unauthenticated-distribution model is gone. |
| D9 | `SocketClient` discarded the ack response and handed listeners the original request; `receiveAck` re-parsed the request as if it were the ack, so a responder's pubkey never reached the requester and encrypted delivery between two fresh nodes could never bootstrap (every send died on a missing key). The `AckMessage(JSONObject, boolean)` constructor also dropped any pubkey on re-parse, breaking relayed acks the same way. | `java/.../socket/SocketClient.java`, `BoneMesh.java`, `message/AckMessage.java` | implementation | fixed (M1) |

Rows D1, D2, D5, D6 are fixed in Java during M1, each with a test that would
have caught it, mutation-checked. Rows marked "protocol (v3)" get their real
fix in the M3 spec; cheap Java mitigations (e.g. a connect timeout) may land
earlier and are noted here when they do.
