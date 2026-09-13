# Migrating from BoneMesh v2 to v3

v3 is a **deliberate clean break**, not a compatible upgrade. A v2 node and a v3
node cannot talk to each other: the wire protocol, the security model, and the
connection model all changed. This note explains what changed and how to move a
deployment across.

## What changed, and why it is incompatible

| | v2 | v3 |
|---|---|---|
| Connection | one TCP connection per message | one long-lived session per neighbor |
| Framing | bare newline, no size limit | newline JSON with hard size caps (defect D7) |
| Identity | self-declared `from` label | ML-DSA-65 keypair; label bound by a root-signed certificate (defect D8) |
| Confidentiality | payload-only, unauthenticated key exchange | full channel encryption from a mutually-authenticated handshake |
| Latency | time since heartbeat tick (meaningless) | real EWMA round-trip time (defect D3) |
| Failure attribution | blamed the destination | blamed the failing hop (defect D4) |
| Loops | unbounded | `ttl` hop limit + poisoned reverse |
| Message identity | none | 128-bit message ids (dedup, ack correlation) |

Because v3 requires a root-signed certificate and a hybrid post-quantum
handshake before any application data flows, there is no configuration that lets
a v2 node join a v3 mesh. Interop was not a design goal; a trustworthy protocol
was.

## Migration path

1. **Stand up a certificate authority.** Use `bonemesh-ca init-root` to generate
   a mesh root keypair offline. Keep `root.priv` off every node; distribute
   `root.pub` (the pin) to all of them.
2. **Issue identities.** For each node, `bonemesh-ca keygen` produces its
   identity keypair and `bonemesh-ca issue` signs its membership certificate.
   Deploy each node with its identity keypair, its certificate, and the pinned
   root public key.
3. **Choose a cutover style.**
   - *Flag day* (simplest): stop the v2 mesh, deploy v3 everywhere, start it.
     Appropriate because the two cannot interoperate anyway.
   - *Bridged* (for staged rollout): run a bridge process that is a v2 node on
     one side and a v3 node on the other, relaying application payloads between
     the two meshes. The bridge is the trust boundary between the encrypted v3
     mesh and the plaintext v2 mesh; document it as such.
4. **Update application code.** The v3 API is `com.axonibyte.bonemesh.v3.Node`:
   `Node.start(label, mesh, rootPublicKey, certificate, identity, port)`,
   `node.connect(host, port)`, `node.send(to, payload)`, and
   `node.addDataListener(...)`. Payloads are still `org.json.JSONObject`.

## Provisioning tooling

The mesh certificate authority is `bonemesh-ca`, a Go command
(`go build -o bonemesh-ca ./cmd/bonemesh-ca` from `go/`). Its subcommands
(`init-root`, `keygen`, `issue`, `verify`) and file formats are unchanged from
the earlier Java `BoneMeshCA` CLI, which has been retired; certificates issued
by either verify interchangeably, so any keys or certs already minted remain
valid. A companion `bonemesh-inspect` decrypts a captured transport stream
against a `BONEMESH_KEYLOG` file for debugging (security.md §8).

## What a v2 user keeps

- JSON application payloads — the object you send is delivered unchanged.
- The label-addressed send model — `send("some-label", payload)`.
- The listener model for receiving delivered payloads.

Everything underneath — identity, encryption, framing, routing metrics — is new.

## Notes for 3.3.0

- **The v2 implementation is no longer in the tree.** Java carried its v2 code
  alongside the v3 port through 3.2.0, including the `CryptoEngine` that is defect
  D8; all 23 files were deleted in 3.3.0, and the jar no longer declares a
  `Main-Class` (it named the v2 entry point, and nothing ever used it). A v2
  deployment that still needs that code should pin a 3.2.0 artifact, which is
  unaffected: nothing in v3 ever referenced it.

- **A 3.2.0 node and a 3.3.0 node do not interoperate for split messages**, and only
  for those. `v` stays 3 and every other pinned vector is unchanged, so handshakes,
  transport frames, routing, acks and whole messages are compatible in both
  directions. What changed is the segment encoding: 3.2.0's Java and Elixir ports
  split an oversized payload into `payload = {"seg": "<base64>"}` at 32000 characters,
  and 3.3.0 uses a 24000-byte UTF-8 text slice in a top-level `seg` (protocol.md
  §6.1, decision #25). That was safe to change precisely because it was never
  specified, never pinned by a vector, and implemented by only two of the seven --
  but a mixed 3.2/3.3 mesh carrying payloads over 64 KiB will drop them, so finish
  the upgrade before sending one.

  Within a single version there is no such caveat: the 49-cell interop matrix sends
  96 KB in every pair.
