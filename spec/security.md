# BoneMesh v3 — security design

**Status: DRAFT for review.** This is a design, not a ratified spec. The
construction is deliberately conventional — it is a reassembly of well-analyzed
parts (hybrid X25519+ML-KEM key agreement, ML-DSA certificate identity, a
Noise-style key schedule, ChaCha20-Poly1305) rather than novel cryptography.
Bit-level constants marked **[PIN]** are settled when the Go reference
implementation and the shared corpus are built (next M3 unit); changing them
after that is a wire break. Review the *design* here before that happens.

Companion document: [`protocol.md`](protocol.md) (framing, connections,
routing). This document owns identity, membership, the handshake, and the
threat model.

---

## 1. Cryptographic primitives

| Role | Primitive | Notes |
|---|---|---|
| Node identity signatures | **ML-DSA-65** (FIPS 204, category 3) | A node *is* its ML-DSA public key; the label is a display name bound by the cert. |
| Mesh root signatures | **ML-DSA-87** (FIPS 204, category 5) | The root is high-value and offline; it gets the strongest parameter set. |
| Ephemeral key agreement | **X25519** *and* **ML-KEM-768** (FIPS 203), hybrid | Both shared secrets are mixed; security holds if *either* primitive holds. Mirrors TLS `X25519MLKEM768`, Signal PQXDH, Rosenpass. |
| AEAD | **ChaCha20-Poly1305** | 256-bit key, 96-bit nonce. Uniformly available and constant-time in software across all six languages. |
| Hash / KDF | **SHA-256** / **HKDF-SHA-256** | Ubiquitous; no BLAKE dependency to source six times. |
| Canonical bytes for signing | **RFC 8785 JCS** | JSON Canonicalization Scheme — keeps certificates human-readable while giving a single deterministic byte string to sign. |

**Why hybrid, not PQ-only.** ML-KEM and ML-DSA implementations are young. Binding
the channel's forward secrecy to X25519 *and* ML-KEM means a break or a bad
implementation of one does not drop the mesh below the other's guarantee. The
cost is one extra ephemeral exchange per handshake, paid once per session.

## 2. Identity

A node's identity is an **ML-DSA-65 keypair**, generated once and persisted. The
public key is the identity; the private key never leaves the node. The
human-facing `label` is not identity — it is an attribute the membership
certificate binds to the identity key, and it is compared case-insensitively
(as in v2).

This closes v2's root defect (**D8**): in v2 a node *was* whatever label it
typed into `from`. In v3, a label is only as trustworthy as the certificate that
binds it to a key the mesh root vouched for.

## 3. Membership certificates

A mesh has a **root ML-DSA-87 keypair**. The private root key is generated
offline by a bundled CLI (`bonemesh-ca`), kept off every node, and used only to
sign member certificates. Every node is configured with the root **public** key,
pinned; that pin is the mesh's trust anchor.

A **membership certificate** is a JSON object (readable, per the project's
design value):

```json
{
  "v": 3,
  "mesh": "acme-prod",
  "label": "alpha",
  "idk": "<base64 ML-DSA-65 public key>",
  "nbf": 1788500000,
  "exp": 1790000000,
  "sig": "<base64 ML-DSA-87 signature by the root>"
}
```

- `mesh` is the mesh identifier; a certificate is valid only within its mesh.
- `idk` is the node's identity public key.
- `nbf` / `exp` are Unix seconds; a certificate is valid only within the window.
  Short windows are the primary revocation mechanism — a compromised node stops
  being a member when its cert expires and the root declines to re-sign.
- `sig` is the root's ML-DSA-87 signature over **`JCS(certificate without the
  `sig` field)`**. `[PIN]` the exact pre-image (field set and JCS profile) is
  frozen with the corpus.

**Verification** (performed on every peer's certificate during the handshake):

1. `v == 3` and `mesh` equals this node's configured mesh id.
2. Current time is within `[nbf, exp]`.
3. `sig` verifies over `JCS(cert \ sig)` under the **pinned root public key**.
4. (Binding to the live handshake — see §4: the peer must prove possession of
   the private key for `idk`, so a replayed certificate alone is not identity.)

An optional **revocation list** (a root-signed JSON list of revoked `idk`s with
an issue time) may be distributed and checked at step 3.5; it is not required
for v3 correctness and is specified as an extension, not a mandate.

## 4. The handshake (BMX)

**BMX** (BoneMesh eXchange) is a three-message, mutually-authenticated,
forward-secret handshake. Its *shape* is Noise `XX` (both parties present a
long-term identity only after an ephemeral channel exists); its *authentication*
is by certificate-and-signature rather than by raw static-key DH, because
identity here lives in root-signed certificates, not bare keys. Its *secrecy* is
the hybrid of an X25519 ephemeral-ephemeral DH and an ML-KEM ephemeral
encapsulation.

Notation: `e_i`/`e_r` are ephemeral X25519 keys; `k_i` is the initiator's
ephemeral ML-KEM encapsulation (public) key; `ct` is an ML-KEM ciphertext;
`h` is the running transcript hash; `ck` is the chaining key; `ENC`/`DEC` are
ChaCha20-Poly1305 with the current handshake key and `h` as associated data.

Each handshake message is a **cleartext JSON line** (§ protocol.md framing).
Ephemeral public values are Base64. Certificates and signatures in messages 2
and 3 are carried **inside `ENC(...)`** — encrypted under keys derived from the
ephemeral exchange, so identities are not exposed to a passive observer.

### Message 1 — initiator → responder (cleartext)

```json
{ "t": "bmx1", "v": 3, "mesh": "acme-prod",
  "e": "<base64 X25519 e_i>",
  "k": "<base64 ML-KEM-768 encapsulation key k_i>",
  "n": "<base64 32-byte fresh random>" }
```

`n` is a fresh nonce ensuring transcript uniqueness (anti-replay of the whole
handshake). The responder rejects `mesh` mismatch or `v != 3` immediately.

### Message 2 — responder → initiator

The responder generates `e_r`, computes:

- `ss_dh = X25519(e_r, e_i)`
- `(ss_kem, ct) = ML-KEM.Encaps(k_i)`

mixes both secrets into the key schedule (§5), derives handshake keys, then
sends its ephemerals in the clear and its identity **encrypted**:

```json
{ "t": "bmx2",
  "e": "<base64 X25519 e_r>",
  "ct": "<base64 ML-KEM ciphertext>",
  "cert": "<base64 ENC(responder membership certificate JSON)>",
  "sig":  "<base64 ENC(ML-DSA-65 signature by responder over h)>" }
```

`sig` is the responder's signature over the transcript hash `h` *as of the point
just before the signature is added* (a TLS-1.3-style CertificateVerify). It
proves the responder holds the private key for the `idk` in its certificate,
binding the certificate to this live session and defeating certificate replay.

### Message 3 — initiator → responder

The initiator now has `e_r` and `ct`, computes the same `ss_dh`/`ss_kem`,
derives the same keys, verifies the responder's certificate (§3) and signature,
then sends its own identity, encrypted:

```json
{ "t": "bmx3",
  "cert": "<base64 ENC(initiator membership certificate JSON)>",
  "sig":  "<base64 ENC(ML-DSA-65 signature by initiator over h)>" }
```

The responder verifies. On success both sides derive **transport keys** (§5) and
the session is open. Either side may send application traffic immediately after
it has both sent and received a valid message 3 / would-send message 3.

**Authentication outcome.** Each side ends holding: a certificate that chains to
the pinned root (member), bound to an identity key that just signed this
session's transcript (live possession), for a peer that agreed on the same
hybrid secret (channel binding). Impersonation requires either the root key, the
peer's identity private key, or breaking both X25519 and ML-KEM.

## 5. Key schedule

A Noise-style symmetric state carries `(ck, h)`. `[PIN]` HKDF labels and the
exact `MixKey`/`MixHash` sequence freeze with the corpus; the structure:

- `MixHash(data)`: `h ← SHA-256(h ‖ data)`. Every handshake message's raw wire
  bytes are absorbed in order, so both sides compute an identical transcript
  from the bytes they actually sent/received (no JSON canonicalization needed
  for the transcript — only certificates, which are signed separately, use JCS).
- `MixKey(ikm)`: `(ck, k) ← HKDF-SHA-256(salt=ck, ikm)`, giving a new chaining
  key and a fresh AEAD key.
- Order: initialize `ck`/`h` from a protocol-label constant and message 1; after
  message 2's ephemerals, `MixKey(ss_dh)` then `MixKey(ss_kem)` — **DH first,
  then KEM** `[PIN]`; handshake encryption uses the resulting key.
- **Transport keys**: after message 3, `Split()` derives two directional keys
  (initiator→responder, responder→initiator) via HKDF from the final `ck`, so
  the two directions never share a key/nonce space.
- **Nonces**: each direction has a 96-bit counter starting at 0, incremented per
  message, never reused. A counter approaching exhaustion forces a rekey (§6).

## 6. Session lifetime, rekeying, forward secrecy

- Because agreement is over **ephemeral** X25519 and ML-KEM keys, compromise of
  a node's long-term identity key does **not** retroactively decrypt recorded
  sessions (forward secrecy). It does allow future impersonation until the
  certificate is revoked or expires.
- Sessions rekey on a **[PIN]** interval (time- or message-count-bounded) by
  running a fresh BMX handshake over the existing connection; the old transport
  keys are discarded.
- Idle sessions are tornd down after a timeout and re-handshaked on demand.

## 7. Trust model and threat model

**What v3 defends against:**

| Adversary capability | Defense |
|---|---|
| Passive eavesdropper on any link | Hybrid forward-secret channel; even identities are encrypted (msg 2/3). |
| Active MITM on a link | Mutual cert-based auth bound to the transcript; MITM lacks a root-signed cert and cannot forge the transcript signature. |
| Non-member trying to join | No root-signed certificate ⇒ handshake rejected. |
| Replay of a whole handshake | Fresh `n` and ephemeral keys per session; transcript signatures do not verify against a new session. |
| Replay/reorder of transport messages | Per-direction nonce counters; a repeated or out-of-window nonce is rejected. |
| Spoofed `from` label (v2's D8) | Label is bound in a root-signed cert to an identity key that must sign the live transcript. |
| Unbounded input (v2's D7) | Hard maximum message size enforced at the frame layer (see protocol.md). |

**What v3 explicitly does NOT defend against (stated, not hidden):**

- **A malicious *member*.** Trust is hop-by-hop: a relaying member decrypts a
  message and re-encrypts it to the next hop, so any member on a path sees the
  plaintext of messages it relays. Members are trusted for v3. End-to-end
  payload protection against untrusted relays is **deferred** (decision #13);
  the message format reserves room for a future end-to-end layer, but v3 does
  not provide it. A suite name or doc that implies confidentiality *from other
  members* would be overclaiming — it is not there.
- **Traffic analysis.** Message sizes and timing are not padded or obscured.
- **Compromise of the root private key.** That is game over for the mesh by
  construction; protecting it (offline, hardware-backed) is an operational
  concern the `bonemesh-ca` tool documents, not a protocol control.
- **Denial of service by a member** flooding the mesh. Rate-limiting is an
  implementation concern, not specified here.

## 8. Debuggability under encryption

The project's "objects readable in flight" value survives encryption via a
development-only hook (decision #5), modeled on TLS `SSLKEYLOGFILE`:

- When (and only when) the environment variable **`BONEMESH_KEYLOG`** names a
  writable path, a node appends, per session, the derived transport keys keyed
  by the session's transcript hash, in a defined text format `[PIN]`.
- The hook is **off by default**, and a node that has it on **logs a loud
  warning** on every session, because it defeats forward secrecy for anyone
  holding the file.
- A bundled **`bonemesh-inspect`** tool reads a key-log plus a captured stream
  and prints the decrypted JSON, so `tcpdump` + inspector reproduces v2's
  "watch the JSON go by" experience without a plaintext production mode.

The inspector and key-log format are specified in `spec/` so **all six
implementations emit compatible logs** — an inspector built once reads a stream
from a node in any language.

## 9. Provisioning workflow (informative)

1. `bonemesh-ca init` generates a mesh root keypair offline; publishes the root
   **public** key.
2. `bonemesh-ca issue --label alpha --key alpha.idk.pub --days 30` produces
   `alpha`'s membership certificate.
3. Each node is deployed with: its own identity keypair, its membership
   certificate, and the pinned root public key. No node ever holds the root
   private key.
4. Rotation: re-issue certificates before expiry; distribute a revocation list
   (§3) to drop a node early.

---

## Open items for review

- **[PIN] constants** (HKDF labels, MixKey order confirmation, JCS field set,
  key-log format, rekey interval) — frozen with the Go reference + corpus, the
  next M3 unit. Flagged so the *design* can be reviewed first.
- **Parameter choices** — ML-DSA-65/-87 split and ML-KEM-768 are proposed;
  raise here if a different category is wanted before they are pinned.
- **Revocation** — specified as an optional extension; promote to mandatory if
  the deployment model needs prompt revocation rather than short-lived certs.
