# BoneMesh v3 — security design

**Status: normative as of 3.1.0.** The design is ratified and the cryptographic
wire contract is **frozen** — implemented by all seven reference implementations
and pinned by the shared corpus (`corpus/`). The construction is deliberately
conventional — it is a reassembly of well-analyzed parts (hybrid X25519+ML-KEM
key agreement, ML-DSA certificate identity, a Noise-style key schedule,
ChaCha20-Poly1305) rather than novel cryptography. Constants formerly marked
**[PIN]** are resolved inline against the corpus. The items 3.0.0 deferred —
periodic session rekey (§6), idle teardown (§6), and the key-log hook with its
now-pinned format (§8) — are **delivered as of 3.1.0** across all seven and are
called out as live where they appear.

Companion document: [`protocol.md`](protocol.md) (framing, connections,
routing). This document owns identity, membership, the handshake, and the
threat model.

**Constant status.** All the wire-affecting values are now **frozen** and
corpus-enforced: *deterministic* values (algorithm identifiers, encodings, the
certificate structure and its canonicalization — §11); the *key-schedule* values
(protocol name, mix order, nonce construction, HKDF usage, split), pinned by
`spec/corpus/transcripts/keyschedule.json`; and the *full handshake transcript*
(the end-to-end ML-KEM/ML-DSA message bytes), pinned by
`handshake-agreement.json`, `pqc-interop.json`, and `transport-frame.json` and
exercised live by the interop matrix across all seven implementations. The
**key-log debug format** (§8) is now pinned too (corpus `keylog.json`) and
emitted by all seven. This document never claims a crypto constant is
interop-verified before code has exercised it.

---

## 1. Cryptographic primitives

| Role | Primitive | Notes |
|---|---|---|
| Node identity signatures | **ML-DSA-65** (FIPS 204, category 3) | A node *is* its ML-DSA public key; the label is a display name bound by the cert. |
| Mesh root signatures | **ML-DSA-87** (FIPS 204, category 5) | The root is high-value and offline; it gets the strongest parameter set. |
| Ephemeral key agreement | **X25519** *and* **ML-KEM-768** (FIPS 203), hybrid | Both shared secrets are mixed; security holds if *either* primitive holds. Mirrors TLS `X25519MLKEM768`, Signal PQXDH, Rosenpass. |
| AEAD | **ChaCha20-Poly1305** | 256-bit key, 96-bit nonce. Uniformly available and constant-time in software across all seven languages. |
| Hash / KDF | **SHA-256** / **HKDF-SHA-256** | Ubiquitous; no BLAKE dependency to source seven times. |
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
- `sig` is the root's ML-DSA-87 signature over **`CANON(certificate without the
  `sig` field)`**. The exact pre-image (field set and canonicalization profile)
  is frozen — fully specified in §11.1 and pinned by `spec/corpus/canon.json`.

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
Ephemeral public values are Base64. Certificates and signatures in messages 2 and
3 are carried **inside `ENC(...)`** — encrypted under keys derived from the
ephemeral exchange, so identities are not exposed to a passive observer.

`ENC(p)` is one operation and it does two things: it seals `p` under the current
handshake key with the current `h` as associated data, and it then absorbs the
resulting ciphertext into `h` (§5, `EncryptAndHash`). The nonce counter advances
once per seal.

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
  "auth": "<base64 ENC({\"cert\": <certificate JSON>, \"sig\": \"<base64 ML-DSA-65 signature>\"})>" }
```

`auth` is a **single** sealed member carrying both the certificate and the
signature. The certificate inside it is a JSON object, not a Base64 string.

`sig` is the responder's signature over the transcript hash `h` *as of the point
just before `ENC` is applied* (a TLS-1.3-style CertificateVerify). It proves the
responder holds the private key for the `idk` in its certificate, binding the
certificate to this live session and defeating certificate replay.

**Why one member and not two.** Through 3.2.0 this section specified separate
`cert` and `sig` members, each separately sealed, and that is under-specified in a
way that cannot be patched by adding a sentence. `ENC` uses `h` as associated data
and absorbs its own ciphertext, so two seals in one message leave three orderings
undetermined: whether `ENC(cert)`'s ciphertext is absorbed before `ENC(sig)` is
computed, whether the signature's pre-image includes that absorption, and which
nonce counter value each seal uses. Every one of those changes the derived keys,
so two implementations could both follow the older text exactly and fail to
interoperate. Sealing one object has none of those degrees of freedom, binds the
certificate and the signature atomically, and costs one AEAD operation instead of
two. All seven reference implementations have always done this; the correction is
to the specification (decision #26).

### Message 3 — initiator → responder

The initiator now has `e_r` and `ct`, computes the same `ss_dh`/`ss_kem`,
derives the same keys, verifies the responder's certificate (§3) and signature,
then sends its own identity, encrypted:

```json
{ "t": "bmx3",
  "auth": "<base64 ENC({\"cert\": <certificate JSON>, \"sig\": \"<base64 ML-DSA-65 signature>\"})>" }
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

A Noise-style symmetric state carries `(ck, h)`. **Frozen** by
`spec/corpus/transcripts/keyschedule.json` (reproduced by both the Java reference
and the Go runner); the structure:

- `MixHash(data)`: `h ← SHA-256(h ‖ data)`.
- `MixKey(ikm)`: `(ck, k) ← HKDF-SHA-256(salt=ck, ikm, info="", 64)`, the first 32
  bytes the new chaining key and the next 32 the fresh AEAD key; the AEAD nonce
  counter resets to 0.
- `EncryptAndHash(p)` — written `ENC(p)` in §4: seal `p` under the current key with
  the current `h` as associated data, then `MixHash(ciphertext)`.

**What is absorbed, and in what order.** Each value is absorbed as it is written or
read, not as part of a whole message. This is the Noise `XX` pattern §4 says the
handshake *is*, so the correspondence is exact rather than approximate: `mesh` is
Noise's prologue, the ephemerals are its `e` tokens, and `ENC` is its
`EncryptAndHash`.

1. `h` and `ck` seed from `SHA-256("BoneMesh_BMX_v3_X25519MLKEM768_ChaChaPoly_SHA256")`.
2. `MixHash(mesh)` — the **prologue**, binding the mesh name into every later key so
   two meshes with identical certificates still derive different secrets.
3. Message 1: `MixHash(e_i)`, `MixHash(k_i)`, `MixHash(n)` — the decoded values, in
   that order.
4. Message 2: `MixHash(e_r)`, `MixKey(ss_dh)`, `MixHash(ct)`, `MixKey(ss_kem)` —
   **DH first, then KEM**, with the KEM ciphertext absorbed between them. Then
   `ENC(auth)`, whose `sig` was computed over `h` as it stood immediately before
   that call.
5. Message 3: `ENC(auth)` under the same rule.

No JSON canonicalization is involved: what is absorbed is the decoded field value,
so neither side depends on the other's key order, spacing or escaping. Only
certificates, which are signed separately, use JCS (§11.1).

**Why not the raw wire bytes.** Through 3.2.0 this section said "every handshake
message's raw wire bytes are absorbed in order". No implementation has ever done
that, and it could not be done as written. `ENC` needs `h` to seal `auth`, and
`auth` is part of message 2's bytes, so absorbing those bytes is circular — the
only way out is to absorb the message *after* sealing, which leaves `e_r` and `ct`
outside the responder's signature pre-image and weakens the channel binding the
signature exists to provide. Hashing whole messages is also not what Noise does,
despite §4 naming Noise `XX` as the pattern. The specification was wrong and the
code was right; this is the correction (decision #26). `keyschedule.json` has
always pinned the construction above, so §5's own claim to be **Frozen** by that
file is now true rather than self-contradictory.

- **Transport keys**: after message 3, `Split()` derives two directional keys as
  `HKDF-SHA-256(salt=ck, ikm="", info="", 64)` — the same shape as `MixKey` with an
  empty `ikm`. The first 32 bytes are the **initiator→responder** key and the next
  32 the **responder→initiator** key, so the two directions never share a
  key/nonce space. That assignment is pinned by
  `spec/corpus/transcripts/handshake-agreement.json`; before 3.3.0 the vector was
  the only place it was recorded.
- **Nonces**: the 96-bit AEAD nonce is 4 zero bytes followed by the 64-bit
  little-endian counter; the counter starts at 0 per key, increments per message,
  and is never reused. A counter approaching exhaustion forces a rekey (§6).
- **Transport AAD**: transport frames are sealed with **empty** associated data —
  the sequence number is in the nonce, which binds it. Stated here because it was
  previously recorded only in prose in `spec/corpus/README.md`.

## 6. Session lifetime, rekeying, forward secrecy

- Because agreement is over **ephemeral** X25519 and ML-KEM keys, compromise of
  a node's long-term identity key does **not** retroactively decrypt recorded
  sessions (forward secrecy). It does allow future impersonation until the
  certificate is revoked or expires.
- **Periodic rekey (delivered in 3.1.0).** The session initiator re-runs a full
  BMX over the live connection when a direction's frame counter crosses
  `BONEMESH_REKEY_FRAMES` (default 65536) or the session ages past
  `BONEMESH_REKEY_MS` (default 1 h). The three BMX messages are tunneled inside
  transport frames (a `rekey` inner type, phases 1–4), so they arrive through
  the normal reader with no raw-stream race; each side swaps its send key
  immediately after sealing its last old-key frame and its receive key
  immediately after opening the peer's, and the per-direction counters reset, so
  interleaved traffic never straddles the boundary. The fresh handshake
  re-verifies the peer's certificate, so an expired cert ends the session at the
  next rekey. A peer that does not implement rekey ignores the `rekey` frames;
  the initiator abandons the attempt after `BONEMESH_REKEY_TIMEOUT_MS` and keeps
  the old keys (safe degrade). AEAD-nonce-counter exhaustion (§5) remains an
  independent rekey trigger.
- **Idle teardown (delivered in 3.1.0, off by default).** When
  `BONEMESH_IDLE_MS > 0`, a link carrying no `data` traffic (probe/echo/disco do
  not count) for that long is closed after a `bye`; it re-handshakes on demand.
  Forward secrecy (above) depends on neither rekey nor idle teardown — it follows
  from the per-session ephemeral agreement regardless.

## 7. Trust model and threat model

**What v3 defends against:**

| Adversary capability | Defense |
|---|---|
| Passive eavesdropper on any link | Hybrid forward-secret channel; even identities are encrypted (msg 2/3). |
| Active MITM on a link | Mutual cert-based auth bound to the transcript; MITM lacks a root-signed cert and cannot forge the transcript signature. |
| Non-member trying to join | No root-signed certificate ⇒ handshake rejected. |
| Replay of a whole handshake | Fresh `n` and ephemeral keys per session; transcript signatures do not verify against a new session. |
| Replay/reorder of transport messages | Per-direction nonce counters, accepted **strictly in order**: the window is exactly one, so a repeated, skipped or reordered `seq` is rejected and the session torn down (protocol.md §4). Earlier drafts said "out-of-window", which described a range this protocol does not have. |
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

Delivered in 3.1.0. The project's "objects readable in flight" value survives
encryption via a development-only hook (decision #5), modeled on TLS
`SSLKEYLOGFILE`:

- When (and only when) the environment variable **`BONEMESH_KEYLOG`** names a
  writable path, a node appends, per session, its derived transport keys keyed
  by the session's transcript hash, in the pinned format (one entry per line;
  `#` comments ignored; unknown labels ignored):

  ```
  BMX3_I2R_TRAFFIC_<epoch> <hex sha256 transcript-hash> <hex 32-byte key>
  BMX3_R2I_TRAFFIC_<epoch> <hex transcript-hash> <hex key>
  ```

  `epoch` is 0 at the handshake and +1 per rekey (§6). A node maps its
  role-relative send/receive keys onto the absolute I2R/R2I directions, so a log
  from either end is read by one inspector; both ends of a session emit
  identical directional keys. Worked vector: `corpus/keylog.json`.
- The hook is **off by default**, and a node that has it on **logs a loud
  warning** on every session, because it defeats forward secrecy for anyone
  holding the file.
- The bundled **`bonemesh-inspect`** tool reads a key-log plus a captured stream
  (`{"dir","frame":{seq,ct}}` NDJSON) and prints the decrypted inner JSON, so a
  capture + inspector reproduces v2's "watch the JSON go by" experience without
  a plaintext production mode. It tries the newest epoch's key first per
  direction and lets the Poly1305 tag pick the winner, so it never has to parse
  rekey control frames.

The format is pinned in `spec/` (`corpus/keylog.json`) so **all seven
implementations emit compatible logs** — an inspector built once reads a stream
from a node in any language, verified by interop tier 10.

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

## 11. Pinned deterministic constants

Frozen and enforced by the corpus. The key schedule is frozen too — see §5 and
`keyschedule.json`; the earlier "provisional" caveat is superseded. Note there are
no HKDF *labels* to freeze: `MixKey` and `Split` both pass an **empty** `info`, so
what is pinned is the protocol-name seed string, the empty-`info` construction, and
the order values are absorbed in. Earlier drafts promised frozen "HKDF labels",
which described a design this protocol does not have.

| Constant | Value |
|---|---|
| Node identity signature | ML-DSA-65 (FIPS 204) |
| Root signature | ML-DSA-87 (FIPS 204) |
| Ephemeral KEM | ML-KEM-768 (FIPS 203) |
| Ephemeral DH | X25519 (RFC 7748) |
| AEAD | ChaCha20-Poly1305 (RFC 8439), 256-bit key, 96-bit nonce |
| Hash / KDF | SHA-256 / HKDF-SHA-256 (RFC 5869) |
| Key/signature/ciphertext encoding in JSON | RFC 4648 standard Base64, with padding, no line breaks |
| Certificate version (`v`) | `3` |

### 11.1 Certificate canonicalization (for the root signature)

The root signs `CANON(certificate without "sig")`. Because a certificate
contains **only JSON strings and non-negative integers** — never floats, arrays,
nested objects, or booleans — canonicalization is a restricted, easy-to-match-
exactly profile (a strict subset of RFC 8785 JCS):

1. Remove the `sig` member.
2. Emit a JSON object with members ordered by **ascending UTF-16 code unit** of
   the member name (for the ASCII names here, plain byte order): `exp`, `idk`,
   `label`, `mesh`, `nbf`, `v`.
3. No whitespace anywhere.
4. Strings use minimal escaping: only `"` `\` and control chars `< 0x20` are
   escaped, the latter as `\uXXXX` lowercase-hex except the short forms
   `\b \t \n \f \r`. Non-ASCII is emitted as raw UTF-8, not `\u`-escaped.
5. Integers are emitted in shortest decimal form, no leading zeros, no `+`, no
   exponent.

The resulting UTF-8 byte string is the ML-DSA-87 signing input. This profile is
pinned and has corpus vectors; a port that reproduces the exact bytes for the
vectors is interoperable for certificate verification.

---

## Open items for review

- **Formerly-[PIN] constants** — the key-schedule seed string, the `MixKey`/`Split`
  construction and absorption order, the JCS field set (§5, §11), and the
  **key-log format** (§8) are all **frozen** and corpus-pinned. (Read "HKDF labels"
  in earlier drafts as the construction: `info` is empty, so there are no labels.)
  Periodic **rekey** (§6) is delivered in 3.1.0; its trigger thresholds are local
  tunables, not wire constants.
- **Parameter choices** — ML-DSA-65/-87 split and ML-KEM-768 are proposed;
  raise here if a different category is wanted before they are pinned.
- **Revocation** — specified as an optional extension; promote to mandatory if
  the deployment model needs prompt revocation rather than short-lived certs.
