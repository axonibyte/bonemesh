# Handshake transcript vectors

Cross-language freezes of the BMX handshake's cryptographic core. Each is
reproduced independently by the Java reference and the Go conformance runner.

| Vector | Freezes | Verified by |
|---|---|---|
| `keyschedule.json` | The full key schedule (init, mixHash, mixKey, encryptAndHash, split) — transcript hashes, chaining keys, ciphertexts, transport keys. | Java (`KsDump`) + Go (`keyschedule`) |
| `handshake-agreement.json` | The X25519 half of the hybrid agreement (Go derives `ss_dh` from the initiator scalar) plus the schedule over both secrets → transport keys. | Java (`AgreementDump`) + Go (`handshake`) |

## What is frozen across languages now

- **Certificate canonicalization** (`../canon.json`) — signing pre-image bytes.
- **The key schedule** — identical transport keys from identical secrets.
- **X25519 agreement** — Java (BouncyCastle) and Go (`crypto/ecdh`) derive the
  same `ss_dh` from the same scalars.

## Deferred interop items (documented, not hidden)

- **ML-KEM cross-decapsulation.** Go's `crypto/mlkem` uses the 64-byte seed
  representation of a decapsulation key; BouncyCastle exports the expanded key.
  A vector proving Go decapsulates a Java-produced ciphertext to the same
  `ss_kem` needs the seed representation reconciled first. Until then `ss_kem`
  is a given input here, and ML-KEM interop rests on both sides implementing
  FIPS 203. Tracked for the interop harness (M5).
- **ML-DSA signature interop.** The Go runner has no ML-DSA yet (stdlib lacks
  it). Java's in-memory handshake exercises mutual ML-DSA authentication; a
  cross-language signature vector lands when Go gains ML-DSA (Cloudflare CIRCL).
- **Byte-exact full transcript** (the whole bmx1/bmx2/bmx3 bytes) depends on
  both of the above, so it follows them.

Neither deferral weakens what is frozen: the key agreement and schedule — the
part that decides whether two nodes derive the same session keys — is proven
across Java and Go today.
