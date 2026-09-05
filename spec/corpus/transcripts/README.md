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

## Post-quantum interop — RESOLVED (Java ↔ Elixir)

`pqc-interop.json` (produced by the Java reference, BouncyCastle) is verified
from the Elixir side (OTP 28's native `:crypto`) by `check-pqc-elixir.sh`:

- **ML-DSA-65 signatures** — Elixir verifies a signature Java made.
- **ML-KEM-768 cross-decapsulation** — Elixir decapsulates a ciphertext Java
  produced to the identical shared secret (BouncyCastle's expanded
  decapsulation-key encoding is accepted by OTP directly).

So the post-quantum primitives interoperate between the two full
implementations, and the BMX handshake works across them.

## Still deferred

- **Go post-quantum interop.** Go's `crypto/mlkem` uses the 64-byte *seed*
  representation of a decapsulation key rather than the expanded key Java/Elixir
  exchange, and Go stdlib has no ML-DSA. The Go conformance runner therefore
  still verifies the key *agreement* (X25519 + schedule) but not ML-KEM
  cross-decapsulation or ML-DSA signatures; resolving it needs the seed
  representation reconciled and an ML-DSA library (Cloudflare CIRCL). Tracked
  for the interop harness.
- **Byte-exact full transcript** (the whole bmx1/bmx2/bmx3 bytes) — best proven
  by a live cross-language handshake, which the two full implementations
  (Java, Elixir) can now perform.

Nothing frozen is weakened: the key agreement and schedule are proven across
Java, Go, and Elixir, and the post-quantum layer is now proven across Java and
Elixir.
