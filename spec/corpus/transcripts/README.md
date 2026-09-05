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

## Post-quantum interop — RESOLVED (Java, Elixir, Rust)

`pqc-interop.json` (produced by the Java reference, BouncyCastle) is verified
from the Elixir side (OTP 28's native `:crypto`, `check-pqc-elixir.sh`) and the
Rust side (RustCrypto `ml-dsa`/`ml-kem`, `check-pqc-rust.sh`):

- **ML-DSA-65 signatures** — each verifies a signature Java made.
- **ML-KEM-768 cross-decapsulation** — each decapsulates a ciphertext Java
  produced to the identical shared secret (BouncyCastle's expanded
  decapsulation-key encoding is accepted by both OTP and RustCrypto directly).

So the post-quantum primitives interoperate across three independent
implementations, and the BMX handshake works across the full ones.

Note on private-key formats (a non-issue by design): implementations differ on
how they *store* private keys — BouncyCastle expands the ML-DSA signing key
while RustCrypto keeps the 32-byte seed. This never affects interop because
private keys never cross a node boundary; only public keys, ciphertexts, and
signatures do, and those are the standard FIPS encodings, which all three match.

## Still deferred

- **Go post-quantum interop.** Go's `crypto/mlkem` uses the 64-byte *seed*
  representation of a decapsulation key rather than the expanded key Java/Elixir
  exchange, and Go stdlib has no ML-DSA. The Go conformance runner therefore
  still verifies the key *agreement* (X25519 + schedule) but not ML-KEM
  cross-decapsulation or ML-DSA signatures; resolving it needs the seed
  representation reconciled and an ML-DSA library (Cloudflare CIRCL). Tracked
  for the interop harness.
- **Byte-exact full transcript** (the whole bmx1/bmx2/bmx3 bytes) — a static
  vector is unnecessary now that the live cross-language handshake is proven end
  to end: `interop/run-matrix.sh` completes a real BMX handshake, encrypted
  transport, and delivery between Java and Elixir in both directions. A pinned
  transcript vector remains optional future work for offline conformance.

Nothing frozen is weakened: the key agreement and schedule are proven across
Java, Go, and Elixir, and the post-quantum layer is now proven across Java and
Elixir.
