# Handshake transcript vectors

Cross-language freezes of the BMX handshake's cryptographic core. Each is
reproduced independently by the Java reference and the Go conformance runner, and
re-checked against these same files by the node ports (e.g. the Go port's
`check-keyschedule-go.sh` / `check-agreement-go.sh`, and the Elixir and Rust
equivalents).

| Vector | Freezes | Verified by |
|---|---|---|
| `keyschedule.json` | The full key schedule (init, mixHash, mixKey, encryptAndHash, split) — transcript hashes, chaining keys, ciphertexts, transport keys. | Java (`KsDump`) + Go (`keyschedule`) |
| `handshake-agreement.json` | The X25519 half of the hybrid agreement (Go derives `ss_dh` from the initiator scalar) plus the schedule over both secrets → transport keys. | Java (`AgreementDump`) + Go (`handshake`) |

## What is frozen across languages now

- **Certificate canonicalization** (`../canon.json`) — signing pre-image bytes.
- **The key schedule** — identical transport keys from identical secrets.
- **X25519 agreement** — Java (BouncyCastle) and Go (`crypto/ecdh`) derive the
  same `ss_dh` from the same scalars.

## Post-quantum interop — RESOLVED (Java, Elixir, Rust, Go)

`pqc-interop.json` (produced by the Java reference, BouncyCastle) is verified
from the Elixir side (OTP 28's native `:crypto`, `check-pqc-elixir.sh`), the
Rust side (RustCrypto `ml-dsa`/`ml-kem`, `check-pqc-rust.sh`), and the Go side
(`check-pqc-go.sh`):

- **ML-DSA-65 signatures** — Elixir, Rust, and Go each verify a signature Java
  made. Go uses Cloudflare CIRCL (`sign/mldsa/mldsa65`), the same code its node
  uses on the handshake path.
- **ML-KEM-768 cross-decapsulation** — Elixir and Rust decapsulate a ciphertext
  Java produced to the identical shared secret, directly from the offline vector
  (BouncyCastle's expanded decapsulation-key encoding is accepted by both OTP
  and RustCrypto). Go proves ML-KEM-768 interop **live** instead: every pairing
  in `interop/run-matrix.sh` completes a real hybrid handshake in which Go
  decapsulates ciphertexts made by Java/Elixir/Rust and vice versa. Go's stdlib
  `crypto/mlkem` is keyed by the 64-byte *seed*, so it does not ingest the
  vector's expanded decapsulation key — but a decapsulation key never crosses a
  node, so this is a key-*representation* detail, not an interop gap (see below).

So the post-quantum primitives interoperate across four independent
implementations, and the BMX handshake works across all four.

Note on private-key formats (a non-issue by design): implementations differ on
how they *store* private keys — BouncyCastle expands the ML-DSA/ML-KEM keys,
RustCrypto and Go keep the seed. This never affects interop because private keys
never cross a node boundary; only public keys, ciphertexts, and signatures do,
and those are the standard FIPS encodings, which all four match.

## Live cross-language matrix

`interop/run-matrix.sh` runs every (responder, initiator) pair across all four
implementations — Java, Elixir, Rust, Go — completing a real BMX handshake,
encrypted transport, and application delivery in each direction. All 16 cells
pass. The harness is implementation-agnostic: it discovers drivers in
`interop/drivers/*.sh` and pairs them without any per-language logic, so a client
never depends on what implementation answers, only that the protocol is obeyed.

## Still deferred

- **Byte-exact full transcript** (the whole bmx1/bmx2/bmx3 bytes) — a static
  vector is unnecessary now that the live cross-language handshake is proven end
  to end across all four languages. A pinned transcript vector remains optional
  future work for offline conformance.

Nothing frozen is weakened: the key agreement and schedule are proven across
Java, Go, Elixir, and Rust, and the post-quantum layer is now proven across all
four.
