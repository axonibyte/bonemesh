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

## Post-quantum interop — RESOLVED (Java, Elixir, Rust, Go, JS, PHP)

`pqc-interop.json` (produced by the Java reference, BouncyCastle) is verified
from the Elixir side (OTP 28's native `:crypto`, `check-pqc-elixir.sh`), the
Rust side (RustCrypto `ml-dsa`/`ml-kem`, `check-pqc-rust.sh`), the Go side
(`check-pqc-go.sh`), the JS side (Node/OpenSSL 3.5, `check-pqc-js.sh`), and the
PHP side (openssl 3.5 CLI, `check-pqc-php.sh`):

- **ML-DSA-65 signatures** — Elixir, Rust, Go, JS, and PHP each verify a
  signature Java made. Go uses Cloudflare CIRCL (`sign/mldsa/mldsa65`); JS uses
  Node's built-in `crypto`; PHP shells out to the openssl 3.5 CLI — in each case
  the same code the node uses on the handshake path.
- **ML-KEM-768 cross-decapsulation** — Elixir and Rust decapsulate a ciphertext
  Java produced to the identical shared secret, directly from the offline vector
  (BouncyCastle's expanded decapsulation-key encoding is accepted by both OTP
  and RustCrypto). Go, JS, and PHP prove ML-KEM-768 interop **live** instead:
  every pairing in `interop/run-matrix.sh` completes a real hybrid handshake in
  which they decapsulate ciphertexts made by the other implementations and vice
  versa. All three work from the 64-byte *seed* form (Go's stdlib `crypto/mlkem`,
  Node's OpenSSL ML-KEM, PHP's openssl CLI), so none ingests the vector's
  expanded decapsulation key — but a decapsulation key never crosses a node, so
  this is a key-*representation* detail, not an interop gap (see below).

So the post-quantum primitives interoperate across six independent
implementations, and the BMX handshake works across all six.

Note on private-key formats (a non-issue by design): implementations differ on
how they *store* private keys — BouncyCastle expands the ML-DSA/ML-KEM keys,
RustCrypto, Go, Node, and openssl keep the seed. This never affects interop
because private keys never cross a node boundary; only public keys, ciphertexts,
and signatures do, and those are the standard FIPS encodings, which all six match.

## Live cross-language matrix

`interop/run-matrix.sh` runs every (responder, initiator) pair across all six
implementations — Java, Elixir, Rust, Go, JS, PHP — completing a real BMX
handshake, encrypted transport, and application delivery in each direction. All
36 cells pass. The harness is implementation-agnostic: it discovers drivers in
`interop/drivers/*.sh` and pairs them without any per-language logic, so a client
never depends on what implementation answers, only that the protocol is obeyed.

## Still deferred

- **Byte-exact full transcript** (the whole bmx1/bmx2/bmx3 bytes) — a static
  vector is unnecessary now that the live cross-language handshake is proven end
  to end across all six languages. A pinned transcript vector remains optional
  future work for offline conformance.

Nothing frozen is weakened: the key agreement and schedule are proven across
Java, Go, Elixir, Rust, JS, and PHP, and the post-quantum layer is now proven
across all six.
