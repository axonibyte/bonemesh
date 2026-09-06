# BoneMesh — PHP

The PHP implementation of BoneMesh v3: a full routing mesh node, wire-compatible
with the Java, Go, Rust, JS, and Elixir implementations. Symmetric crypto
(X25519, HKDF-SHA-256, ChaCha20-Poly1305) comes from the bundled **sodium**
extension; the post-quantum primitives (ML-KEM-768, ML-DSA-65/87) come from
**OpenSSL 3.5**, so the `openssl` extension must be linked against OpenSSL ≥ 3.5.

Requires PHP with the `sodium` and `openssl` (≥ 3.5) extensions; the interop
toolchain is `php:8.5-cli` (Debian trixie, which ships OpenSSL 3.5). Sources are
autoloaded (`src/autoload.php`); there is no build step.

## Test

```sh
cd php
php tests/run.php
```

`tests/run.php` runs every `tests/*.test.php` file and exits non-zero on any
failure — this is what the `bonemesh-php` reaper tenant (`php/.reaper.toml`)
runs.

## Interop

The neutral driver is [`../interop/drivers/php.sh`](../interop/drivers/php.sh)
(`keygen` / `listen` / `connect` / `mesh`, plus `caps` and `--acks` /
`--sessions`). See [`../interop/README.md`](../interop/README.md) and
[`../docs/testing.md`](../docs/testing.md).

## Embedding

`new Node(...)` then `connect`, `send` / `sendMid`, and the `onMessage` /
`onAck` callbacks (drive the loop with `serve`). The worked example, alongside
the other five languages, is in
[`../docs/user-guide.md`](../docs/user-guide.md) §5.
