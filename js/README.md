# BoneMesh — JavaScript

The JavaScript implementation of BoneMesh v3: a full routing mesh node for
Node.js, wire-compatible with the Java, Go, Rust, PHP, and Elixir
implementations. Crypto uses Node's built-in `node:crypto` / WebCrypto (X25519,
ML-KEM-768, ML-DSA-65/87, HKDF-SHA-256, ChaCha20-Poly1305) — no npm crypto
dependency to source.

Requires Node.js 24+ (for the stable ML-KEM / ML-DSA primitives). There are no
runtime dependencies, so there is no install or build step.

## Test

```sh
cd js
node --test
```

This is what the `bonemesh-js` reaper tenant (`js/.reaper.toml`) runs — the
built-in `node:test` runner over `test/`.

## Interop

The neutral driver is [`../interop/drivers/js.sh`](../interop/drivers/js.sh)
(`keygen` / `listen` / `connect` / `mesh`, plus `caps` and `--acks` /
`--sessions`). See [`../interop/README.md`](../interop/README.md) and
[`../docs/testing.md`](../docs/testing.md).

## Embedding

`import { Node } from './src/node.js'` and drive it with `Node.start`,
`connect`, `send` / `sendMid`, and the `onMessage` / `onAck` listeners. The
worked example, alongside the other five languages, is in
[`../docs/user-guide.md`](../docs/user-guide.md) §5.
