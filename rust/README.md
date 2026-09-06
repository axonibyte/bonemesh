# BoneMesh — Rust

The Rust implementation of BoneMesh v3: a full routing mesh node, wire-compatible
with the Java, Go, JS, PHP, and Elixir implementations. Crypto is RustCrypto and
dalek (`ml-dsa`, `ml-kem`, `x25519-dalek`, `chacha20poly1305`, HKDF).

Dependencies are vendored (`vendor/`), so builds and tests run offline.

## Build

```sh
cd rust
cargo build --offline
```

## Test

```sh
cargo test --offline
```

This is what the `bonemesh-rust` reaper tenant (`rust/.reaper.toml`) runs
(with `CARGO_HOME` pointed at a cache). Some suites live in `tests/` as separate
binaries — notably the rekey and key-log tests, isolated so their `BONEMESH_*`
env overrides can't leak into other suites.

## Interop

The neutral driver is [`../interop/drivers/rust.sh`](../interop/drivers/rust.sh)
(`keygen` / `listen` / `connect` / `mesh`, plus `caps` and `--acks` /
`--sessions`). See [`../interop/README.md`](../interop/README.md) and
[`../docs/testing.md`](../docs/testing.md).

## Embedding

The node API (`Node::start(Config { … })`, then `add_listener` / `connect` /
`send`; `add_ack_listener` for ack delivery) is shown, alongside the other five
languages, in [`../docs/user-guide.md`](../docs/user-guide.md) §5.
