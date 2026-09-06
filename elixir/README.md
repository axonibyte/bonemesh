# BoneMesh — Elixir

The Elixir implementation of BoneMesh v3: a full routing mesh node built on OTP,
wire-compatible with the Java, Go, Rust, JS, and PHP implementations. The node is
a `GenServer`; the post-quantum and symmetric primitives (ML-KEM-768,
ML-DSA-65/87, X25519, HKDF-SHA-256, ChaCha20-Poly1305) come from Erlang/OTP's
`:crypto`.

**Requires Erlang/OTP 28** (for the ML-KEM / ML-DSA support in `:crypto`) and a
matching Elixir. This is why Elixir is skipped on the `ubuntu-26.04` interop
guest — see [`../docs/testing.md`](../docs/testing.md) §3.

## Build

There are no external deps to fetch — just compile:

```sh
cd elixir
mix compile
```

## Test

```sh
mix test
```

This is what the `bonemesh-elixir` reaper tenant (`elixir/.reaper.toml`) runs.

## Interop

The neutral driver is
[`../interop/drivers/elixir.sh`](../interop/drivers/elixir.sh) (`keygen` /
`listen` / `connect` / `mesh`, plus `caps` and `--acks` / `--sessions`). See
[`../interop/README.md`](../interop/README.md) and
[`../docs/testing.md`](../docs/testing.md).

## Embedding

`Bonemesh.Node.start_link/1`, then `connect`, `send` / `send_mid`, and
`add_listener(node, self())` — delivered payloads arrive as
`{:bonemesh_data, payload}` messages. The worked example, alongside the other
five languages, is in [`../docs/user-guide.md`](../docs/user-guide.md) §5.
