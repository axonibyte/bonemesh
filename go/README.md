# BoneMesh — Go

The Go implementation of BoneMesh v3: a full routing mesh node, plus the
canonical operator tools `bonemesh-ca` (mesh certificate authority) and
`bonemesh-inspect` (key-log traffic decryptor). Wire-compatible with the Java,
Rust, JS, PHP, and Elixir implementations. Crypto is Go stdlib (X25519,
ML-KEM-768, HKDF, ChaCha20-Poly1305) plus Cloudflare CIRCL for ML-DSA-65/87.

Dependencies are vendored, so every build and test is offline. Requires Go 1.26.

## Build

```sh
cd go
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go build ./...
```

Tools:

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go build -o bonemesh-ca      ./cmd/bonemesh-ca
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go build -o bonemesh-inspect ./cmd/bonemesh-inspect
```

## Test

```sh
GOTOOLCHAIN=local GOFLAGS=-mod=vendor go test ./...
```

This is what the `bonemesh-gonode` reaper tenant (`go/.reaper.toml`) runs.

## Interop

The neutral driver is [`../interop/drivers/go.sh`](../interop/drivers/go.sh)
(`keygen` / `listen` / `connect` / `mesh`, plus `caps` and the `--acks` /
`--sessions` / `--capture` observability flags — Go is the one implementation
that offers `--capture`). See [`../interop/README.md`](../interop/README.md) and
[`../docs/testing.md`](../docs/testing.md).

## Embedding

The node API (`node.Start(node.Config{…})`, then `AddListener` / `Connect` /
`Send`) is shown, alongside the other five languages, in
[`../docs/user-guide.md`](../docs/user-guide.md) §5.
