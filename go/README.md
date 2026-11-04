# BoneMesh — Go

The Go implementation of BoneMesh v3: a full routing mesh node, plus the
canonical operator tools `bonemesh-ca` (mesh certificate authority) and
`bonemesh-inspect` (key-log traffic decryptor). Wire-compatible with the Java,
Rust, JS, PHP, and Elixir implementations. Crypto is Go stdlib (X25519,
ML-KEM-768, HKDF, ChaCha20-Poly1305) plus Cloudflare CIRCL for ML-DSA-65/87.

Dependencies are vendored, so every build and test is offline. Requires Go 1.26.

## Depending on it

```sh
GOPROXY=direct go get forge.axonibyte.com/axonibyte/bonemesh/go/v3@v3.3.2
```

The path names this repository's **public HTTPS face**, which is the only host
Go can fetch from: the canonical remote `forge-01.corp.axonibyte.com` has no SSH
through the front door, and GitHub is a mirror. `GOPROXY=direct` sends Go
straight there; once the module has been fetched through the public proxy it is
no longer needed.

The module sits in a subdirectory, so two things follow, and both are release
steps rather than code:

- **Tag it `go/vX.Y.Z` as well as the bare `X.Y.Z`**, on the same commit. Go
  reads only the prefixed tag for a module in a subdirectory; the bare tags
  remain for the other implementations.
- **The first fetchable tag has to be a new version.** `go/v3.3.1` cannot be
  backfilled onto the `3.3.1` commit, because the `go.mod` there still declares
  the old path and Go refuses a module whose declared path does not match the
  one it was asked for.

`sh ci/check-go-module.sh` asserts the host, directory and major version of
every Go module in the tree, and `--self-test` proves it can still fail. It
exists because nothing else can see this class of fault: a wrong module path
builds and tests perfectly (see `docs/defects.md` D25).

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
