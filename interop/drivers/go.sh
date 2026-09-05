#!/bin/sh
# Go driver for the interop harness. Speaks the same neutral driver contract.
# Builds offline from the committed vendor/ tree; prefers the pinned go126
# toolchain when present, else whatever "go" is on PATH.
repo=$(cd "$(dirname "$0")/../.." && pwd)
bin="$repo/go/interop_node"
go=go126
command -v "$go" >/dev/null 2>&1 || go=go
[ -x "$bin" ] || (cd "$repo/go" && GOTOOLCHAIN=local GOFLAGS=-mod=vendor "$go" build -o interop_node ./cmd/interop_node)
exec "$bin" "$@"
