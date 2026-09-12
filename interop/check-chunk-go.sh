#!/bin/sh
# Go splitting against the shared corpus (spec/corpus/chunk.json): the pinned
# section 0 constants and the exact byte boundaries the cuts land on.
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
go=go126
command -v "$go" >/dev/null 2>&1 || go=go
cd "$repo/go" && GOTOOLCHAIN=local GOFLAGS=-mod=vendor "$go" run ./cmd/interop_checks chunk "$repo/spec/corpus/chunk.json"
