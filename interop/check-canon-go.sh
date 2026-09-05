#!/bin/sh
# Go canon conformance against the shared corpus (spec/corpus/canon.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
go=go126
command -v "$go" >/dev/null 2>&1 || go=go
cd "$repo/go" && GOTOOLCHAIN=local GOFLAGS=-mod=vendor "$go" run ./cmd/canon_check "$repo/spec/corpus/canon.json"
