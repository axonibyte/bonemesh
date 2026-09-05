#!/bin/sh
# Go frame classifier verdicts against the shared corpus (spec/corpus/framing.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
go=go126
command -v "$go" >/dev/null 2>&1 || go=go
cd "$repo/go" && GOTOOLCHAIN=local GOFLAGS=-mod=vendor "$go" run ./cmd/interop_checks framing "$repo/spec/corpus/framing.json"
