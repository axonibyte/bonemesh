#!/bin/sh
# Go hybrid key-agreement against the shared vector (spec/corpus/transcripts/handshake-agreement.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
go=go126
command -v "$go" >/dev/null 2>&1 || go=go
cd "$repo/go" && GOTOOLCHAIN=local GOFLAGS=-mod=vendor "$go" run ./cmd/agreement_check "$repo/spec/corpus/transcripts/handshake-agreement.json"
