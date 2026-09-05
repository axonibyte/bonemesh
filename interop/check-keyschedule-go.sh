#!/bin/sh
# Go key-schedule KAT against the shared vector (spec/corpus/transcripts/keyschedule.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
go=go126
command -v "$go" >/dev/null 2>&1 || go=go
cd "$repo/go" && GOTOOLCHAIN=local GOFLAGS=-mod=vendor "$go" run ./cmd/keyschedule_check "$repo/spec/corpus/transcripts/keyschedule.json"
