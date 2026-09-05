#!/bin/sh
# Cross-language post-quantum interop for the Go port: Go verifies a Java-made
# ML-DSA-65 signature from the shared vector
# (spec/corpus/transcripts/pqc-interop.json). ML-KEM-768 interop with Java is
# proven live by the interop matrix (the vector ships an expanded decapsulation
# key that Go's seed-keyed stdlib crypto/mlkem does not ingest, and which never
# crosses a node); see the pqc_check tool's doc comment.
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
go=go126
command -v "$go" >/dev/null 2>&1 || go=go
cd "$repo/go" && GOTOOLCHAIN=local GOFLAGS=-mod=vendor "$go" run ./cmd/pqc_check "$repo/spec/corpus/transcripts/pqc-interop.json"
