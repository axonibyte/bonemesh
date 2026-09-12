#!/bin/sh
# Go key-log reader against the shared vector (spec/corpus/keylog.json).
#
# Also the byte-exact corpus comparison for the vector that go/cmd/bonemesh-inspect's
# unit test mirrors in code: that test cannot read spec/ from inside its tenant, so
# drift between the mirror and the committed corpus surfaces here.
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
go=go126
command -v "$go" >/dev/null 2>&1 || go=go
cd "$repo/go" && GOTOOLCHAIN=local GOFLAGS=-mod=vendor "$go" run ./cmd/keylog_check "$repo/spec/corpus/keylog.json"
