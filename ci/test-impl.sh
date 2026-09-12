#!/bin/sh
# The single source of truth for "how is implementation X tested".
#
# Bitbucket Pipelines cannot loop and each step takes exactly one image, so the
# YAML declares one step per implementation differing only in name, image and
# cache, and every one of them runs this script. Keeping the logic here means a
# change to how a language is tested is a one-line change in one file rather than
# an edit to eight near-identical YAML blocks.
#
# Each implementation runs its own suite AND its byte-exact corpus checks from
# interop/. That second half is possible in CI and not in a reaper tenant: a
# tenant syncs one subtree and cannot see spec/corpus at all, whereas a CI clone
# has the whole repository. Before this existed the corpus checks ran nowhere.
#
# Usage: sh ci/test-impl.sh <java|go|rust|js|php|elixir|python|spec>
set -eu

impl="${1:?usage: test-impl.sh <java|go|rust|js|php|elixir|python|spec>}"
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
cd "$repo"

log() { echo "test-impl[$impl]: $*"; }

# The CI containers call it "go"; the developer driver pins "go126" alongside
# other Go versions. Same resolution the interop check scripts use, so this script
# runs unchanged in both places.
go=go126
command -v "$go" >/dev/null 2>&1 || go=go

# The seven corpus families. Java's scripts carry no -<impl> suffix (it is the
# reference implementation); every other language's do.
corpus_checks() {
  for fam in canon framing messages keyschedule agreement pqc transport keylog; do
    if [ "$1" = java ]; then s="interop/check-$fam.sh"; else s="interop/check-$fam-$1.sh"; fi
    if [ ! -f "$s" ]; then
      # A missing check is not coverage. Fail loudly rather than skipping, which
      # is the same rule interop/run-corpus-checks.sh enforces.
      echo "test-impl[$impl]: FAIL no corpus check at $s" >&2
      return 1
    fi
    log "corpus: $fam"
    sh "$s"
  done
}

case "$impl" in
  java)
    log "gradle test"
    (cd java && ./gradlew --no-daemon test)
    corpus_checks java
    ;;
  go)
    log "go test ./... (vendored, hermetic)"
    (cd go && GOTOOLCHAIN=local GOFLAGS=-mod=vendor "$go" test ./...)
    corpus_checks go
    ;;
  rust)
    log "cargo test --offline (vendored)"
    (cd rust && cargo test --offline)
    corpus_checks rust
    ;;
  js)
    log "node --test"
    (cd js && node --test)
    corpus_checks js
    ;;
  php)
    log "php tests/run.php"
    (cd php && php tests/run.php)
    corpus_checks php
    ;;
  elixir)
    log "mix test"
    (cd elixir && mix test)
    corpus_checks elixir
    ;;
  python)
    log "uv sync --locked, pytest, and the dependency-licence gate"
    (cd python && uv sync --locked && uv run pytest -q && uv run tools/check_licenses.py)
    corpus_checks python
    ;;
  spec)
    # The corpus conformance runner, plus methodology tier 3 (source-as-data),
    # which reads the spec as data and checks every implementation against it.
    # Tier 3 belongs here rather than under a language: it is one tool covering
    # all of them, and it needs the whole repository.
    log "go test ./... in spec/conformance"
    (cd spec/conformance && GOTOOLCHAIN=local GOFLAGS=-mod=vendor "$go" test ./...)
    log "tier 3: source-as-data"
    sh interop/check-spec.sh
    ;;
  *)
    echo "test-impl: unknown implementation '$impl'" >&2
    exit 2
    ;;
esac

log "green"
