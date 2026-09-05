#!/bin/sh
# Cross-language post-quantum interop: Elixir verifies a Java-made ML-DSA
# signature and decapsulates a Java-made ML-KEM ciphertext (shared vector
# spec/corpus/transcripts/pqc-interop.json). Resolves the deferred PQC interop.
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
cd "$repo/elixir" && mix run --no-start scripts/pqc_check.exs "$repo/spec/corpus/transcripts/pqc-interop.json"
