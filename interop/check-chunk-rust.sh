#!/bin/sh
# Rust splitting against the shared corpus (spec/corpus/chunk.json): the pinned
# section 0 constants and the exact byte boundaries the cuts land on.
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
cd "$repo/rust" && cargo run --offline --quiet --bin interop_checks -- chunk "$repo/spec/corpus/chunk.json"
