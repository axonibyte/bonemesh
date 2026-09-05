#!/bin/sh
# Cross-language canon interop for the Rust port vs the shared corpus.
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
cd "$repo/rust" && cargo run --offline --quiet --bin canon_check -- "$repo/spec/corpus/canon.json"
