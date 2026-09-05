#!/bin/sh
# Cross-language framing interop for the Rust port vs the shared corpus.
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
cd "$repo/rust" && cargo run --offline --quiet --bin interop_checks -- framing "$repo/spec/corpus/framing.json"
