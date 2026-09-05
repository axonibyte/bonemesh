#!/bin/sh
# Cross-language messages interop for the Rust port vs the shared corpus.
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
cd "$repo/rust" && cargo run --offline --quiet --bin interop_checks -- messages "$repo/spec/corpus/messages.json"
