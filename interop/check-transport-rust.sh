#!/bin/sh
# Rust transport-frame KAT against the shared vector (spec/corpus/transcripts/transport-frame.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
cd "$repo/rust" && cargo run --offline --quiet --bin transport_check -- "$repo/spec/corpus/transcripts/transport-frame.json"
