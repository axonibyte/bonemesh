#!/bin/sh
# Cross-language agreement interop for the Rust port vs the shared vector.
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
cd "$repo/rust" && cargo run --offline --quiet --bin agreement_check -- "$repo/spec/corpus/transcripts/handshake-agreement.json"
