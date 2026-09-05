#!/bin/sh
# Cross-language keyschedule interop for the Rust port vs the shared vector.
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
cd "$repo/rust" && cargo run --offline --quiet --bin keyschedule_check -- "$repo/spec/corpus/transcripts/keyschedule.json"
