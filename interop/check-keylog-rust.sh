#!/bin/sh
# Rust key-log reader against the shared vector (spec/corpus/keylog.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
cd "$repo/rust" && cargo run --offline --quiet --bin keylog_check -- "$repo/spec/corpus/keylog.json"
