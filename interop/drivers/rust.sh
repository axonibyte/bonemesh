#!/bin/sh
# Rust driver for the interop harness. Speaks the same neutral driver contract.
repo=$(cd "$(dirname "$0")/../.." && pwd)
bin="$repo/rust/target/debug/interop_node"
[ -x "$bin" ] || (cd "$repo/rust" && cargo build --offline --quiet --bin interop_node)
exec "$bin" "$@"
