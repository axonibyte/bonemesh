#!/bin/sh
# Cross-language post-quantum interop for the Rust port: Rust verifies a
# Java-made ML-DSA signature and decapsulates a Java-made ML-KEM ciphertext
# (shared vector spec/corpus/transcripts/pqc-interop.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
cd "$repo/rust" && cargo run --offline --quiet --bin pqc_check -- "$repo/spec/corpus/transcripts/pqc-interop.json"
