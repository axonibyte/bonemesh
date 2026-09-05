#!/bin/sh
# JS post-quantum interop: verifies a Java ML-DSA-65 signature (spec/corpus/transcripts/pqc-interop.json); ML-KEM proven live by the matrix.
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
exec node "$repo/js/bin/pqc_check.js" "$repo/spec/corpus/transcripts/pqc-interop.json"
