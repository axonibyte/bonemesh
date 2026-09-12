#!/bin/sh
# Python post-quantum interop: verifies a Java ML-DSA-65 signature
# (spec/corpus/transcripts/pqc-interop.json); ML-KEM proven live by the matrix.
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
exec "$here/python-run.sh" bin/pqc_check.py "$repo/spec/corpus/transcripts/pqc-interop.json"
