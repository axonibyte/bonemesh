#!/bin/sh
# PHP post-quantum interop: verifies a Java ML-DSA-65 signature; ML-KEM proven live by the matrix.
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
exec php "$repo/php/bin/pqc_check.php" "$repo/spec/corpus/transcripts/pqc-interop.json"
