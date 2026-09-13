#!/bin/sh
# JS splitting against the shared corpus (spec/corpus/chunk.json): the pinned
# section 0 constants and the exact byte boundaries the cuts land on.
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
exec node "$repo/js/bin/interop_checks.js" chunk "$repo/spec/corpus/chunk.json"
