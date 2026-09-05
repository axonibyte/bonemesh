#!/bin/sh
# JS canon conformance against the shared corpus (spec/corpus/canon.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
exec node "$repo/js/bin/canon_check.js" "$repo/spec/corpus/canon.json"
