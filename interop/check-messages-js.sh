#!/bin/sh
# JS message validator verdicts against the shared corpus (spec/corpus/messages.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
exec node "$repo/js/bin/interop_checks.js" messages "$repo/spec/corpus/messages.json"
