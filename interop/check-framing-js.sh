#!/bin/sh
# JS frame classifier verdicts against the shared corpus (spec/corpus/framing.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
exec node "$repo/js/bin/interop_checks.js" framing "$repo/spec/corpus/framing.json"
