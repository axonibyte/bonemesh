#!/bin/sh
# Python frame classifier verdicts against the shared corpus (spec/corpus/framing.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
exec "$here/python-run.sh" bin/interop_checks.py framing "$repo/spec/corpus/framing.json"
