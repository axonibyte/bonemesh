#!/bin/sh
# Python canon conformance against the shared corpus (spec/corpus/canon.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
exec "$here/python-run.sh" bin/canon_check.py "$repo/spec/corpus/canon.json"
