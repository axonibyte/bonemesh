#!/bin/sh
# Python message validator verdicts against the shared corpus (spec/corpus/messages.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
exec "$here/python-run.sh" bin/interop_checks.py messages "$repo/spec/corpus/messages.json"
