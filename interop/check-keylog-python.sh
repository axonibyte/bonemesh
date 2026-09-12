#!/bin/sh
# Python key-log reader against the shared vector (spec/corpus/keylog.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
exec "$here/python-run.sh" bin/keylog_check.py "$repo/spec/corpus/keylog.json"
