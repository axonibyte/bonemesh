#!/bin/sh
# Python transport-frame KAT against the shared vector (spec/corpus/transcripts/transport-frame.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
exec "$here/python-run.sh" bin/transport_check.py "$repo/spec/corpus/transcripts/transport-frame.json"
