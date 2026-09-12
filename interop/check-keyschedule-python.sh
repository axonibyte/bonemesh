#!/bin/sh
# Python key-schedule KAT against the shared vector (spec/corpus/transcripts/keyschedule.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
exec "$here/python-run.sh" bin/keyschedule_check.py "$repo/spec/corpus/transcripts/keyschedule.json"
