#!/bin/sh
# JS key-schedule KAT against the shared vector (spec/corpus/transcripts/keyschedule.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
exec node "$repo/js/bin/keyschedule_check.js" "$repo/spec/corpus/transcripts/keyschedule.json"
