#!/bin/sh
# JS transport-frame KAT against the shared vector (spec/corpus/transcripts/transport-frame.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
exec node "$repo/js/bin/transport_check.js" "$repo/spec/corpus/transcripts/transport-frame.json"
