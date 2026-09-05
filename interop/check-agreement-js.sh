#!/bin/sh
# JS hybrid key-agreement against the shared vector (spec/corpus/transcripts/handshake-agreement.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
exec node "$repo/js/bin/agreement_check.js" "$repo/spec/corpus/transcripts/handshake-agreement.json"
