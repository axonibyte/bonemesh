#!/bin/sh
# Python hybrid key-agreement against the shared vector (spec/corpus/transcripts/handshake-agreement.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
exec "$here/python-run.sh" bin/agreement_check.py "$repo/spec/corpus/transcripts/handshake-agreement.json"
