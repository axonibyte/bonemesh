#!/bin/sh
# JS key-log reader against the shared vector (spec/corpus/keylog.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
exec node "$repo/js/bin/keylog_check.js" "$repo/spec/corpus/keylog.json"
