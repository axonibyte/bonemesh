#!/bin/sh
# PHP key-log reader against the shared vector (spec/corpus/keylog.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
exec php "$repo/php/bin/keylog_check.php" "$repo/spec/corpus/keylog.json"
