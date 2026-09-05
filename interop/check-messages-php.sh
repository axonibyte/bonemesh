#!/bin/sh
# PHP message validator verdicts against spec/corpus/messages.json.
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
exec php "$repo/php/bin/interop_checks.php" messages "$repo/spec/corpus/messages.json"
