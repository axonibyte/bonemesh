#!/bin/sh
# PHP canon conformance against spec/corpus/canon.json.
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
exec php "$repo/php/bin/canon_check.php" "$repo/spec/corpus/canon.json"
