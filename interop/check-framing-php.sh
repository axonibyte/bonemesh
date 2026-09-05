#!/bin/sh
# PHP frame classifier verdicts against spec/corpus/framing.json.
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
exec php "$repo/php/bin/interop_checks.php" framing "$repo/spec/corpus/framing.json"
