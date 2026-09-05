#!/bin/sh
# PHP hybrid key-agreement against spec/corpus/transcripts/handshake-agreement.json.
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
exec php "$repo/php/bin/agreement_check.php" "$repo/spec/corpus/transcripts/handshake-agreement.json"
