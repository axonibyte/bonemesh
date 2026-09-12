#!/bin/sh
# PHP transport-frame KAT against the shared vector (spec/corpus/transcripts/transport-frame.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
exec php "$repo/php/bin/transport_check.php" "$repo/spec/corpus/transcripts/transport-frame.json"
