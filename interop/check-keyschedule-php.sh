#!/bin/sh
# PHP key-schedule KAT against spec/corpus/transcripts/keyschedule.json.
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
exec php "$repo/php/bin/keyschedule_check.php" "$repo/spec/corpus/transcripts/keyschedule.json"
