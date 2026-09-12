#!/bin/sh
# Elixir key-log reader against the shared vector (spec/corpus/keylog.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
echo "checking the Elixir key-log reader against the shared vector"
cd "$repo/elixir" && mix run --no-start scripts/keylog_check.exs "$repo/spec/corpus/keylog.json"
