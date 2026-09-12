#!/bin/sh
# Elixir transport-frame KAT against the shared vector (spec/corpus/transcripts/transport-frame.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
echo "checking the Elixir transport frame against the shared vector"
cd "$repo/elixir" && mix run --no-start scripts/transport_check.exs "$repo/spec/corpus/transcripts/transport-frame.json"
