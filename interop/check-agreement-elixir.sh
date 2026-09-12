#!/bin/sh
# Elixir hybrid key-agreement against the shared vector (spec/corpus/transcripts/handshake-agreement.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
echo "checking the Elixir key agreement against the shared vector"
cd "$repo/elixir" && mix run --no-start scripts/agreement_check.exs "$repo/spec/corpus/transcripts/handshake-agreement.json"
