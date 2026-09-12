#!/bin/sh
# Elixir splitting against the shared corpus (spec/corpus/chunk.json): the pinned
# section 0 constants and the exact byte boundaries the cuts land on.
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
cd "$repo/elixir" && mix run --no-start scripts/chunk_check.exs "$repo/spec/corpus/chunk.json"
