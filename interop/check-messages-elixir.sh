#!/bin/sh
# Cross-language messages interop for the Elixir port vs the shared corpus.
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
cd "$repo/elixir" && mix run --no-start scripts/message_check.exs "$repo/spec/corpus/messages.json"
