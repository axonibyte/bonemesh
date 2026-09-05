#!/bin/sh
# Cross-language framing interop for the Elixir port vs spec/corpus/framing.json.
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
cd "$repo/elixir" && mix run --no-start scripts/frame_check.exs "$repo/spec/corpus/framing.json"
