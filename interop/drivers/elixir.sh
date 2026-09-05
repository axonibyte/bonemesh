#!/bin/sh
# Elixir driver for the interop harness. Speaks the same neutral driver contract.
repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo/elixir" && exec mix run --no-start scripts/interop_node.exs "$@"
