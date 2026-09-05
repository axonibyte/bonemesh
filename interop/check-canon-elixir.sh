#!/bin/sh
# Cross-language canon interop for the Elixir port: its canonicalizer must
# reproduce spec/corpus/canon.json byte-for-byte, the same file Java and Go
# validate. Runs where the whole repo is present (the driver, later M5 interop).
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
echo "checking the Elixir canonicalizer against spec/corpus/canon.json"
cd "$repo/elixir" && mix run --no-start scripts/canon_check.exs "$repo/spec/corpus/canon.json"
