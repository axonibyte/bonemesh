#!/bin/sh
# Cross-language key-schedule freeze for the Elixir port: it must reproduce
# spec/corpus/transcripts/keyschedule.json, which the Java and Go runners also
# reproduce. Agreement means all three derive identical transport keys.
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
echo "checking the Elixir key schedule against the shared vector"
cd "$repo/elixir" && mix run --no-start scripts/keyschedule_check.exs "$repo/spec/corpus/transcripts/keyschedule.json"
