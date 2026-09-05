#!/bin/sh
# Elixir driver for the interop harness. Speaks the same neutral driver contract.
#
# `mix run` holds the build-directory lock for its lifetime, so two concurrent
# invocations from this one project deadlock. Tiers that run a single Elixir node
# at a time are unaffected. A tier that runs several Elixir nodes at once (tier 8)
# precompiles first and sets BONEMESH_ELIXIR_NO_COMPILE=1, which adds
# --no-compile here so the concurrent runs skip the lock.
repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo/elixir" && exec mix run ${BONEMESH_ELIXIR_NO_COMPILE:+--no-compile} --no-start scripts/interop_node.exs "$@"
