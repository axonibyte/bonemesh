#!/bin/sh
# Go driver for the interop harness. Speaks the same neutral driver contract.
# Builds offline from the committed vendor/ tree; prefers the pinned go126
# toolchain when present, else whatever "go" is on PATH.
repo=$(cd "$(dirname "$0")/../.." && pwd)
bin="$repo/go/interop_node"
sh "$repo/interop/ensure-bin.sh" go interop_node
exec "$bin" "$@"
