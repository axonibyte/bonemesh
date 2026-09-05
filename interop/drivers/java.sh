#!/bin/sh
# Java driver for the interop harness. Speaks the neutral driver contract
# (see ../README.md); the harness invokes it exactly as it invokes every other
# driver.
repo=$(cd "$(dirname "$0")/../.." && pwd)
exec java -cp "$repo/java/build/libs/bonemesh.jar" \
  com.axonibyte.bonemesh.v3.tools.InteropNode "$@"
