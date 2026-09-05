#!/bin/sh
# JavaScript (Node.js) driver for the interop harness. Speaks the same neutral
# driver contract. No build step — pure Node standard library.
repo=$(cd "$(dirname "$0")/../.." && pwd)
exec node "$repo/js/bin/interop_node.js" "$@"
