#!/bin/sh
# PHP driver for the interop harness. Speaks the same neutral driver contract.
# No build step; PQC reaches the platform's openssl 3.5 CLI at runtime.
repo=$(cd "$(dirname "$0")/../.." && pwd)
exec php "$repo/php/bin/interop_node.php" "$@"
