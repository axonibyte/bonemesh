#!/bin/sh
# Java key-log reader against the shared vector (spec/corpus/keylog.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
jar="$repo/java/build/libs/bonemesh.jar"
sh "$here/ensure-jar.sh"
echo "checking the Java key-log reader against the shared vector"
java -cp "$jar" com.axonibyte.bonemesh.v3.transport.KeylogCheck "$repo/spec/corpus/keylog.json"
