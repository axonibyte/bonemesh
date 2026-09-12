#!/bin/sh
# Cross-language splitting interop: the Java splitter must produce exactly the
# segment byte boundaries pinned in the shared corpus (spec/corpus/chunk.json), and
# must agree with its pinned section 0 constants.
#
# Runs where the whole repo is present (the driver, and the interop tenant).
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
corpus="$repo/spec/corpus/chunk.json"
jar="$repo/java/build/libs/bonemesh.jar"

sh "$here/ensure-jar.sh"

echo "checking the Java splitter against $corpus"
java -cp "$jar" com.axonibyte.bonemesh.v3.message.ChunkCheck "$corpus"
