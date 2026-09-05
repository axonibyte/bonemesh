#!/bin/sh
# Cross-language framing interop: the Java frame classifier must reach the same
# accept/reject verdict as the Go conformance runner on every case in the shared
# corpus (spec/corpus/framing.json). This is the defect-D7 size-cap contract,
# agreed across languages.
#
# Runs where the whole repo is present (the driver, later the M5 interop tenant).
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
corpus="$repo/spec/corpus/framing.json"
jar="$repo/java/build/libs/bonemesh.jar"

if [ ! -f "$jar" ]; then
  echo "building the Java shadow jar first..."
  (cd "$repo/java" && ./gradlew --no-daemon --quiet shadowJar)
fi

echo "checking the Java frame classifier against $corpus"
java -cp "$jar" com.axonibyte.bonemesh.v3.transport.FrameCheck "$corpus"
