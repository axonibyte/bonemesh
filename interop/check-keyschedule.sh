#!/bin/sh
# Cross-language freeze of the BMX key schedule: the Java SymmetricState must
# reproduce the shared vector (spec/corpus/transcripts/keyschedule.json) that
# the Go conformance runner also reproduces independently. Agreement means a
# Java node and a Go node derive identical transcript hashes and transport keys.
#
# Runs where the whole repo is present (the driver, and later the M5 interop
# tenant). Exits non-zero on any mismatch.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
vector="$repo/spec/corpus/transcripts/keyschedule.json"
jar="$repo/java/build/libs/bonemesh.jar"

if [ ! -f "$jar" ]; then
  echo "building the Java shadow jar first..."
  (cd "$repo/java" && ./gradlew --no-daemon --quiet shadowJar)
fi

echo "checking the Java key schedule against $vector"
java -cp "$jar" com.axonibyte.bonemesh.v3.handshake.KsDump "$vector"
