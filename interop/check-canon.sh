#!/bin/sh
# First cross-language interop proof: the Java certificate canonicalizer must
# reproduce, byte-for-byte, the shared corpus (spec/corpus/canon.json) that the
# Go conformance runner also validates. Agreement here means a certificate
# signed by one implementation verifies under any other.
#
# Runs where the whole repo is present (the driver, and later the M5 interop
# tenant) — not inside a single-language reaper tenant, which syncs only its
# own subtree. Exits non-zero on any mismatch.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
corpus="$repo/spec/corpus/canon.json"
jar="$repo/java/build/libs/bonemesh.jar"

if [ ! -f "$jar" ]; then
  echo "building the Java shadow jar first..."
  (cd "$repo/java" && ./gradlew --no-daemon --quiet shadowJar)
fi

echo "checking the Java canonicalizer against $corpus"
java -cp "$jar" com.axonibyte.bonemesh.v3.cert.CanonDump "$corpus"
