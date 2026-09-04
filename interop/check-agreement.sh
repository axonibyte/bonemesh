#!/bin/sh
# Java side of the BMX hybrid key-agreement freeze: the Java implementation must
# reproduce spec/corpus/transcripts/handshake-agreement.json, which the Go
# conformance runner also reproduces (deriving ss_dh independently via
# crypto/ecdh). Agreement means Java and Go reach the same transport keys.
#
# Runs where the whole repo is present (the driver, later the M5 interop tenant).
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
vector="$repo/spec/corpus/transcripts/handshake-agreement.json"
jar="$repo/java/build/libs/bonemesh.jar"

if [ ! -f "$jar" ]; then
  echo "building the Java shadow jar first..."
  (cd "$repo/java" && ./gradlew --no-daemon --quiet shadowJar)
fi

echo "checking the Java key agreement against $vector"
java -cp "$jar" com.axonibyte.bonemesh.v3.handshake.AgreementDump "$vector"
