#!/bin/sh
# Cross-language transport-frame freeze: the Java transport must reproduce
# spec/corpus/transcripts/transport-frame.json, which the Go runner also
# reproduces (and opens) with x/crypto. Agreement means a node in one language
# can read the encrypted frames another sealed.
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
jar="$repo/java/build/libs/bonemesh.jar"
[ -f "$jar" ] || (cd "$repo/java" && ./gradlew --no-daemon --quiet shadowJar)
echo "checking the Java transport frame against the shared vector"
java -cp "$jar" com.axonibyte.bonemesh.v3.transport.TransportDump "$repo/spec/corpus/transcripts/transport-frame.json"
