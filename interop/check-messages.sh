#!/bin/sh
# Cross-language message-schema interop: the Java validator must reach the same
# valid/invalid verdict (and reason tag) as the Go conformance runner on every
# case in spec/corpus/messages.json.
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
jar="$repo/java/build/libs/bonemesh.jar"
[ -f "$jar" ] || (cd "$repo/java" && ./gradlew --no-daemon --quiet shadowJar)
echo "checking the Java message validator against spec/corpus/messages.json"
java -cp "$jar" com.axonibyte.bonemesh.v3.message.MessageCheck "$repo/spec/corpus/messages.json"
