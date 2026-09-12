#!/bin/sh
# Ensures java/build/libs/bonemesh.jar is at least as new as every Java source
# input, rebuilding it when it is not.
#
# The Java check scripts previously built the jar only when it was *absent*
# ("[ -f "$jar" ] || gradlew shadowJar"), so editing a Java source and re-running
# a corpus check silently verified the PREVIOUS build -- a check that reports PASS
# for code that is not the code under test. An mtime comparison fixes that
# without paying gradle's ~20s no-daemon startup on every check: when the jar is
# current this exits in milliseconds.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
jar="$repo/java/build/libs/bonemesh.jar"

build() {
  echo "building the Java shadow jar ($1)..."
  (cd "$repo/java" && ./gradlew --no-daemon --quiet shadowJar)
}

if [ ! -f "$jar" ]; then
  build "no jar present"
  exit 0
fi

# -print -quit stops at the first newer input, so this stays cheap on a big tree.
stale=$(find "$repo/java/src" "$repo/java/build.gradle" "$repo/java/gradle.properties" \
          -newer "$jar" -print -quit 2>/dev/null || true)
if [ -n "$stale" ]; then
  build "sources newer than the jar"
fi
