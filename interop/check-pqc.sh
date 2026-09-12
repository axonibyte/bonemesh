#!/bin/sh
# Java post-quantum interop against the shared vector
# (spec/corpus/transcripts/pqc-interop.json). Java produced the vector, so this
# pass is not the cross-language proof -- the other six implementations verifying
# it is. What this catches is the vector drifting out from under its producer: a
# BouncyCastle upgrade that changes an encoding or breaks a primitive would leave
# the committed bytes unreproducible, and nothing else would notice.
#
# Java is also the only implementation that checks BOTH halves, since it is keyed
# by the expanded ML-KEM decapsulation key the vector ships.
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
jar="$repo/java/build/libs/bonemesh.jar"
sh "$here/ensure-jar.sh"
echo "checking the Java post-quantum primitives against the shared vector"
java -cp "$jar" com.axonibyte.bonemesh.v3.crypto.PqcDump "$repo/spec/corpus/transcripts/pqc-interop.json"
