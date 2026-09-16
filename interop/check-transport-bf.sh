#!/bin/sh
# brainfuck transport-frame KAT against the shared vector
# (spec/corpus/transcripts/transport-frame.json).
#
# The program under test is bf/transport-frame.bf: a file containing nothing
# but the eight brainfuck instructions and inert comments, which constructs the
# BMX nonce from the sequence number and seals the frame with bfsodium's
# ChaCha20-Poly1305 through the brainstem broker.
#
# THIS SCRIPT DOES THE JSON AND NONE OF THE CRYPTO. It pulls three hex fields
# out of the vector with sed and turns them into bytes; every cryptographic
# operation, and the nonce construction that is the protocol's own detail,
# happens in brainfuck. That is the same division the Go port makes when it
# reads the vector with Go's JSON parser rather than with Go's crypto.
#
# Minutes rather than milliseconds, and that is the honest cost of the thing.
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
vector="$repo/spec/corpus/transcripts/transport-frame.json"

[ -r "$vector" ] || { echo "no vector at $vector" >&2; exit 1; }

sh "$repo/bf/setup.sh"
sh "$repo/bf/build.sh" --check

field() { sed -n "s/.*\"$1\": *\"\([0-9a-f]*\)\".*/\1/p" "$vector"; }
num()   { sed -n "s/.*\"$1\": *\([0-9]*\).*/\1/p" "$vector"; }

key=$(field key_hex)
pt=$(field inner_plaintext_hex)
want=$(field ct_hex)
seq=$(num seq)

[ -n "$key" ] && [ -n "$pt" ] && [ -n "$want" ] && [ -n "$seq" ] \
    || { echo "could not read the vector" >&2; exit 1; }

plen=$(( ${#pt} / 2 ))

# LITTLE ENDIAN BY DIVISION, not by reversing text. `tac` is GNU and this
# repository is checked on more than one kind of machine; a loop over the
# remainder is POSIX and is obviously right at a glance, which a pipeline of
# sed and tr is not.
#
# The seq goes in little endian because that is the order the nonce wants it:
# the program forwards those eight bytes unswapped, so the construction stays
# visible in the vector rather than hidden inside a byte order.
le() {   # le VALUE WIDTH -- little endian hex
    _v=$1; _w=$2; _o=; _i=0
    while [ "$_i" -lt "$_w" ]; do
        _o="$_o$(printf '%02x' $(( _v % 256 )))"
        _v=$(( _v / 256 )); _i=$(( _i + 1 ))
    done
    printf '%s' "$_o"
}

# hx is bfsodium's, built by bf/setup.sh, and is used instead of xxd for the
# same reason: xxd ships with vim and is not a thing to require of a CI image
# when the toolchain already carries a hex tool.
hx="$repo/bf/toolchain/bfsodium/tools/hx"
[ -x "$hx" ] || { echo "no hex tool at $hx -- run bf/setup.sh" >&2; exit 1; }

echo "checking the brainfuck transport frame against $vector"
echo "  key 32 bytes, seq $seq, plaintext $plen bytes"

in=$(mktemp); out=$(mktemp)
trap 'rm -f "$in" "$out"' EXIT
printf '%s%s%s%s' "$key" "$(le "$seq" 8)" "$(le "$plen" 2)" "$pt" | "$hx" -r > "$in"

rc=0
sh "$repo/bf/run.sh" "$repo/bf/transport-frame.bf" < "$in" > "$out" || rc=$?
[ "$rc" -eq 0 ] || { echo "the program exited $rc" >&2; exit 1; }

got=$("$hx" < "$out")
if [ "$got" != "$want" ]; then
    echo "MISMATCH" >&2
    echo "  want $want" >&2
    echo "  got  $got" >&2
    exit 1
fi
echo "OK  ct = $got"
echo "    sealed by brainfuck, agreeing with the Java reference and the Go runner"
