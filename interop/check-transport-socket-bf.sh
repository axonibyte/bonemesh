#!/bin/sh
# brainfuck transport frame OVER A REAL SOCKET, against the shared vector
# (spec/corpus/transcripts/transport-frame.json).
#
# check-transport-bf.sh proves a brainfuck program computes the sealed frame
# the Java reference computes. This proves it can put that frame ON A WIRE:
# bf/transport-socket.bf binds an ephemeral TCP port, listens, connects to it,
# accepts, seals the frame, writes the ciphertext to the socket, reads it back
# off the accepted end and hands it out. Every byte crosses a real kernel
# socket, and the expectation is the same forty six bytes as the non-socket
# check -- a stronger claim against the same frozen number.
#
# IT TALKS TO ITSELF, and the README is explicit about what that does and does
# not show. It shows the socket path works end to end under brainstem. It does
# NOT show agreement with a peer in another language, which needs a BMX
# handshake and therefore X25519 and ML-KEM. This is step 1 of the road.
#
# NO PORT IS AGREED HERE OR ANYWHERE. brainstem's bind replies with the
# address it actually bound, so the program reads its own port out of that
# reply -- which is why this script passes no port, opens no socket of its own
# and needs no second process to coordinate with.
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

# Little endian by division rather than by reversing text: tac is GNU, and a
# loop over the remainder is POSIX and obviously right at a glance.
le() {
    _v=$1; _w=$2; _o=; _i=0
    while [ "$_i" -lt "$_w" ]; do
        _o="$_o$(printf '%02x' $(( _v % 256 )))"
        _v=$(( _v / 256 )); _i=$(( _i + 1 ))
    done
    printf '%s' "$_o"
}

hx="$repo/bf/toolchain/bfsodium/tools/hx"
[ -x "$hx" ] || { echo "no hex tool at $hx -- run bf/setup.sh" >&2; exit 1; }

echo "checking the brainfuck transport frame OVER A SOCKET against $vector"
echo "  key 32 bytes, seq $seq, plaintext $plen bytes"

in=$(mktemp); out=$(mktemp)
trap 'rm -f "$in" "$out"' EXIT
# The socket program takes a ONE byte plaintext length, because the read back
# off the socket is a counted loop and plen + 16 has to fit a cell.
printf '%s%s%02x%s' "$key" "$(le "$seq" 8)" "$plen" "$pt" | "$hx" -r > "$in"

rc=0
sh "$repo/bf/run.sh" "$repo/bf/transport-socket.bf" < "$in" > "$out" || rc=$?
[ "$rc" -eq 0 ] || { echo "the program exited $rc" >&2; exit 1; }

got=$("$hx" < "$out")
if [ "$got" != "$want" ]; then
    echo "MISMATCH" >&2
    echo "  want $want" >&2
    echo "  got  $got" >&2
    exit 1
fi
echo "OK  ct = $got"
echo "    sealed by brainfuck, sent through a TCP socket and read back,"
echo "    matching the frozen corpus that Java and Go each reproduce"
