#!/bin/sh
# brainfuck key-schedule KAT against the shared vector
# (spec/corpus/transcripts/keyschedule.json).
#
# The program under test is bf/keyschedule.bf: a file containing nothing but
# the eight brainfuck instructions and inert comments, which holds the
# transcript hash and the chaining key on its own tape and spawns an
# interpreter on a bfsodium routine for each step of the schedule. No shell
# in the middle -- that is the claim, and it is why this check exists
# separately from check-transport-bf.sh, which is a single call.
#
# INCREMENTAL BY DESIGN, and that is a property of the vector rather than a
# concession. keyschedule.json freezes all TEN intermediates -- h_init,
# h_after_mesh, ck_after_dh, ck_after_kem, ct1, h_after_ct1, ct2,
# h_after_ct2 and both transport keys -- so an implementation can be checked
# at every stage rather than only at the end. This script compares however
# many the program emits, in schedule order, and says which are still
# unimplemented. A corpus that published only the transport keys would have
# forced an all-or-nothing implementation.
#
# THIS SCRIPT DOES THE JSON AND NONE OF THE CRYPTO, the same division the Go
# port makes when it reads the vector with Go's JSON parser rather than with
# Go's crypto.
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/.." && pwd)
vector="$repo/spec/corpus/transcripts/keyschedule.json"

[ -r "$vector" ] || { echo "no vector at $vector" >&2; exit 1; }

sh "$repo/bf/setup.sh"
sh "$repo/bf/build.sh" --check

field() { sed -n "s/.*\"$1\": *\"\([0-9a-f]*\)\".*/\1/p" "$vector"; }

# The outputs in schedule order, which is the order the program emits them.
# Adding a step to the program means the next name here starts being compared
# with no change to this script.
names='h_init h_after_mesh ck_after_dh ck_after_kem ct1_hex h_after_ct1 ct2_hex h_after_ct2 transport_key_i2r transport_key_r2i'

hx="$repo/bf/toolchain/bfsodium/tools/hx"
[ -x "$hx" ] || { echo "no hex tool at $hx -- run bf/setup.sh" >&2; exit 1; }

echo "checking the brainfuck key schedule against $vector"

out=$(mktemp)
trap 'rm -f "$out"' EXIT

# The program reads mesh, ss_dh and ss_kem from stdin, each variable one
# preceded by a single length byte. The shell builds that stream out of the
# vector; the brainfuck does every cryptographic step.
ks_in() {
    m=$(field mesh_hex)
    printf "%02x%s" $(( ${#m} / 2 )) "$m"
    field ss_dh_hex
    field ss_kem_hex
}

rc=0
ks_in | "$hx" -r | sh "$repo/bf/run.sh" "$repo/bf/keyschedule.bf" > "$out" || rc=$?
[ "$rc" -eq 0 ] || { echo "the program exited $rc" >&2; exit 1; }

got=$("$hx" < "$out")
pos=0
done_n=0
for n in $names; do
    want=$(field "$n")
    [ -n "$want" ] || { echo "the vector has no $n" >&2; exit 1; }
    len=${#want}
    # Past what the program emitted? Then this step is not implemented yet,
    # and so is every step after it -- the schedule is a sequence.
    if [ $(( pos + len )) -gt ${#got} ]; then
        echo "  -- $n and the steps after it are not implemented yet"
        break
    fi
    mine=$(printf '%s' "$got" | cut -c $(( pos + 1 ))-$(( pos + len )))
    if [ "$mine" != "$want" ]; then
        echo "MISMATCH at $n" >&2
        echo "  want $want" >&2
        echo "  got  $mine" >&2
        exit 1
    fi
    echo "  ok $n"
    pos=$(( pos + len ))
    done_n=$(( done_n + 1 ))
done

# Bytes left over mean the program emitted something this script does not
# know how to name, which is a desync rather than a pass.
if [ "$pos" -ne "${#got}" ]; then
    echo "the program emitted $(( ${#got} / 2 )) bytes; $(( pos / 2 )) were accounted for" >&2
    exit 1
fi

echo "OK  $done_n of 10 frozen values reproduced by brainfuck"
[ "$done_n" -eq 10 ] || echo "    (the remaining steps are listed in bf/keyschedule.poke)"
