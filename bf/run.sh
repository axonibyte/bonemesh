#!/bin/sh
# run.sh -- run one bf/ program under the pinned broker.
#
#   sh bf/run.sh transport-frame.bf < input > output
#
# A brainfuck program in this directory is not run the way a bfsodium routine
# is. A routine is `bfi routine.bf < input`: pure computation, stdin to
# stdout. A program needs a BROKER on the other end of its stdin and stdout,
# because what it does is SEQUENCE routines by spawning them, and the eight
# instructions cannot spawn anything on their own.
#
# THE BROKER RUNS IN THE PINNED CHECKOUT, and nothing is copied anywhere. A
# program spawns a routine BY NAME, resolved against the broker's working
# directory, so that directory is bfsodium's own tree and a routine is named
# exactly as bfsodium names it: sha256/hkdf.bf, not hkdf.bf.
#
# IT USED TO FLATTEN EVERY ROUTINE INTO A SCRATCH DIRECTORY UNDER ITS BASENAME
# and that was wrong in two ways, one slow and one dangerous.
#
# The dangerous one first. bfsodium has a sha256 family and a sha512 family
# and five of their basenames are the same -- expand, hashcore, hkdf, hmac,
# round. Flattened, the later one wins, so a program asking for hkdf.bf
# silently got HKDF-SHA-512 while its own transcript said SHA256. That is not
# a name clash, it is THE HARNESS CHOOSING THE CIPHER SUITE, and it is exactly
# the binding that must not be implicit in a protocol whose suite string is
# hashed into h_init. A qualified name puts the choice back in the program,
# where the corpus can check it. It was found by bumping the pin and watching
# ck_after_dh disagree with the frozen vector; nothing else could see it.
#
# The slow one: it copied every routine bfsodium has, 58 files and 155 MB, to
# make three of them reachable -- once per program run, and growing with
# everything bfsodium would ever add.
#
# AND THE ISOLATION IT CLAIMED WAS NEVER REAL. The old comment said a symlink
# "would reach back into the toolchain this is deliberately isolated from",
# but brainstem's path check refuses exactly two things, an empty path and an
# embedded NUL, and its own comment says why: "brainstem is not a sandbox" has
# been in its CONVENTIONS since the first commit. A program could always have
# named an absolute path. What the copy did buy is a checkout that stays
# pristine, and bf/setup.sh now asserts that directly instead.
#
# THE WALL CLOCK BOUND IS GENEROUS ON PURPOSE. Brainfuck has no arithmetic:
# SHA-256 of one 64 byte block is about 1.15 billion interpreter instructions,
# roughly two seconds, and the AEAD is an order of magnitude more. The point
# of a bound is that a HANG ends, not that a slow run is punished.
set -eu

[ $# -eq 1 ] || { echo "usage: run.sh PROGRAM.bf < input" >&2; exit 2; }
prog=$1

# A relative program path means what it meant where it was TYPED, so it is
# made absolute before the cd below moves the ground under it.
case $prog in
    /*) ;;
    *)  prog=$(pwd)/$prog ;;
esac

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=${BF_TOOLCHAIN:-$here/toolchain}
bfs=$root/bfsodium
bs=$root/brainstem

[ -r "$prog" ] || { echo "run: no such program: $prog" >&2; exit 2; }
[ -x "$bs/build/brainstem" ] || { echo "run: no broker -- run bf/setup.sh" >&2; exit 2; }
[ -x "$bfs/tools/bfi" ]      || { echo "run: no interpreter -- run bf/setup.sh" >&2; exit 2; }

# stdin and stdout are inherited untouched: the shell already connected them
# to whatever the caller meant, and the broker hands them to the program.
#
# The program is named by the absolute path made above, because the cd moves
# the ground under a relative one. The interpreter is named relative to the
# checkout and the broker RECORDS it, so a spawn frame with a zero length
# path still means "the interpreter I am running under" and no program has
# to carry its name.
( cd "$bfs" && timeout "${BF_TIMEOUT:-3600}" "$bs/build/brainstem" \
    --op-timeout "${BF_OP_TIMEOUT:-1800000}" -- ./tools/bfi "$prog" )
