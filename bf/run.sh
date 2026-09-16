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
# WHAT THE SCRATCH DIRECTORY IS FOR. The program spawns an interpreter on a
# bfsodium routine BY NAME, resolved against the broker's working directory,
# so that directory has to contain the interpreter and every routine a program
# might name. They are copied rather than symlinked, because the broker
# resolves the name against its own working directory and a symlink would
# reach back into the toolchain this is deliberately isolated from.
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

d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT

cp "$bfs/tools/bfi" "$d/bfi"
cp "$prog" "$d/prog.bf"
# Every routine a program might spawn, flattened in under its basename, which
# is how the broker will resolve it.
for r in "$bfs"/*/*.bf; do
    case "$r" in */programs/*) continue ;; esac
    cp "$r" "$d/$(basename "$r")"
done

# stdin and stdout are inherited untouched: the shell already connected them
# to whatever the caller meant, and the broker hands them to the program.
( cd "$d" && timeout "${BF_TIMEOUT:-3600}" "$bs/build/brainstem" \
    --op-timeout "${BF_OP_TIMEOUT:-1800000}" -- ./bfi ./prog.bf )
