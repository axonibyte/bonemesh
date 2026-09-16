#!/bin/sh
# build.sh -- expand every .poke in this directory into committed brainfuck.
#
#   sh bf/build.sh            expand, writing the .bf files
#   sh bf/build.sh --check    compare only; write nothing
#
# --check is what the interop scripts run. A provenance check that REWROTE the
# tree would pass by fixing the thing it was meant to report.
#
# THREE STEPS, AND THE MIDDLE ONE IS THE INTERESTING ONE.
#
#   1. brainstem's bfgen --annotate expands the skeleton and carries its "#"
#      comments through as ";" comments. Without the flag they are dropped,
#      which is right for brainstem's own fixtures and wrong here: a file
#      nobody can read is not a language implementation anybody can review.
#
#   2. bfsodium's bflint --fix makes the prose PORTABLE. This is not a style
#      pass. A full stop is the brainfuck instruction '.', a comma is ',', and
#      ordinary English dropped into a .bf file EXECUTES -- so the lint
#      rewrites those bytes to safe lookalikes and then proves the file still
#      portable by extracting the instruction stream twice, once treating ';'
#      as a comment to end of line and once not, and requiring the two to be
#      identical. That is why the prose below reads "ABI 1_1" and ends its
#      sentences with a semicolon.
#
#   3. bfsodium's bflayout puts brainfuck on the left and English on the
#      right, which is how a skeleton is read rather than how it is written.
#
# AND THE INSTRUCTION STREAM MUST NOT MOVE, which is checked here rather than
# hoped for: the laid-out file is compared against a BARE expansion of the
# same skeleton, instruction for instruction. Prose in a brainfuck file is
# only acceptable if it cannot change the program.
set -eu

check=no
bad=0
if [ "${1:-}" = "--check" ]; then check=yes; shift; fi
[ $# -eq 0 ] || { echo "usage: build.sh [--check]" >&2; exit 2; }

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=${BF_TOOLCHAIN:-$here/toolchain}
bfs=$root/bfsodium
bs=$root/brainstem

[ -r "$bs/tools/bfgen.sh" ] || { echo "build: run bf/setup.sh first" >&2; exit 2; }
command -v perl >/dev/null 2>&1 || { echo "build: bflayout needs perl" >&2; exit 2; }
[ -x "$bfs/tools/bflint" ] || cc -O2 -std=c99 -o "$bfs/tools/bflint" "$bfs/tools/bflint.c"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cd "$here"
for p in *.poke; do
    out="${p%.poke}.bf"

    sh "$bs/tools/bfgen.sh" --annotate "$p" > "$tmp/ann"
    "$bfs/tools/bflint" --fix "$tmp/ann" >/dev/null
    ( cd "$bfs" && perl tools/bflayout.pl "$tmp/ann" ) > "$tmp/laid"

    sh "$bs/tools/bfgen.sh" "$p" > "$tmp/bare"
    tr -cd '><+-.,[]' < "$tmp/laid" > "$tmp/a"
    tr -cd '><+-.,[]' < "$tmp/bare" > "$tmp/b"
    if ! cmp -s "$tmp/a" "$tmp/b"; then
        echo "build: $out would change the program; the prose is not inert" >&2
        exit 1
    fi

    if [ -f "$out" ] && cmp -s "$tmp/laid" "$out"; then
        [ "$check" = yes ] || echo "  unchanged $out"
    elif [ "$check" = yes ]; then
        echo "build: $out is not what this script makes of $p" >&2
        bad=1
    else
        cp "$tmp/laid" "$out"
        echo "  wrote $out"
    fi
done

[ "$bad" -eq 0 ] || exit 1
[ "$check" = yes ] && echo "build: every program matches its skeleton"
exit 0
