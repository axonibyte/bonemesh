#!/bin/sh
# setup.sh -- fetch and build the pinned brainfuck toolchain, under bf/.
#
#   sh bf/setup.sh
#
# THE DEPENDENCY DIRECTION IS STRICT and it is worth saying why. bfsodium is a
# general brainfuck crypto library; brainstem is a general syscall broker for
# standard brainfuck. Neither knows BoneMesh exists and neither should: the
# next brainfuck library that wants to chain primitives has nothing to do with
# cryptography, and the next protocol wanting brainfuck crypto has nothing to
# do with this one. A consumer knowing its infrastructure is ordinary; the
# reverse is how a general tool quietly becomes a special one.
#
# So this CLONES rather than vendors. Two copies of a crypto routine are two
# things that can disagree about what the routine is, and the copy living in a
# consumer's tree is the one nobody ever regenerates.
#
# ONE PIN IS NAMED HERE, NOT TWO. bfsodium pins brainstem by commit already,
# so the broker's revision is read out of bfsodium's own provisioning script
# rather than repeated -- a second copy of a pin drifts exactly as a second
# copy of a routine does. The day either pin becomes a TAG instead of a SHA is
# the day that project considers itself releasable, which makes the form of
# these pins the cheapest status report available.
#
# EVERYTHING LANDS UNDER bf/toolchain AND NOTHING NEEDS ROOT. bfsodium's own
# gate installs the broker to /opt because a disposable guest is the only
# thing it has to please; a check script in somebody else's repository is not
# that, so the broker is built here and reached with BRAINSTEM_DIR.
set -eu

# bfsodium at the revision this port was checked against.
BFSODIUM_COMMIT=436a11aec43a53649de3d7b04e672954c24aac66

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=${BF_TOOLCHAIN:-$here/toolchain}

command -v cc  >/dev/null 2>&1 || { echo "setup: no C compiler" >&2; exit 1; }
command -v git >/dev/null 2>&1 || { echo "setup: no git" >&2; exit 1; }

# Already at the pin? Recorded in a file rather than asked of git, so that
# "already built" and "built something else" are different answers -- the same
# reason bfsodium records brainstem's.
if [ -x "$root/bfsodium/tools/bfi" ] && [ -x "$root/brainstem/build/brainstem" ] \
   && [ "$(cat "$root/PINNED" 2>/dev/null)" = "$BFSODIUM_COMMIT" ]; then
    echo "setup: already built at bfsodium $BFSODIUM_COMMIT"
    exit 0
fi

mkdir -p "$root"

echo "setup: fetching bfsodium $BFSODIUM_COMMIT"
rm -rf "$root/bfsodium"
git clone -q https://github.com/calebpower/bfsodium "$root/bfsodium" \
    || { echo "setup: could not clone bfsodium" >&2; exit 1; }
( cd "$root/bfsodium" && git checkout -q "$BFSODIUM_COMMIT" ) \
    || { echo "setup: no commit $BFSODIUM_COMMIT in bfsodium" >&2; exit 1; }

# Read the broker's pin out of bfsodium rather than naming it again here.
bs=$(sed -n 's/^BRAINSTEM_COMMIT=//p' "$root/bfsodium/tools/guest-setup.sh")
[ -n "$bs" ] || { echo "setup: no BRAINSTEM_COMMIT in bfsodium's guest-setup" >&2; exit 1; }

echo "setup: fetching brainstem $bs (bfsodium's own pin)"
rm -rf "$root/brainstem"
git clone -q https://github.com/calebpower/brainstem "$root/brainstem" \
    || { echo "setup: could not clone brainstem" >&2; exit 1; }
( cd "$root/brainstem" && git checkout -q "$bs" ) \
    || { echo "setup: no commit $bs in brainstem" >&2; exit 1; }

echo "setup: building the broker"
( cd "$root/brainstem" && sh tools/build.sh >/dev/null )

# Only the interpreter and the hex tool. bfsodium's lints and style checkers
# belong to its gate, not to this one: nothing here regenerates its routines.
echo "setup: building the interpreter and the hex tool"
cc -O2 -std=c99 -o "$root/bfsodium/tools/bfi" "$root/bfsodium/tools/bfi.c"
cc -O2 -std=c99 -o "$root/bfsodium/tools/hx"  "$root/bfsodium/tools/hx.c"

printf '%s\n' "$BFSODIUM_COMMIT" > "$root/PINNED"
echo "setup: done -- bfsodium $BFSODIUM_COMMIT, brainstem $bs"
