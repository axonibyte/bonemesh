#!/bin/sh
# Ensures a compiled helper binary is at least as new as its sources, rebuilding
# it when it is not.
#
# This is ensure-jar.sh's fix applied to the rest of the fleet. Every caller used
# to guard its build with `[ -x "$bin" ] || build`, which rebuilds only when the
# binary is ABSENT -- so editing a source and re-running a tier silently exercised
# the previous build. That is a check reporting PASS for code that is not the code
# under test, and it is not hypothetical: the 3.3.0 splitting work was invisible to
# the interop matrix until this was fixed, because interop_node had been built
# before it and the matrix dutifully tested the old binary. Five of seven cells
# "failed" for reasons that had already been fixed, and go's rows "failed" for a
# reason that had never existed.
#
# An mtime comparison costs milliseconds when the binary is current, so no caller
# pays a build on every invocation.
#
# Usage: ensure-bin.sh go <command-name>    (builds repo/go/<name> from ./cmd/<name>)
#        ensure-bin.sh rust <binary-name>   (builds repo/rust/target/debug/<name>)
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
lang=${1:?usage: ensure-bin.sh <go|rust> <name>}
name=${2:?usage: ensure-bin.sh <go|rust> <name>}

case "$lang" in
  go)
    bin="$repo/go/$name"
    srcs="$repo/go/cmd $repo/go/node $repo/go/message $repo/go/routing $repo/go/frame \
          $repo/go/transport $repo/go/handshake $repo/go/keyschedule $repo/go/crypto \
          $repo/go/cert $repo/go/canon $repo/go/go.mod"
    build() {
      echo "building go/$name ($1)..." >&2
      g=go126; command -v "$g" >/dev/null 2>&1 || g=go
      (cd "$repo/go" && GOTOOLCHAIN=local GOFLAGS=-mod=vendor "$g" build -o "$name" "./cmd/$name")
    }
    ;;
  rust)
    bin="$repo/rust/target/debug/$name"
    srcs="$repo/rust/src $repo/rust/Cargo.toml"
    build() {
      echo "building rust $name ($1)..." >&2
      (cd "$repo/rust" && cargo build --offline --quiet --bin "$name")
    }
    ;;
  *)
    echo "ensure-bin.sh: unknown language '$lang'" >&2
    exit 2
    ;;
esac

if [ ! -x "$bin" ]; then
  build "not present"
  exit 0
fi

# -print -quit stops at the first newer input, so this stays cheap on a big tree.
# shellcheck disable=SC2086  # srcs is a deliberate word-split list of roots
stale=$(find $srcs -newer "$bin" -print -quit 2>/dev/null || true)
if [ -n "$stale" ]; then
  build "sources newer than the binary"
fi
