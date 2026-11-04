#!/bin/sh
# Asserts that every Go module in this repository declares a path `go get` can
# actually fetch it from.
#
# WHY THIS EXISTS AND WHY NO COMPILER REPLACES IT. A module's declared path can
# be completely wrong and every build and test still passes, because inside the
# module the imports are self-consistent, and the consumers in interop/ reach it
# through a filesystem `replace`. That is exactly how this repository shipped
# three faults at once (issue #2): `go/go.mod` declared
# `github.com/axonibyte/bonemesh/gonode` -- a directory that does not exist, on a
# host that is only a mirror, with no major-version suffix for a v3 release line.
# `go build`, `go test` and all thirteen interop tiers were green throughout. The
# only thing that noticed was a third project trying to depend on it.
#
# So this check is deliberately narrow. It asserts only the claims a compiler
# cannot: that the path names the right host, the right directory and the right
# major version. Everything else about these modules -- that the imports resolve,
# that the vendor trees are consistent, that the `replace` targets exist -- is
# already proven by `go build -mod=vendor`, which is a cheaper oracle, so none of
# it is re-checked here.
#
# Usage:
#   sh ci/check-go-module.sh              check this repository
#   sh ci/check-go-module.sh --self-test  prove the check can fail
set -eu

# The one declared fact in this file, and it has to be declared rather than
# derived: it is a POLICY, not an observable. `git remote` cannot supply it --
# the canonical remote is forge-01.corp.axonibyte.com, which is inside the corp
# network and has no SSH through the front door, so Go cannot fetch from it;
# github.com answers `?go-get=1` perfectly well but is a mirror, so a path
# naming it would resolve and still be wrong. What Go must use is the public
# HTTPS face of the same repository, which is this:
CANONICAL="forge.axonibyte.com/axonibyte/bonemesh"

# Where each sibling implementation declares the release version, in its own
# native packaging format. Used to derive the major version the Go module path
# must carry. These are INDEPENDENT sources and the check requires them to
# agree -- that mutual agreement is the oracle. A single VERSION file would be
# cheaper and would prove nothing, because the thing being checked would then be
# derived from the same string it is checked against.
version_sources() {
  cat <<'LIST'
java/gradle.properties|prjVersion=
js/package.json|"version":
elixir/mix.exs|version:
python/pyproject.toml|version =
rust/Cargo.toml|version =
LIST
}

fail=0
note() { echo "check-go-module: $*"; }
bad()  { echo "check-go-module: REFUSED: $*" >&2; fail=1; }

# --- the release major version, agreed across the implementations ------------

# Runs in a command substitution, so it CANNOT report through the shared `fail`
# flag -- a subshell's assignment is discarded. It reports through its exit
# status instead, and every caller must honour it; the self-test's "sources
# disagree" arm is what holds that wiring honest.
repo_major() {
  root=$1
  seen=""
  bust=0
  # Read line by line, NOT `for spec in $(version_sources)`: the keys contain
  # spaces ("version = "), so word-splitting tore each one in half and the loop
  # then reported a missing source called "=". The self-test's accept arm is what
  # caught it -- every refuse arm stayed green, because a check that refuses
  # everything refuses the broken trees too.
  while IFS= read -r spec; do
    [ -n "$spec" ] || continue
    file=${spec%%|*}
    key=${spec#*|}
    if [ ! -f "$root/$file" ]; then
      echo "check-go-module: REFUSED: no version source at $file" >&2
      bust=1
      continue
    fi
    # First match wins: Cargo.toml and pyproject.toml both name dependency
    # versions further down, and package.json nests them.
    v=$(grep -m1 -- "$key" "$root/$file" |
        sed -e 's/.*[^0-9]\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/') || v=""
    case $v in
      [0-9]*.[0-9]*.[0-9]*) ;;
      *) echo "check-go-module: REFUSED: cannot read a version out of $file (looked for '$key')" >&2
         bust=1
         continue ;;
    esac
    seen="$seen$file=$v
"
  done <<LIST
$(version_sources)
LIST
  [ "$bust" = 0 ] || return 1

  # Every source must say the same thing. A disagreement here is itself a defect
  # worth failing on: it means a release went out half-bumped.
  uniq_v=$(printf '%s' "$seen" | sed 's/.*=//' | sort -u)
  if [ -z "$uniq_v" ] || [ "$(printf '%s\n' "$uniq_v" | wc -l | tr -d ' ')" != 1 ]; then
    echo "check-go-module: REFUSED: the implementations disagree about the release version:" >&2
    printf '%s' "$seen" >&2
    return 1
  fi
  printf '%s' "$uniq_v" | cut -d. -f1
}

# --- the modules -------------------------------------------------------------

check_tree() {
  root=$1
  major=$(repo_major "$root") || return 1
  note "release major version, agreed across the implementations: v$major"

  mods=$(find "$root" -name go.mod -not -path '*/vendor/*' | sort)
  [ -n "$mods" ] || { bad "found no go.mod at all under $root"; return 1; }

  for gomod in $mods; do
    dir=$(dirname "$gomod")
    rel=${dir#"$root"}
    rel=${rel#/}
    [ -n "$rel" ] || rel=""
    mod=$(sed -n 's/^module  *//p' "$gomod" | head -1)
    [ -n "$mod" ] || { bad "$gomod declares no module path"; continue; }

    # A path whose first element carries a dot is a domain, so Go will try to
    # fetch it over the network: it is PUBLISHED and every arm below applies. A
    # path without one (bonemesh-tier5) can only ever be reached through a
    # `replace`, so it is internal and constrained by nothing here. That is the
    # whole distinction -- there is no exemption list to drift out of date.
    case ${mod%%/*} in
      *.*) ;;
      *) note "$rel: internal module '$mod' (no domain, never fetched)"; continue ;;
    esac

    case $mod in
      "$CANONICAL"/*) rest=${mod#"$CANONICAL"/} ;;
      "$CANONICAL")   rest="" ;;
      *) bad "$gomod declares '$mod', which is not under $CANONICAL -- go get would fetch it from somewhere this repository is not served from"
         continue ;;
    esac

    # Split a trailing major-version element off the remainder.
    case $rest in
      v[0-9]|v[0-9][0-9])           got_major=${rest#v}; moddir="" ;;
      */v[0-9]|*/v[0-9][0-9])       got_major=${rest##*/v}; moddir=${rest%/v*} ;;
      *)                            got_major=1; moddir=$rest ;;
    esac

    # Arm 1: the path must name the directory the module is actually in. This is
    # the arm that needs nothing declared -- it reads the filesystem.
    if [ "$moddir" != "$rel" ]; then
      bad "$gomod declares '$mod', so go get looks for the module in '$moddir/' of the repository, but it is in '$rel/'"
    fi

    # Arm 2: from v2 on, the path must end in the major version.
    if [ "$got_major" != "$major" ]; then
      bad "$gomod declares '$mod' (major v$got_major) for a v$major release line; the path must end in '/v$major'"
    fi

    if [ "$fail" = 0 ] && [ -n "$rel" ]; then
      note "$rel: '$mod' -- fetchable as 'go get $mod@v$major.Y.Z', which needs a '$rel/v$major.Y.Z' tag on the commit"
    fi
  done
  return 0
}

# --- self-test ---------------------------------------------------------------
#
# A check nobody has watched fail is a check of unmeasured value, so this mode
# builds throwaway trees that reproduce each real defect and asserts the check
# complains about every one -- and that it stays quiet on a clean tree.

self_test() {
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  passes=0
  failures=0

  plant() { # plant <root> <module-path-for-go/>
    r=$1
    mkdir -p "$r/go" "$r/interop/tier5" "$r/java" "$r/js" "$r/elixir" "$r/python" "$r/rust"
    printf 'module %s\n\ngo 1.26.0\n' "$2" > "$r/go/go.mod"
    printf 'module bonemesh-tier5\n\ngo 1.26.0\n' > "$r/interop/tier5/go.mod"
    printf 'prjVersion=3.3.1\n'   > "$r/java/gradle.properties"
    printf '{ "version": "3.3.1" }\n' > "$r/js/package.json"
    printf '  version: "3.3.1",\n'    > "$r/elixir/mix.exs"
    printf 'version = "3.3.1"\n'      > "$r/python/pyproject.toml"
    printf 'version = "3.3.1"\n'      > "$r/rust/Cargo.toml"
  }

  arm() { # arm <expectation: accept|refuse> <name> <root>
    want=$1; name=$2; r=$3
    # Two ways to refuse and both must count: check_tree's exit status (a
    # version it could not derive at all) and the `fail` flag (a module path it
    # read and rejected). Honouring only one of them is how this harness would
    # quietly pass a tree it should condemn.
    if ( fail=0; check_tree "$r" >/dev/null 2>&1 || exit 1; exit "$fail" ); then
      got=accept
    else
      got=refuse
    fi
    if [ "$got" = "$want" ]; then
      echo "  ok      $name ($got)"
      passes=$((passes + 1))
    else
      echo "  BROKEN  $name: wanted $want, got $got" >&2
      failures=$((failures + 1))
    fi
  }

  echo "check-go-module: self-test"

  plant "$tmp/clean" "$CANONICAL/go/v3"
  arm accept "a correct module path is accepted" "$tmp/clean"

  # The three faults of issue #2, each on its own.
  plant "$tmp/d1" "github.com/axonibyte/bonemesh/gonode"
  arm refuse "the original defect: mirror host, absent directory, no major" "$tmp/d1"

  plant "$tmp/d2" "$CANONICAL/gonode/v3"
  arm refuse "right host and major, directory that does not exist" "$tmp/d2"

  plant "$tmp/d3" "$CANONICAL/go"
  arm refuse "right host and directory, missing /v3 on a v3 release line" "$tmp/d3"

  plant "$tmp/d4" "github.com/axonibyte/bonemesh/go/v3"
  arm refuse "right directory and major, mirror host" "$tmp/d4"

  # A module published under a host that merely looks plausible.
  plant "$tmp/d5" "forge.axonibyte.com/axonibyte/bonemesh-go/go/v3"
  arm refuse "a near-miss repository name" "$tmp/d5"

  # The version sources are an oracle in their own right: if they disagree, a
  # release went out half-bumped and the Go path cannot be derived at all.
  plant "$tmp/d6" "$CANONICAL/go/v3"
  printf 'version = "4.0.0"\n' > "$tmp/d6/rust/Cargo.toml"
  arm refuse "the implementations disagree about the version" "$tmp/d6"

  # And a real v4 bump that forgot the module path -- the likeliest future fault.
  plant "$tmp/d7" "$CANONICAL/go/v3"
  for f in java/gradle.properties js/package.json elixir/mix.exs python/pyproject.toml rust/Cargo.toml; do
    sed -e 's/3\.3\.1/4.0.0/' "$tmp/d7/$f" > "$tmp/d7/$f.new" && mv "$tmp/d7/$f.new" "$tmp/d7/$f"
  done
  arm refuse "a v4 release line with a /v3 module path" "$tmp/d7"

  echo "check-go-module: self-test: $passes ok, $failures broken"
  [ "$failures" = 0 ] || return 1
}

case "${1:-}" in
  --self-test)
    self_test
    ;;
  "")
    here=$(cd "$(dirname "$0")" && pwd)
    check_tree "$(cd "$here/.." && pwd)" || fail=1
    [ "$fail" = 0 ] || { echo "check-go-module: FAILED" >&2; exit 1; }
    note "green"
    ;;
  *)
    echo "usage: check-go-module.sh [--self-test]" >&2
    exit 2
    ;;
esac
