#!/bin/sh
# Runs every byte-exact corpus check: each family against each implementation.
#
# The check-*.sh scripts are the ONLY oracles that compare an implementation
# against the shared corpus byte-for-byte -- the in-tenant unit suites mirror the
# vectors by hand, because a reaper tenant syncs one subtree and cannot see
# spec/corpus at all. Until this runner existed nothing invoked them: the root
# tenant ran the matrix and tiers 5-10, and CI ran Java's gradle test. So
# docs/testing.md's tier-1-4 claim of "byte-exact agreement with the shared
# corpus" was, in practice, unrun. This is what runs it.
#
# Deliberately NOT named check-*.sh: family discovery below globs that namespace,
# so a runner living in it would discover itself as a family called "all". Named
# for run-matrix.sh instead, which it sits beside in the root tenant's chain.
#
# Naming convention it relies on:
#   check-<family>.sh          the Java check (Java is the reference implementation)
#   check-<family>-<impl>.sh   every other implementation
# A family is therefore a check-*.sh basename with no second hyphenated part, so
# family names must stay single words.
#
# Two passes. The first is the plain one. The second re-runs everything under a
# hostile default charset (testing-methodology tier 1: "run interop vectors a
# second time under a non-UTF-8 default"), which is where canon.json's
# non-ascii-emitted-raw-utf8 vector and framing.json's invalid-utf8 verdict
# actually bite -- an implementation that only agrees when the platform default
# happens to be UTF-8 has a latent interop bug, and this is the pass that says so.
#
# What the hostile pass does NOT prove: these checks compare a value produced by
# the implementation against an expected value read out of the same corpus file,
# so a charset fault that corrupts BOTH sides identically -- decoding the whole
# file with a broken charset, say -- stays invisible, because the comparison is
# then self-consistent. Verified: injecting exactly that into the Java canon
# check passes both passes. What the pass does catch is the asymmetric and far
# likelier fault, where the implementation *emits* platform-encoded bytes instead
# of UTF-8 (injected into Jcs.canonicalize: plain pass green, hostile pass red).
#
# A missing (family, implementation) pair is a FAILURE, not a skip: the grid is
# supposed to be complete, and a silently absent check reads as coverage. A
# missing *toolchain* is a skip, logged loudly, exactly as the tiers do it.
#
# Usage:
#   sh interop/run-corpus-checks.sh              both passes
#   sh interop/run-corpus-checks.sh --plain      first pass only
#   sh interop/run-corpus-checks.sh --self-test  prove the runner can fail
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)

mode="${1:-both}"

# --- discovery ---------------------------------------------------------------

# Whole-repo checkers that live in the check-*.sh namespace but are NOT
# per-implementation families. check-spec.sh is one tool covering every
# implementation at once (methodology tier 3), so there is no check-spec-<impl>.sh
# to look for and demanding one would fail every language. Listed explicitly, with
# the reason, rather than pattern-matched: a new whole-repo checker should have to
# declare itself here.
NOT_A_FAMILY="spec"

families=""
for s in "$here"/check-*.sh; do
  base=$(basename "$s" .sh)
  fam=${base#check-}
  case "$fam" in
    *-*) continue ;;          # check-<family>-<impl>.sh, handled per family
  esac
  skip=no
  for n in $NOT_A_FAMILY; do
    [ "$fam" = "$n" ] && skip=yes
  done
  [ "$skip" = yes ] && continue
  families="$families $fam"
done

# Implementations are the union of the driver registry (interop/README.md: the
# drivers directory *is* the registry) and any -<impl> check suffix, so a new
# language is picked up by dropping its files in, with no edit here.
impls="java"
for d in "$here"/drivers/*.sh; do
  impl=$(basename "$d" .sh)
  [ "$impl" = java ] && continue
  impls="$impls $impl"
done

echo "corpus-check families:$families"
echo "implementations:$impls"

# --- completeness: every (family, impl) must have a script -------------------

missing=""
for fam in $families; do
  for impl in $impls; do
    if [ "$impl" = java ]; then s="$here/check-$fam.sh"; else s="$here/check-$fam-$impl.sh"; fi
    [ -f "$s" ] || missing="$missing $fam/$impl"
  done
done
if [ -n "$missing" ]; then
  echo "FAIL: no check script for:$missing"
  echo "      (a missing check is not coverage -- add it, or remove the family)"
  exit 1
fi

# --- toolchain probe, same idiom as the tiers --------------------------------

# Build the Java jar first so the Java probe is judged on the toolchain rather
# than on whether a previous run happened to leave an artifact behind.
sh "$here/ensure-jar.sh"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

usable=""
for impl in $impls; do
  d="$here/drivers/$impl.sh"
  if [ -x "$d" ] && "$d" keygen --id-pub "$work/probe.pub" --id-priv "$work/probe.priv" >/dev/null 2>&1 \
     && [ -s "$work/probe.pub" ]; then
    usable="$usable $impl"
  else
    echo "SKIP $impl — toolchain unavailable on this host"
  fi
done
echo "implementations usable:$usable"

# --- the passes --------------------------------------------------------------

fail=0
failed=""

run_pass() {
  label="$1"
  echo
  echo "=== corpus checks: $label pass ==="
  for fam in $families; do
    for impl in $usable; do
      if [ "$impl" = java ]; then s="$here/check-$fam.sh"; else s="$here/check-$fam-$impl.sh"; fi
      if sh "$s" >"$work/out" 2>&1; then
        echo "PASS  $fam  $impl"
      else
        echo "FAIL  $fam  $impl"
        sed 's/^/        /' "$work/out"
        fail=$((fail + 1))
        failed="$failed $label:$fam/$impl"
      fi
    done
  done
}

case "$mode" in
  --self-test)
    # Self-test the oracle, on both of its failure modes. A runner that cannot
    # fail is indistinguishable from a suite that passes.
    #
    #   1. a BROKEN check is detected, named, and fails the run
    #   2. a MISSING check is detected and fails the run (the completeness gate,
    #      which is what stops an absent script from reading as coverage)
    #
    # The fake implementation needs a driver whose keygen succeeds (that is the
    # toolchain probe) and a script for EVERY family, or gate 2 fires first and
    # gate 1 is never reached -- which is exactly what happened the first time
    # this self-test was run.
    driver="$here/drivers/selftestimpl.sh"
    cleanup_selftest() {
      rm -f "$driver"
      for f in $families; do rm -f "$here/check-$f-selftestimpl.sh"; done
      rm -rf "$work"
    }
    trap cleanup_selftest EXIT

    printf '#!/bin/sh\n[ "$1" = keygen ] || exit 1\nshift\nwhile [ $# -gt 1 ]; do [ "$1" = --id-pub ] && echo x > "$2"; shift 2; done\nexit 0\n' > "$driver"
    chmod +x "$driver"

    broken=$(echo $families | cut -d' ' -f1)
    for f in $families; do
      if [ "$f" = "$broken" ]; then
        printf '#!/bin/sh\necho "deliberately broken check (runner self-test)"\nexit 1\n' > "$here/check-$f-selftestimpl.sh"
      else
        printf '#!/bin/sh\nexit 0\n' > "$here/check-$f-selftestimpl.sh"
      fi
      chmod +x "$here/check-$f-selftestimpl.sh"
    done

    echo "self-test 1: a broken '$broken' check must be detected and named"
    if sh "$0" --plain >"$work/st1.log" 2>&1; then
      echo "SELF-TEST FAIL: the runner reported success with a broken check present"
      sed 's/^/    /' "$work/st1.log"; exit 1
    fi
    if ! grep -q "FAIL  $broken  selftestimpl" "$work/st1.log"; then
      echo "SELF-TEST FAIL: the runner did not name the broken check"
      sed 's/^/    /' "$work/st1.log"; exit 1
    fi
    # ... and it must not have cried wolf about the families that are fine.
    if grep -qE "FAIL  (${broken}) " "$work/st1.log" && [ "$(grep -c 'FAIL  ' "$work/st1.log")" -ne 1 ]; then
      echo "SELF-TEST FAIL: the runner flagged checks that were not broken"
      sed 's/^/    /' "$work/st1.log"; exit 1
    fi
    echo "  ok: detected, named, and nothing else flagged"

    echo "self-test 2: a missing check must fail the run, not pass quietly"
    rm -f "$here/check-$broken-selftestimpl.sh"
    if sh "$0" --plain >"$work/st2.log" 2>&1; then
      echo "SELF-TEST FAIL: a missing check did not fail the run"
      sed 's/^/    /' "$work/st2.log"; exit 1
    fi
    if ! grep -q "no check script for:.*$broken/selftestimpl" "$work/st2.log"; then
      echo "SELF-TEST FAIL: the runner did not name the missing check"
      sed 's/^/    /' "$work/st2.log"; exit 1
    fi
    echo "  ok: missing check named and fatal"

    echo "SELF-TEST PASS: the runner fails on both a broken and a missing check"
    exit 0
    ;;
  --plain)
    run_pass plain
    passes="the plain pass"
    ;;
  both)
    run_pass plain

    # Hostile default charset. LC_ALL/LANG cover the POSIX runtimes; the JVM and
    # CPython each need their own knob, because both override the locale by
    # default (JEP 400 pins file.encoding to UTF-8 regardless of locale, and
    # CPython enables UTF-8 mode ahead of the locale).
    #
    # file.encoding=COMPAT rather than a named charset: under LC_ALL=C it makes
    # the JVM derive everything from the locale, which lands on US-ASCII for
    # file.encoding, native.encoding AND stdout.encoding. That is strictly more
    # hostile than naming ISO-8859-1 (which leaves native/stdout on UTF-8), and
    # ASCII cannot represent canon.json's "café" label at all -- so an
    # implementation that round-trips the canonical bytes through a
    # platform-encoded reader or writer fails here, which is the point.
    #
    # These are `export`ed rather than written as `VAR=x run_pass ...`: a prefix
    # assignment on a FUNCTION call does not reach the processes that function
    # starts, so the prefix form ran the whole pass in a pristine environment and
    # reported a meaningless row of PASSes. That was caught by injecting a real
    # charset bug (reading the corpus with the platform default instead of UTF-8)
    # and watching the hostile pass fail to notice.
    LC_ALL=C
    LANG=C
    LC_CTYPE=C
    JAVA_TOOL_OPTIONS=-Dfile.encoding=COMPAT
    PYTHONUTF8=0
    PYTHONCOERCECLOCALE=0
    export LC_ALL LANG LC_CTYPE JAVA_TOOL_OPTIONS PYTHONUTF8 PYTHONCOERCECLOCALE

    # Having been theatre once, the pass now proves it is hostile before it runs.
    # A pass that silently reverts to UTF-8 would report success for exactly the
    # defect it exists to catch, which is worse than not running it.
    if command -v java >/dev/null 2>&1; then
      enc=$(java -XshowSettings:properties -version 2>&1 \
              | sed -n 's/^ *file\.encoding = //p' | head -1)
      case "$enc" in
        ""|UTF-8|utf-8|UTF8)
          echo "FAIL: the hostile-charset pass is not hostile (JVM file.encoding=${enc:-unknown})"
          echo "      refusing to report PASSes that would mean nothing"
          exit 1
          ;;
        *) echo "hostile pass confirmed: JVM file.encoding=$enc" ;;
      esac
    fi

    run_pass "hostile-charset (LC_ALL=C, JVM+CPython forced off UTF-8)"

    unset LC_ALL LANG LC_CTYPE JAVA_TOOL_OPTIONS PYTHONUTF8 PYTHONCOERCECLOCALE
    passes="both passes"
    ;;
  *)
    echo "usage: $0 [--plain|--self-test]" >&2
    exit 2
    ;;
esac

echo
if [ "$fail" -gt 0 ]; then
  echo "corpus checks: $fail failure(s):$failed"
  exit 1
fi
echo "corpus checks: every family agrees with the shared corpus, in ${passes}"
