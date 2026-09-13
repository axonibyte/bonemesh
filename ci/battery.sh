#!/bin/sh
# The whole pre-push battery: all nine reaper tenants, in sequence, torn down even
# on failure. Sequential because each `up` provisions a machine and the pool has
# eight members, so nine concurrent sessions would not fit.
#
# In the repository rather than in a shell history because it is the gate that
# decides whether a release is green. Rebuilt from memory each session, its
# lessons get lost -- both of the ones below were learned twice before this file
# existed.
#
# Lesson 1: `reaper up` is NOT wrapped in timeout(1). It forks a heartbeat that
# runs until `reaper down` and inherits the command's descriptors, so timeout
# waits on the heartbeat and hangs long after `up` has actually succeeded.
#
# Lesson 2 (D19): for the root tenant the exit status is necessary but not
# sufficient. reaper 0.1.0 exits 0 when a run finished but its results never came
# back; 0.1.1 fixes that upstream, and this still checks the evidence, because the
# same check also catches a harness pointed at a stale result. So the prior guest
# log is deleted first and the verdict requires the FINAL tier's own pass line in
# the newly retrieved one. Note the message "results are not coming back" is a
# warn from reaper's *periodic* collector thread and is emitted before the run
# even starts if the guest is not yet reachable -- treating it as a verdict
# rejects perfectly good runs, so it is reported and not acted on.
#
# Usage: sh ci/battery.sh [output-dir]
set -eu

repo=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$repo/out/battery}
mkdir -p "$out"
: > "$out/summary.txt"

final_line='tier 10: all gated feature-behavior scenarios passed'
guestlog="$repo/out/interop.log"

note() { echo "$1" | tee -a "$out/summary.txt"; }

# The root tenant last: it is the longest, provisions every toolchain, and is the
# only place tier 6's netem work runs.
for t in spec go rust js php elixir java python .; do
  if [ "$t" = "." ]; then name=interop-root; else name=$t; fi
  dir="$repo/$t"
  [ "$name" = interop-root ] && rm -f "$guestlog"

  echo "=== $name: up ==="
  if ! (cd "$dir" && reaper up >"$out/$name.up.log" 2>&1 </dev/null); then
    note "FAIL $name (up)"
    (cd "$dir" && reaper down >>"$out/$name.up.log" 2>&1 </dev/null) || true
    continue
  fi

  echo "=== $name: test ==="
  if (cd "$dir" && reaper test >"$out/$name.test.log" 2>&1 </dev/null); then
    status=0
  else
    status=$?
  fi

  if [ "$name" = interop-root ]; then
    note "$name: reaper test exit status $status"
    if grep -q 'results are not coming back' "$out/$name.test.log" 2>/dev/null; then
      note "WARN $name: a retrieval attempt failed during the run (periodic collector)"
    fi
    if [ ! -s "$guestlog" ]; then
      note "FAIL $name (no retrieved guest log at $guestlog)"
    elif ! grep -q "$final_line" "$guestlog"; then
      note "FAIL $name (retrieved guest log lacks the final tier's own pass line)"
    elif [ "$status" -ne 0 ]; then
      note "FAIL $name (tiers passed but reaper test exited $status)"
    else
      note "PASS $name"
      grep -E 'tier [0-9]+:|all pairs interoperate|agrees with the pinned spec' "$guestlog" \
        | sed 's/^/    /' | tee -a "$out/summary.txt"
    fi
  elif [ "$status" -eq 0 ]; then
    note "PASS $name"
  else
    note "FAIL $name (test exited $status)"
  fi

  (cd "$dir" && reaper down >"$out/$name.down.log" 2>&1 </dev/null) \
    || note "WARN $name: down failed"
done

note "=== battery complete ==="
grep -q '^FAIL' "$out/summary.txt" && exit 1
exit 0
