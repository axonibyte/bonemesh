#!/bin/sh
# Tier 11 — long-horizon soak (methodology tier 11). NOT part of the standard
# battery: it costs real wall-clock and is meant to run once per release.
#
# It repeatedly drives the tier-9 seeded churn engine — a fleet under SEND /
# INTRUDE / KILL / RESTART with the four safety invariants (authenticated-only
# delivery, no fabrication, delivery of every authenticated send, survival) —
# for the whole soak duration, with the 3.1 features cycling underneath: a low
# rekey threshold so every session rekeys many times during the run, plus the
# default retry/ack/NAK behavior. Reusing tier 9's self-tested oracle rather
# than re-implementing it is deliberate; tier 11 adds the duration, the feature
# cycling, seed rotation, and a reviewable artifact bundle.
#
# Gate: skips loudly unless BONEMESH_LONG_SOAK=1 or --long-soak is passed.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)

gated=no
[ "${1:-}" = "--long-soak" ] && gated=yes
[ "${BONEMESH_LONG_SOAK:-}" = "1" ] && gated=yes
if [ "$gated" != yes ]; then
  echo "SKIP tier 11 — long-horizon soak. Run it once per release with:"
  echo "    BONEMESH_LONG_SOAK=1 sh interop/tier11.sh    (or: sh interop/tier11.sh --long-soak)"
  echo "  Tunables: BONEMESH_SOAK_SECONDS (default 3600), BONEMESH_SOAK_SEED (default 11000)."
  exit 0
fi

seconds="${BONEMESH_SOAK_SECONDS:-3600}"
seed="${BONEMESH_SOAK_SEED:-11000}"
bundle="${REAPER_OUT:-$repo/interop/out}/tier11-${seed}-$(date +%Y%m%d%H%M%S)"
mkdir -p "$bundle"

echo "tier 11: soaking for ~${seconds}s (seed base=$seed); 3.1 features cycling; bundle -> $bundle"
echo "soak: seconds=$seconds seed_base=$seed host=$(uname -sr)" > "$bundle/summary.txt"

# The 3.1 features that should churn during the soak. A low rekey threshold
# forces frequent live rekeys; idle teardown is left OFF so it cannot race a
# scheduled send and turn a delivery invariant into a spurious failure (idle
# teardown is exercised deterministically by tier 10 instead).
export BONEMESH_REKEY_FRAMES="${BONEMESH_REKEY_FRAMES:-20}"
export BONEMESH_REKEY_MS="${BONEMESH_REKEY_MS:-60000}"
export BONEMESH_IDLE_MS=0

end=$(( $(date +%s) + seconds ))
run=0
while [ "$(date +%s)" -lt "$end" ]; do
  run=$((run + 1))
  s=$(( seed + run ))
  log="$bundle/run-${run}-seed-${s}.log"
  echo "  soak run $run (seed=$s, $(( end - $(date +%s) ))s remaining)"
  if BONEMESH_SIM_SEED="$s" BONEMESH_SIM_ROUNDS="${BONEMESH_SIM_ROUNDS:-40}" sh "$here/tier9.sh" > "$log" 2>&1; then
    echo "run $run seed=$s PASS" >> "$bundle/summary.txt"
  else
    echo "run $run seed=$s FAIL" >> "$bundle/summary.txt"
    echo "tier 11: FAILED on soak run $run (seed=$s) — see $log"
    tail -20 "$log"
    exit 1
  fi
done

echo "tier 11: soak PASSED — $run churn cycles over ~${seconds}s with rekey cycling; bundle at $bundle" | tee -a "$bundle/summary.txt"
