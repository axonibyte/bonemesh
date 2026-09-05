#!/bin/sh
# Tier 9 — simulated meshes (methodology tier 9), language-agnostic.
#
# Over a seeded sequence of actions it churns a fleet of listener nodes (one per
# usable implementation) with nemesis operations, then checks the invariants that
# must hold no matter what happened. The plan is generated from a single seed
# (printed, and accepted back via BONEMESH_SIM_SEED) so any failure replays.
#
# Actions per round (seeded): SEND (an authenticated member sends a uniquely
# tagged payload to a live listener), INTRUDE (a peer holding a certificate from
# a DIFFERENT mesh root tries to send — it must be rejected), KILL (drop a live
# listener), RESTART (bring a killed listener back with its same identity — a
# stale-identity reconnect).
#
# Invariants (checked from the listeners' delivery logs against what the sim
# authored), the security-critical core that holds for every implementation:
#   1. authenticated-only: no intruder payload is ever delivered anywhere;
#   2. no fabrication: every delivered tag is one the sim actually sent;
#   3. delivery: every authenticated send to a live listener arrived;
#   4. survival: after all the churn, a final send to each live node still lands.
# (Dedup and routing convergence are routing-layer properties covered by tier 8;
# this tier does not re-assert them.)
#
# The invariant checker is self-tested first against synthetic logs — one with a
# smuggled intruder tag, one missing an expected tag — so a green run means the
# checks can actually fail.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
jar="$repo/java/build/libs/bonemesh.jar"
mesh="tier9-mesh"
rounds="${BONEMESH_SIM_ROUNDS:-24}"
seed="${BONEMESH_SIM_SEED:-90210}"
work=$(mktemp -d)
trap 'rm -rf "$work"; kill $(jobs -p) 2>/dev/null || true; pkill -f "$mesh" 2>/dev/null || true' EXIT

ca() { java -cp "$jar" com.axonibyte.bonemesh.v3.tools.BoneMeshCA "$@" >/dev/null 2>&1; }

# --- invariant checks (pure, over out-files) ----------------------------------
# no intruder-* tag anywhere; used both for the real logs and the self-test.
has_intruder() { grep -q "intruder-" "$1" 2>/dev/null; }
has_tag() { grep -q "\"$2\"" "$1" 2>/dev/null; }

# --- oracle self-test: the checks must fire on known-bad logs ------------------
printf '{"probe":"intruder-r3"}\n' > "$work/synthetic-bad.txt"
printf '{"probe":"auth-r1"}\n' > "$work/synthetic-ok.txt"
if ! has_intruder "$work/synthetic-bad.txt"; then
  echo "tier 9: FAIL — authenticated-only check did not flag a smuggled intruder tag"; exit 1
fi
if has_intruder "$work/synthetic-ok.txt"; then
  echo "tier 9: FAIL — authenticated-only check flagged a clean log"; exit 1
fi
if has_tag "$work/synthetic-ok.txt" "auth-r1" && ! has_tag "$work/synthetic-ok.txt" "auth-r999"; then
  : # delivery check distinguishes present vs missing tags
else
  echo "tier 9: FAIL — delivery check cannot tell a present tag from a missing one"; exit 1
fi
echo "oracle self-test passed: invariant checks fire on known-bad logs"

echo "provisioning meshes (real root + a foreign root; seed=$seed rounds=$rounds)"
[ -f "$jar" ] || (cd "$repo/java" && ./gradlew --no-daemon --quiet shadowJar)
ca init-root --out "$work/ca"
ca init-root --out "$work/ca-foreign"

# The authenticated sender and the intruder (same key format — Go — for both).
"$here/drivers/go.sh" keygen --id-pub "$work/sender.pub" --id-priv "$work/sender.priv"
ca issue --root-priv "$work/ca/root.priv" --root-pub "$work/ca/root.pub" \
  --mesh "$mesh" --label sender --key "$work/sender.pub" --days 1 --out "$work/sender.cert.json"
"$here/drivers/go.sh" keygen --id-pub "$work/intruder.pub" --id-priv "$work/intruder.priv"
ca issue --root-priv "$work/ca-foreign/root.priv" --root-pub "$work/ca-foreign/root.pub" \
  --mesh "$mesh" --label intruder --key "$work/intruder.pub" --days 1 --out "$work/intruder.cert.json"

# Usable implementations become the fleet.
impls=""
for d in "$here"/drivers/*.sh; do
  impl=$(basename "$d" .sh)
  if "$d" keygen --id-pub "$work/probe.pub" --id-priv "$work/probe.priv" >/dev/null 2>&1 && [ -s "$work/probe.pub" ]; then
    impls="$impls $impl"
  else
    echo "SKIP $impl — toolchain unavailable on this host"
  fi
done
set -- $impls
nimpls=$#
echo "fleet:$impls ($nimpls nodes)"

free_port() {
  p=${1:-35300}
  while :; do
    if (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null; then exec 3>&- 3<&-; p=$((p + 1)); else echo "$p"; return; fi
  done
}
impl_at() { i=0; for x in $impls; do [ "$i" = "$1" ] && { echo "$x"; return; }; i=$((i + 1)); done; }

# Start a listener for one impl (issuing its member cert the first time).
start_listener() {
  impl="$1"; port="$2"
  if [ ! -f "$work/$impl.cert.json" ]; then
    "$here/drivers/$impl.sh" keygen --id-pub "$work/$impl.pub" --id-priv "$work/$impl.priv"
    ca issue --root-priv "$work/ca/root.priv" --root-pub "$work/ca/root.pub" \
      --mesh "$mesh" --label "$impl" --key "$work/$impl.pub" --days 1 --out "$work/$impl.cert.json"
  fi
  "$here/drivers/$impl.sh" listen --port "$port" --mesh "$mesh" \
    --root-pub "$work/ca/root.pub" --cert "$work/$impl.cert.json" \
    --id-pub "$work/$impl.pub" --id-priv "$work/$impl.priv" \
    --out "$work/out-$impl.txt" --seconds 400 &
  rm -f "$work/dead-$impl"
}
wait_bind() { t=0; while ! (exec 3<>/dev/tcp/127.0.0.1/$1) 2>/dev/null; do t=$((t + 1)); [ "$t" -gt 250 ] && break; sleep 0.1; done; exec 3>&- 3<&- 2>/dev/null || true; }

# One authenticated send of {"probe":TAG} to impl's listener.
auth_send() {
  impl="$1"; tag="$2"
  printf '{"probe":"%s"}' "$tag" > "$work/msg.json"
  "$here/drivers/go.sh" connect --mesh "$mesh" \
    --root-pub "$work/ca/root.pub" --cert "$work/sender.cert.json" \
    --id-pub "$work/sender.pub" --id-priv "$work/sender.priv" \
    --host 127.0.0.1 --port "$(cat "$work/port-$impl")" --to "$impl" --message "$work/msg.json" --seconds 8 \
    >/dev/null 2>&1 || true
}
# An intruder (foreign-root cert) attempt — must be rejected, never delivered.
intrude() {
  impl="$1"; tag="$2"
  printf '{"probe":"%s"}' "$tag" > "$work/imsg.json"
  "$here/drivers/go.sh" connect --mesh "$mesh" \
    --root-pub "$work/ca-foreign/root.pub" --cert "$work/intruder.cert.json" \
    --id-pub "$work/intruder.pub" --id-priv "$work/intruder.priv" \
    --host 127.0.0.1 --port "$(cat "$work/port-$impl")" --to "$impl" --message "$work/imsg.json" --seconds 5 \
    >/dev/null 2>&1 || true
}

# Boot the fleet.
base=35300
for impl in $impls; do
  port=$(free_port "$base"); base=$((port + 1))
  echo "$port" > "$work/port-$impl"
  : > "$work/out-$impl.txt"
  : > "$work/expect-$impl.txt"
  start_listener "$impl" "$port"
done
for impl in $impls; do wait_bind "$(cat "$work/port-$impl")"; done
echo "fleet up; running $rounds seeded rounds"

# Deterministic action plan from the seed: "action target" per line.
plan=$(awk -v seed="$seed" -v rounds="$rounds" -v n="$nimpls" 'BEGIN{
  srand(seed);
  for(i=0;i<rounds;i++){ printf "%d %d\n", int(rand()*4), int(rand()*n) }
}')

round=0
echo "$plan" | while read -r action target; do
  round=$((round + 1))
  impl=$(impl_at "$target")
  case "$action" in
    0) # SEND
      tag="auth-r$round"
      if [ -f "$work/dead-$impl" ]; then
        auth_send "$impl" "$tag"   # to a dead node: attempted, not expected to arrive
      else
        echo "$tag" >> "$work/expect-$impl.txt"
        auth_send "$impl" "$tag"
        echo "  r$round SEND -> $impl ($tag)"
      fi
      ;;
    1) # INTRUDE
      intrude "$impl" "intruder-r$round"
      echo "  r$round INTRUDE -> $impl (must be rejected)"
      ;;
    2) # KILL
      if [ ! -f "$work/dead-$impl" ]; then
        pkill -f "listen --port $(cat "$work/port-$impl")" 2>/dev/null || true
        touch "$work/dead-$impl"
        echo "  r$round KILL $impl"
      fi
      ;;
    3) # RESTART
      if [ -f "$work/dead-$impl" ]; then
        start_listener "$impl" "$(cat "$work/port-$impl")"
        wait_bind "$(cat "$work/port-$impl")"
        echo "  r$round RESTART $impl"
      fi
      ;;
  esac
  sleep 0.2
done

echo "settling, then a final control send to every live node"
sleep 2
for impl in $impls; do
  if [ ! -f "$work/dead-$impl" ]; then
    echo "control-$impl" >> "$work/expect-$impl.txt"
    auth_send "$impl" "control-$impl"
  fi
done
sleep 2

echo "checking invariants"
# Failures are appended here (survives the pipeline subshells below).
: > "$work/FAILED"
for impl in $impls; do
  out="$work/out-$impl.txt"
  # 1. authenticated-only: no intruder tag ever delivered.
  if has_intruder "$out"; then
    echo "$impl: an intruder payload was delivered" >> "$work/FAILED"
  fi
  # 3. delivery: every expected authenticated tag arrived (this reads from a
  # file, so it runs in the current shell — but we still record via the file).
  while read -r tag; do
    [ -z "$tag" ] && continue
    has_tag "$out" "$tag" || echo "$impl: expected tag '$tag' was never delivered" >> "$work/FAILED"
  done < "$work/expect-$impl.txt"
  # 2. no fabrication: every delivered probe tag is one we authored.
  grep -o '"probe":"[^"]*"' "$out" 2>/dev/null | sed 's/.*":"//; s/"$//' | while read -r got; do
    grep -qx "$got" "$work/expect-$impl.txt" || echo "$impl: delivered a tag never sent: '$got'" >> "$work/FAILED"
  done
done

if [ -s "$work/FAILED" ]; then
  echo "tier 9: FAILURES present (replay with BONEMESH_SIM_SEED=$seed BONEMESH_SIM_ROUNDS=$rounds):"
  sed 's/^/  FAIL /' "$work/FAILED"
  exit 1
fi
echo "tier 9: mesh upheld authenticated-only delivery, no fabrication, and survival across $rounds seeded actions (seed=$seed)"
