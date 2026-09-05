#!/bin/sh
# Tier 5 — node vs. fake peer (methodology tier 5), language-agnostic.
#
# For every implementation, the node under test runs in listen mode (its own
# driver) while the Go fault peer (tier5/faultpeer) connects and runs a battery
# of deterministic faults: non-JSON, oversize, and unterminated frames; a
# wrong-mesh bmx1; a handshake aborted after bmx1; garbage and tampered bmx3; and
# a corrupted transport frame after a real handshake.
#
# Two oracles, in order:
#   1. After the whole fault battery the listener's output file is EMPTY — no
#      fault produced a delivered payload.
#   2. A final valid handshake+send DOES deliver its marker — self-testing that
#      the oracle can see a delivery at all, and that the node survived every
#      fault (a crash would make this control fail).
#
# Runs on the driver (which has every toolchain), like run-matrix.sh. Exits
# non-zero if any implementation fails either oracle.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
jar="$repo/java/build/libs/bonemesh.jar"
mesh="tier5-mesh"
marker="tier5-delivered-ok"
work=$(mktemp -d)
trap 'rm -rf "$work"; kill $(jobs -p) 2>/dev/null || true' EXIT

ca() { java -cp "$jar" com.axonibyte.bonemesh.v3.tools.BoneMeshCA "$@" >/dev/null 2>&1; }

echo "building the fault peer"
(cd "$repo/interop/tier5" && GOTOOLCHAIN=local GOFLAGS=-mod=vendor go126 build -o faultpeer . 2>/dev/null) \
  || (cd "$repo/interop/tier5" && GOTOOLCHAIN=local GOFLAGS=-mod=vendor go build -o faultpeer .)
faultpeer="$repo/interop/tier5/faultpeer"

echo "provisioning the mesh root"
[ -f "$jar" ] || (cd "$repo/java" && ./gradlew --no-daemon --quiet shadowJar)
ca init-root --out "$work/ca"

# The fault peer's own identity (Go key format), certified into the mesh.
"$here/drivers/go.sh" keygen --id-pub "$work/peer.pub" --id-priv "$work/peer.priv"
ca issue --root-priv "$work/ca/root.priv" --root-pub "$work/ca/root.pub" \
  --mesh "$mesh" --label two --key "$work/peer.pub" --days 1 --out "$work/peer.cert.json"

issue_node() {
  driver="$1"
  "$here/drivers/$driver.sh" keygen --id-pub "$work/one.pub" --id-priv "$work/one.priv"
  ca issue --root-priv "$work/ca/root.priv" --root-pub "$work/ca/root.pub" \
    --mesh "$mesh" --label one --key "$work/one.pub" --days 1 --out "$work/one.cert.json"
}

impls=""
for d in "$here"/drivers/*.sh; do impls="$impls $(basename "$d" .sh)"; done
echo "implementations under test:$impls"

free_port() {
  p=34500
  while :; do
    if (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null; then exec 3>&- 3<&-; p=$((p + 1)); else echo "$p"; return; fi
  done
}

peer() {
  "$faultpeer" --host 127.0.0.1 --port "$port" --mesh "$mesh" \
    --root-pub "$work/ca/root.pub" --cert "$work/peer.cert.json" --id-priv "$work/peer.priv" \
    --to one "$@" >/dev/null 2>&1 || true
}

faults="garbage oversize truncated wrong-mesh-bmx1 abort-after-bmx1 garbage-bmx3 tampered-bmx3 bad-transport"
fail=0
results=""

for impl in $impls; do
  port=$(free_port)
  out="$work/out-$impl.txt"
  : > "$out"
  issue_node "$impl"

  "$here/drivers/$impl.sh" listen --port "$port" --mesh "$mesh" \
    --root-pub "$work/ca/root.pub" --cert "$work/one.cert.json" \
    --id-pub "$work/one.pub" --id-priv "$work/one.priv" --out "$out" --seconds 40 &
  listener=$!

  tries=0
  while ! (exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null; do
    tries=$((tries + 1)); [ "$tries" -gt 100 ] && break; sleep 0.1
  done
  exec 3>&- 3<&- 2>/dev/null || true

  # Fault battery.
  for s in $faults; do
    peer --scenario "$s"
    sleep 0.2
  done

  # Oracle 1: nothing delivered by any fault.
  sleep 0.5
  if [ -s "$out" ]; then
    results="$results\nFAIL  $impl  — a fault produced a delivered payload:"
    results="$results\n        $(head -c 200 "$out")"
    fail=1
    kill "$listener" 2>/dev/null || true; wait "$listener" 2>/dev/null || true
    continue
  fi

  # Oracle 2: a valid send after the battery delivers (node survived; oracle works).
  peer --scenario valid-send --marker "$marker"
  ok=no; tries=0
  while [ "$tries" -lt 30 ]; do
    if grep -q "$marker" "$out" 2>/dev/null; then ok=yes; break; fi
    tries=$((tries + 1)); sleep 0.2
  done

  kill "$listener" 2>/dev/null || true; wait "$listener" 2>/dev/null || true

  if [ "$ok" = yes ]; then
    results="$results\nPASS  $impl  — survived 8 faults, delivered nothing spurious, then delivered the control"
  else
    results="$results\nFAIL  $impl  — control send did not deliver (node crashed under a fault, or oracle blind)"
    fail=1
  fi
done

printf '%b\n' "$results"
if [ "$fail" -ne 0 ]; then
  echo "tier 5: FAILURES present"
  exit 1
fi
echo "tier 5: every implementation withstands the fault battery"
