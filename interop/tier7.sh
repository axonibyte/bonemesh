#!/bin/sh
# Tier 7 — seeded fuzzing (methodology tier 7), language-agnostic.
#
# For every implementation, the node under test runs in listen mode while the Go
# fuzzer (tier7/) drives it through many randomized, replayable mutation
# strategies over frames, handshake messages, and transport payloads. The seed
# is printed and accepted back via BONEMESH_FUZZ_SEED, so a failure reproduces
# exactly; BONEMESH_FUZZ_ITERS sets the iteration count.
#
# Two oracles, in order, as in tier 5:
#   1. After the whole fuzz run the listener's output is EMPTY — no mutated input
#      produced a delivered payload (every transport-phase strategy corrupts the
#      frame, so a correct node delivers nothing).
#   2. A final valid handshake+send DOES deliver its marker — self-testing that
#      the oracle can see a delivery, and that the node survived the run.
#
# Runs on the driver and as the interop guest tenant. Exits non-zero on failure.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
cabin="$repo/go/bonemesh-ca"
mesh="tier7-mesh"
marker="tier7-delivered-ok"
seed="${BONEMESH_FUZZ_SEED:-424242}"
iters="${BONEMESH_FUZZ_ITERS:-120}"
work=$(mktemp -d)
trap 'rm -rf "$work"; kill $(jobs -p) 2>/dev/null || true' EXIT

ca() { "$cabin" "$@" >/dev/null 2>&1; }

echo "building the fuzzer"
(cd "$repo/interop/tier7" && GOTOOLCHAIN=local GOFLAGS=-mod=vendor go126 build -o fuzzer . 2>/dev/null) \
  || (cd "$repo/interop/tier7" && GOTOOLCHAIN=local GOFLAGS=-mod=vendor go build -o fuzzer .)
fuzzer="$repo/interop/tier7/fuzzer"

echo "provisioning the mesh root (seed=$seed iters=$iters)"
[ -x "$cabin" ] || (cd "$repo/go" && GOTOOLCHAIN=local GOFLAGS=-mod=vendor go build -o bonemesh-ca ./cmd/bonemesh-ca)
ca init-root --out "$work/ca"
printf '{"probe":"%s"}' "$marker" > "$work/msg.json"

# The fuzzer's / control's identity (Go key format), certified into the mesh.
"$here/drivers/go.sh" keygen --id-pub "$work/two.pub" --id-priv "$work/two.priv"
ca issue --root-priv "$work/ca/root.priv" --root-pub "$work/ca/root.pub" \
  --mesh "$mesh" --label two --key "$work/two.pub" --days 1 --out "$work/two.cert.json"

issue_node() {
  "$here/drivers/$1.sh" keygen --id-pub "$work/one.pub" --id-priv "$work/one.priv"
  ca issue --root-priv "$work/ca/root.priv" --root-pub "$work/ca/root.pub" \
    --mesh "$mesh" --label one --key "$work/one.pub" --days 1 --out "$work/one.cert.json"
}

impls=""
for d in "$here"/drivers/*.sh; do
  impl=$(basename "$d" .sh)
  if "$d" keygen --id-pub "$work/probe.pub" --id-priv "$work/probe.priv" >/dev/null 2>&1 && [ -s "$work/probe.pub" ]; then
    impls="$impls $impl"
  else
    echo "SKIP $impl — toolchain unavailable on this host"
  fi
done
echo "implementations under test:$impls"

free_port() {
  p=34900
  while :; do
    if (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null; then exec 3>&- 3<&-; p=$((p + 1)); else echo "$p"; return; fi
  done
}

fail=0
results=""

for impl in $impls; do
  port=$(free_port)
  out="$work/out-$impl.txt"
  : > "$out"
  issue_node "$impl"

  "$here/drivers/$impl.sh" listen --port "$port" --mesh "$mesh" \
    --root-pub "$work/ca/root.pub" --cert "$work/one.cert.json" \
    --id-pub "$work/one.pub" --id-priv "$work/one.priv" --out "$out" --seconds 120 &
  listener=$!
  tries=0
  while ! (exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null; do
    tries=$((tries + 1)); [ "$tries" -gt 100 ] && break; sleep 0.1
  done
  exec 3>&- 3<&- 2>/dev/null || true

  "$fuzzer" --seed "$seed" --iterations "$iters" --host 127.0.0.1 --port "$port" \
    --mesh "$mesh" --root-pub "$work/ca/root.pub" --cert "$work/two.cert.json" \
    --id-priv "$work/two.priv" --to one >/dev/null 2>&1 || true

  sleep 0.5
  if [ -s "$out" ]; then
    results="$results\nFAIL  $impl  — fuzzing produced a delivered payload (seed=$seed):"
    results="$results\n        $(head -c 200 "$out")"
    fail=1
    kill "$listener" 2>/dev/null || true; wait "$listener" 2>/dev/null || true
    continue
  fi

  # Control: a real valid send must still deliver.
  "$here/drivers/go.sh" connect --mesh "$mesh" \
    --root-pub "$work/ca/root.pub" --cert "$work/two.cert.json" \
    --id-pub "$work/two.pub" --id-priv "$work/two.priv" \
    --host 127.0.0.1 --port "$port" --to one --message "$work/msg.json" --seconds 12 \
    >/dev/null 2>&1 || true
  ok=no; tries=0
  while [ "$tries" -lt 30 ]; do
    if grep -q "$marker" "$out" 2>/dev/null; then ok=yes; break; fi
    tries=$((tries + 1)); sleep 0.2
  done

  kill "$listener" 2>/dev/null || true; wait "$listener" 2>/dev/null || true

  if [ "$ok" = yes ]; then
    results="$results\nPASS  $impl  — survived $iters fuzz iterations, delivered nothing spurious, then delivered the control"
  else
    results="$results\nFAIL  $impl  — control send did not deliver (node died under fuzzing, or oracle blind); seed=$seed"
    fail=1
  fi
done

printf '%b\n' "$results"
if [ "$fail" -ne 0 ]; then
  echo "tier 7: FAILURES present (replay with BONEMESH_FUZZ_SEED=$seed)"
  exit 1
fi
echo "tier 7: every implementation withstands $iters fuzz iterations (seed=$seed)"
