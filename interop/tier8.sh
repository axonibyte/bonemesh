#!/bin/sh
# Tier 8 — concurrency / convergence (methodology tier 8), language-agnostic.
#
# Every implementation now routes, so this tier builds a mixed-language diamond
# from whatever implementations are usable on this host (six on the driver, five
# on the interop guest which lacks Erlang/OTP 28):
#
#         bravo (relay)
#        /            \
#   alpha              charlie
#        \            /
#         delta (relay)
#
# The four roles are assigned round-robin across the usable implementations, so
# a message from alpha to the non-neighbor charlie is relayed cross-language.
# alpha streams to charlie; once routes converge the relay alpha is using is
# killed, and two oracles fire:
#   1. routing state converges — no live node keeps a route whose next hop is the
#      dead relay, and alpha's route to charlie moves to the surviving relay;
#   2. delivery heals — after the kill (and a cleared log) charlie still receives.
#
# The convergence oracle is self-tested first against a known-bad routing dump.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
jar="$repo/java/build/libs/bonemesh.jar"
mesh="tier8-mesh"
marker="tier8-delivered-ok"
work=$(mktemp -d)
trap 'rm -rf "$work"; kill $(jobs -p) 2>/dev/null || true; pkill -f "$mesh" 2>/dev/null || true' EXIT

ca() { java -cp "$jar" com.axonibyte.bonemesh.v3.tools.BoneMeshCA "$@" >/dev/null 2>&1; }
[ -f "$jar" ] || (cd "$repo/java" && ./gradlew --no-daemon --quiet shadowJar)

# Every implementation routes, so any usable driver can play any role.
usable=""
for d in "$here"/drivers/*.sh; do
  impl=$(basename "$d" .sh)
  if "$d" keygen --id-pub "$work/probe.pub" --id-priv "$work/probe.priv" >/dev/null 2>&1 && [ -s "$work/probe.pub" ]; then
    usable="$usable $impl"
  else
    echo "SKIP $impl — toolchain unavailable on this host"
  fi
done
# shellcheck disable=SC2086
set -- $usable
n=$#
if [ "$n" -lt 2 ]; then
  echo "tier 8: need at least two routing implementations for a diamond; only '$usable' usable — skipping"
  exit 0
fi
nth() { i=0; for x in $usable; do [ "$i" -eq "$1" ] && { echo "$x"; return; }; i=$((i + 1)); done; }
r_alpha=$(nth $((0 % n))); r_bravo=$(nth $((1 % n))); r_charlie=$(nth $((2 % n))); r_delta=$(nth $((3 % n)))
echo "diamond: alpha=$r_alpha bravo=$r_bravo(relay) charlie=$r_charlie delta=$r_delta(relay)"

# If Elixir is in play, precompile once and let concurrent nodes skip its build
# lock (two `mix run` invocations otherwise deadlock).
case " $usable " in
  *" elixir "*) (cd "$repo/elixir" && mix compile >/dev/null 2>&1) || true; export BONEMESH_ELIXIR_NO_COMPILE=1 ;;
esac

# --- next-hop helpers over the JSON route dumps ({"dest":"nexthop",...}) -------
nexthop() { grep -o "\"$2\":\"[^\"]*\"" "$1" 2>/dev/null | head -1 | sed 's/.*":"//; s/"$//'; }
routes_via() { grep -q "\":\"$2\"" "$1" 2>/dev/null; }

# --- oracle self-test: it must flag a route through the doomed node -----------
printf '{"charlie":"bravo","delta":"bravo"}' > "$work/synthetic.json"
if ! routes_via "$work/synthetic.json" bravo || routes_via "$work/synthetic.json" delta; then
  echo "tier 8: FAIL — convergence oracle mis-detects routes through a node"
  exit 1
fi
echo "oracle self-test passed: route-through-node detection works"

echo "provisioning the mesh root"
ca init-root --out "$work/ca"
printf '{"probe":"%s"}' "$marker" > "$work/msg.json"

issue() { # label driver
  "$here/drivers/$2.sh" keygen --id-pub "$work/$1.pub" --id-priv "$work/$1.priv"
  ca issue --root-priv "$work/ca/root.priv" --root-pub "$work/ca/root.pub" \
    --mesh "$mesh" --label "$1" --key "$work/$1.pub" --days 1 --out "$work/$1.cert.json"
}
issue alpha "$r_alpha"; issue bravo "$r_bravo"; issue charlie "$r_charlie"; issue delta "$r_delta"

free_port() {
  p=${1:-35100}
  while :; do
    if (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null; then exec 3>&- 3<&-; p=$((p + 1)); else echo "$p"; return; fi
  done
}
wait_bind() { t=0; while ! (exec 3<>/dev/tcp/127.0.0.1/$1) 2>/dev/null; do t=$((t + 1)); [ "$t" -gt 250 ] && break; sleep 0.1; done; exec 3>&- 3<&- 2>/dev/null || true; }
common() { printf -- '--mesh %s --root-pub %s --cert %s --id-pub %s --id-priv %s' "$mesh" "$work/ca/root.pub" "$work/$1.cert.json" "$work/$1.pub" "$work/$1.priv"; }

outC="$work/charlie.out"; : > "$outC"
routesA="$work/alpha.routes"

portB=$(free_port)
portD=$(free_port $((portB + 1)))
echo "starting relay bravo (:$portB, $r_bravo)"
# shellcheck disable=SC2046
"$here/drivers/$r_bravo.sh" listen --port "$portB" $(common bravo) --out "$work/bravo.out" --seconds 60 &
wait_bind "$portB"
echo "starting relay delta (:$portD, $r_delta)"
# shellcheck disable=SC2046
"$here/drivers/$r_delta.sh" listen --port "$portD" $(common delta) --out "$work/delta.out" --seconds 60 &
wait_bind "$portD"

echo "starting charlie (dest, $r_charlie) and alpha (sender, $r_alpha), both dialing both relays"
# shellcheck disable=SC2046
"$here/drivers/$r_charlie.sh" mesh $(common charlie) --peers "127.0.0.1:$portB,127.0.0.1:$portD" --out "$outC" --seconds 60 &
# shellcheck disable=SC2046
"$here/drivers/$r_alpha.sh" mesh $(common alpha) --peers "127.0.0.1:$portB,127.0.0.1:$portD" \
  --send-to charlie --message "$work/msg.json" --routes "$routesA" --seconds 60 &

echo "waiting for routes to converge and delivery to begin"
ok=no; t=0
while [ "$t" -lt 60 ]; do
  if grep -q "$marker" "$outC" 2>/dev/null; then ok=yes; break; fi
  t=$((t + 1)); sleep 0.25
done
[ "$ok" = yes ] || { echo "tier 8: FAIL — no delivery before any fault (topology never converged)"; exit 1; }
echo "pre-kill: charlie is receiving from alpha"

sleep 1
victim=$(nexthop "$routesA" charlie)
case "$victim" in
  bravo) vport=$portB; survivor=delta ;;
  delta) vport=$portD; survivor=bravo ;;
  *) echo "tier 8: FAIL — alpha has no converged route to charlie (nexthop='$victim')"; exit 1 ;;
esac
echo "alpha routes to charlie via $victim; killing that relay"
pkill -f "listen --port $vport" 2>/dev/null || true
: > "$outC"

echo "waiting for reconvergence away from $victim"
fail=0

# Oracle 1: routing converges — alpha's route to charlie moves to the survivor.
ok=no; t=0
while [ "$t" -lt 60 ]; do
  [ "$(nexthop "$routesA" charlie)" = "$survivor" ] && { ok=yes; break; }
  t=$((t + 1)); sleep 0.25
done
if [ "$ok" = yes ]; then
  # And no live node keeps a route whose next hop is the dead relay.
  routes_via "$routesA" "$victim" && { echo "  FAIL: alpha still routes through the dead relay $victim"; fail=1; }
else
  echo "  FAIL: alpha did not reroute charlie to the survivor '$survivor' (stuck at '$(nexthop "$routesA" charlie)')"; fail=1
fi

# Oracle 2: delivery heals over the alternate path.
ok=no; t=0
while [ "$t" -lt 40 ]; do
  if grep -q "$marker" "$outC" 2>/dev/null; then ok=yes; break; fi
  t=$((t + 1)); sleep 0.25
done
[ "$ok" = yes ] || { echo "  FAIL: charlie stopped receiving after the relay died (no heal)"; fail=1; }

kill $(jobs -p) 2>/dev/null || true

if [ "$fail" -ne 0 ]; then
  echo "tier 8: FAILURES present"
  exit 1
fi
echo "tier 8: converged off the dead relay ($victim -> $survivor) and delivery healed"
