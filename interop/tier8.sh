#!/bin/sh
# Tier 8 — concurrency / convergence (methodology tier 8).
#
# Only Java and Elixir route (the Go/Rust/JS/PHP ports do direct delivery), so
# this tier is scoped to them and needs both present — it runs on the driver and
# skips loudly where either is missing (e.g. the interop guest, which has no
# Erlang/OTP 28).
#
# Topology is a diamond with two disjoint paths from sender to destination:
#
#         bravo (relay)
#        /            \
#   alpha              charlie
#        \            /
#         delta (relay)
#
# alpha (java) sends continuously toward charlie (java); the relays bravo and
# delta are elixir. Once routes converge, the relay alpha is currently using is
# killed. The tier asserts, with two oracles:
#   1. routing state converges — no live node keeps a route whose next hop is the
#      dead relay, and alpha's route to charlie moves to the surviving relay;
#   2. delivery heals — after the kill (and a cleared log) charlie still receives
#      alpha's payloads, over the alternate path.
#
# The convergence oracle is self-tested first: fed a routing dump that DOES route
# through the (about-to-be) dead node, it must complain — so a green run means
# something.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
jar="$repo/java/build/libs/bonemesh.jar"
mesh="tier8-mesh"
marker="tier8-delivered-ok"
work=$(mktemp -d)
trap 'rm -rf "$work"; kill $(jobs -p) 2>/dev/null || true' EXIT

ca() { java -cp "$jar" com.axonibyte.bonemesh.v3.tools.BoneMeshCA "$@" >/dev/null 2>&1; }

usable() {
  "$here/drivers/$1.sh" keygen --id-pub "$work/probe.pub" --id-priv "$work/probe.priv" >/dev/null 2>&1 && [ -s "$work/probe.pub" ]
}
if ! usable java || ! usable elixir; then
  echo "tier 8: needs both the Java and Elixir (routing) implementations; not both present here — skipping"
  exit 0
fi

# --- next-hop helpers over the JSON route dumps ({"dest":"nexthop",...}) -------
nexthop() { grep -o "\"$2\":\"[^\"]*\"" "$1" 2>/dev/null | head -1 | sed 's/.*":"//; s/"$//'; }
routes_via() { grep -q "\":\"$2\"" "$1" 2>/dev/null; } # true if any route's next hop is $2

# --- oracle self-test: it must flag a route through the doomed node -----------
printf '{"charlie":"bravo","delta":"bravo"}' > "$work/synthetic.json"
if ! routes_via "$work/synthetic.json" bravo; then
  echo "tier 8: FAIL — convergence oracle did not flag a route through the dead node in a known-bad dump"
  exit 1
fi
if routes_via "$work/synthetic.json" delta; then
  echo "tier 8: FAIL — convergence oracle flagged a route through a node that carries none"
  exit 1
fi
echo "oracle self-test passed: route-through-node detection works"

echo "provisioning the mesh root"
[ -f "$jar" ] || (cd "$repo/java" && ./gradlew --no-daemon --quiet shadowJar)
ca init-root --out "$work/ca"
printf '{"probe":"%s"}' "$marker" > "$work/msg.json"

# Node -> implementation. Endpoints Java, relays Elixir: cross-language routing.
issue() { # label driver
  "$here/drivers/$2.sh" keygen --id-pub "$work/$1.pub" --id-priv "$work/$1.priv"
  ca issue --root-priv "$work/ca/root.priv" --root-pub "$work/ca/root.pub" \
    --mesh "$mesh" --label "$1" --key "$work/$1.pub" --days 1 --out "$work/$1.cert.json"
}
issue alpha java
issue bravo elixir
issue charlie java
issue delta elixir

# free_port [floor] — first unused port at or above floor (default 35100).
free_port() {
  p=${1:-35100}
  while :; do
    if (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null; then exec 3>&- 3<&-; p=$((p + 1)); else echo "$p"; return; fi
  done
}
wait_bind() {
  t=0
  while ! (exec 3<>/dev/tcp/127.0.0.1/$1) 2>/dev/null; do t=$((t + 1)); [ "$t" -gt 250 ] && break; sleep 0.1; done
  exec 3>&- 3<&- 2>/dev/null || true
}

# Precompile Elixir once so the two concurrent relays can run --no-compile
# without contending on mix's build lock.
(cd "$repo/elixir" && mix compile >/dev/null 2>&1) || true
export BONEMESH_ELIXIR_NO_COMPILE=1

common() { # label driver -> echoes the shared flags
  printf -- '--mesh %s --root-pub %s --cert %s --id-pub %s --id-priv %s' \
    "$mesh" "$work/ca/root.pub" "$work/$1.cert.json" "$work/$1.pub" "$work/$1.priv"
}

outC="$work/charlie.out"; : > "$outC"
routesA="$work/alpha.routes"; routesC="$work/charlie.routes"

# Start the relays one at a time: pick each port only after the previous relay
# has bound it, so the two never collide, and stagger the elixir starts so two
# `mix run` invocations don't contend on the build lock.
portB=$(free_port)
portD=$(free_port $((portB + 1)))
echo "starting relay bravo (:$portB, elixir)"
# shellcheck disable=SC2046
"$here/drivers/elixir.sh" listen --port "$portB" $(common bravo elixir) --out "$work/bravo.out" --seconds 60 &
wait_bind "$portB"
echo "starting relay delta (:$portD, elixir)"
# shellcheck disable=SC2046
"$here/drivers/elixir.sh" listen --port "$portD" $(common delta elixir) --out "$work/delta.out" --seconds 60 &
wait_bind "$portD"

echo "starting charlie (java, dest) and alpha (java, sender), both dialing both relays"
# shellcheck disable=SC2046
"$here/drivers/java.sh" mesh $(common charlie java) --peers "127.0.0.1:$portB,127.0.0.1:$portD" \
  --out "$outC" --routes "$routesC" --seconds 60 &
# shellcheck disable=SC2046
"$here/drivers/java.sh" mesh $(common alpha java) --peers "127.0.0.1:$portB,127.0.0.1:$portD" \
  --send-to charlie --message "$work/msg.json" --routes "$routesA" --seconds 60 &

echo "waiting for routes to converge and delivery to begin"
ok=no; t=0
while [ "$t" -lt 40 ]; do
  if grep -q "$marker" "$outC" 2>/dev/null; then ok=yes; break; fi
  t=$((t + 1)); sleep 0.25
done
if [ "$ok" != yes ]; then
  echo "tier 8: FAIL — no delivery before any fault (topology never converged)"
  exit 1
fi
echo "pre-kill: charlie is receiving from alpha"

# Which relay is alpha routing charlie through right now?
sleep 1
victim=$(nexthop "$routesA" charlie)
case "$victim" in
  bravo) vport=$portB ;;
  delta) vport=$portD ;;
  *) echo "tier 8: FAIL — alpha has no converged route to charlie (nexthop='$victim')"; exit 1 ;;
esac
echo "alpha routes to charlie via $victim; killing that relay"

# Kill the relay alpha depends on (matched by its listen port), then watch the
# mesh heal. Its neighbors detect the dropped socket and withdraw routes via it.
pkill -f "interop_node.exs listen --port $vport" 2>/dev/null || true

: > "$outC"   # only post-heal deliveries count
survivor=bravo; [ "$victim" = bravo ] && survivor=delta

echo "waiting for reconvergence away from $victim"
sleep 6

fail=0
# Oracle 1: no live node keeps a route through the dead relay; alpha moved to the survivor.
if routes_via "$routesA" "$victim"; then
  echo "  FAIL: alpha still has a route whose next hop is the dead relay $victim"; fail=1
fi
if routes_via "$routesC" "$victim"; then
  echo "  FAIL: charlie still has a route whose next hop is the dead relay $victim"; fail=1
fi
newhop=$(nexthop "$routesA" charlie)
if [ "$newhop" != "$survivor" ]; then
  echo "  FAIL: alpha's route to charlie is '$newhop', expected the survivor '$survivor'"; fail=1
fi

# Oracle 2: delivery healed over the alternate path.
ok=no; t=0
while [ "$t" -lt 40 ]; do
  if grep -q "$marker" "$outC" 2>/dev/null; then ok=yes; break; fi
  t=$((t + 1)); sleep 0.25
done
if [ "$ok" != yes ]; then
  echo "  FAIL: charlie stopped receiving after the relay was killed (no heal)"; fail=1
fi

kill $(jobs -p) 2>/dev/null || true

if [ "$fail" -ne 0 ]; then
  echo "tier 8: FAILURES present"
  exit 1
fi
echo "tier 8: routing converged off the dead relay ($victim -> $survivor) and delivery healed"
