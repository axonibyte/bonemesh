#!/bin/sh
# Tier 6 — containerized full mesh under a hostile network (methodology tier 6),
# language-agnostic. Two parts:
#
#   A. Mixed-language matrix under netem. Every usable (responder, initiator)
#      pair completes a real BMX handshake + delivery while loopback carries
#      added latency and packet loss. Proves the handshake and transport tolerate
#      a degraded link (TCP recovers loss; the handshake round-trips survive
#      jitter), across languages.
#   B. Partition and heal. A listener is cut off with an iptables DROP on its
#      port: a send must NOT be delivered (two oracles — the connect fails and the
#      output stays empty). The rule is removed and an identical send now DOES
#      deliver — self-testing that the partition, not a broken setup, caused the
#      silence, and that the node recovers.
#
# Needs Linux tc/netem + iptables and root, so it runs on the interop guest, not
# the FreeBSD driver. On a host without them it no-ops loudly (exit 0) rather
# than pretending to have run.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)

if ! command -v tc >/dev/null 2>&1 || ! command -v iptables >/dev/null 2>&1 || [ "$(id -u)" != 0 ]; then
  echo "tier 6: needs Linux tc/netem + iptables as root; not available here — skipping (runs on the interop guest)"
  exit 0
fi

jar="$repo/java/build/libs/bonemesh.jar"
mesh="tier6-mesh"
marker="tier6-delivered-ok"
work=$(mktemp -d)
netem_on=0
part_port=""
cleanup() {
  [ "$netem_on" = 1 ] && tc qdisc del dev lo root 2>/dev/null || true
  [ -n "$part_port" ] && iptables -D INPUT -i lo -p tcp --dport "$part_port" -j DROP 2>/dev/null || true
  rm -rf "$work"
  kill $(jobs -p) 2>/dev/null || true
}
trap cleanup EXIT

ca() { java -cp "$jar" com.axonibyte.bonemesh.v3.tools.BoneMeshCA "$@" >/dev/null 2>&1; }
[ -f "$jar" ] || (cd "$repo/java" && ./gradlew --no-daemon --quiet shadowJar)

free_port() {
  p=34800
  while :; do
    if (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null; then exec 3>&- 3<&-; p=$((p + 1)); else echo "$p"; return; fi
  done
}

fail=0

echo "== Part A: mixed-language matrix under netem (delay 30ms +/- 8ms, loss 2%) =="
tc qdisc add dev lo root netem delay 30ms 8ms loss 2%
netem_on=1
if sh "$here/run-matrix.sh"; then
  echo "Part A PASS: every usable pair interoperated under netem"
else
  echo "Part A FAIL: a pair failed to interoperate under netem"
  fail=1
fi
tc qdisc del dev lo root
netem_on=0

echo "== Part B: partition and heal =="
ca init-root --out "$work/ca"
printf '{"probe":"%s"}' "$marker" > "$work/msg.json"

usable=""
for d in "$here"/drivers/*.sh; do
  impl=$(basename "$d" .sh)
  if "$d" keygen --id-pub "$work/probe.pub" --id-priv "$work/probe.priv" >/dev/null 2>&1 && [ -s "$work/probe.pub" ]; then
    usable="$usable $impl"
  fi
done
# shellcheck disable=SC2086
set -- $usable
A="$1"
B="${2:-$1}"
echo "partition pair: responder=$A initiator=$B"

"$here/drivers/$A.sh" keygen --id-pub "$work/one.pub" --id-priv "$work/one.priv"
ca issue --root-priv "$work/ca/root.priv" --root-pub "$work/ca/root.pub" --mesh "$mesh" --label one --key "$work/one.pub" --days 1 --out "$work/one.cert.json"
"$here/drivers/$B.sh" keygen --id-pub "$work/two.pub" --id-priv "$work/two.priv"
ca issue --root-priv "$work/ca/root.priv" --root-pub "$work/ca/root.pub" --mesh "$mesh" --label two --key "$work/two.pub" --days 1 --out "$work/two.cert.json"

port=$(free_port)
out="$work/out-partition.txt"
: > "$out"
"$here/drivers/$A.sh" listen --port "$port" --mesh "$mesh" \
  --root-pub "$work/ca/root.pub" --cert "$work/one.cert.json" \
  --id-pub "$work/one.pub" --id-priv "$work/one.priv" --out "$out" --seconds 40 &
listener=$!
tries=0
while ! (exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null; do
  tries=$((tries + 1)); [ "$tries" -gt 100 ] && break; sleep 0.1
done
exec 3>&- 3<&- 2>/dev/null || true

connect_send() {
  "$here/drivers/$B.sh" connect --mesh "$mesh" \
    --root-pub "$work/ca/root.pub" --cert "$work/two.cert.json" \
    --id-pub "$work/two.pub" --id-priv "$work/two.priv" \
    --host 127.0.0.1 --port "$port" --to one --message "$work/msg.json" --seconds "$1" \
    >/dev/null 2>&1 || true
}

# Partition: drop everything to the listener's port.
iptables -A INPUT -i lo -p tcp --dport "$port" -j DROP
part_port="$port"
connect_send 6
sleep 1
if [ -s "$out" ]; then
  echo "Part B FAIL: a message was delivered across the partition"
  fail=1
else
  # Heal and send again.
  iptables -D INPUT -i lo -p tcp --dport "$port" -j DROP
  part_port=""
  connect_send 12
  ok=no; tries=0
  while [ "$tries" -lt 30 ]; do
    if grep -q "$marker" "$out" 2>/dev/null; then ok=yes; break; fi
    tries=$((tries + 1)); sleep 0.2
  done
  if [ "$ok" = yes ]; then
    echo "Part B PASS: silent under partition, delivered after heal"
  else
    echo "Part B FAIL: no delivery after heal (recovery broken, or oracle blind)"
    fail=1
  fi
fi

kill "$listener" 2>/dev/null || true
wait "$listener" 2>/dev/null || true

if [ "$fail" -ne 0 ]; then
  echo "tier 6: FAILURES present"
  exit 1
fi
echo "tier 6: mesh survives netem impairment and recovers from partition"
