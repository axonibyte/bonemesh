#!/bin/sh
# Tier 12 — emitted-message conformance, the code->spec direction (decision #24).
#
# Every other oracle in this repository asks "is what I received well-formed?".
# message.validate() answers that, and it is called from no node's wire path in
# any of the seven -- only from the corpus-check binaries -- so the `messages`
# family has always validated a side-car (decision #27). Nothing asked the other
# question: "is what I emitted named by the spec?" A port could add a field to a
# frame and every gate in the tree would stay green. That is the same blind spot
# that let a public broadcast() live in exactly one implementation until a human
# diffed two ports method-for-method (decision #23).
#
# The messages checked here were really sealed and really sent: a Go node captures
# the wire while the language under test writes its BONEMESH_KEYLOG, and
# bonemesh-inspect decodes the capture with those keys. A capture records BOTH
# directions and the capturing node is the initiator, so i2r frames are Go's own
# emissions and r2i are the peer's -- one capturing implementation covers all
# seven, which is what decision #18 anticipated when it declined to port --capture.
#
# What this tier does NOT prove:
#   - that a REQUIRED field was present, or that a value is meaningful. Presence
#     and type are pinned by messages.json and the seven validators; checking them
#     again from the same source would produce a check that agrees with itself.
#   - two of the eight inner types. `nak` needs a TTL-exhausted relay, which a
#     two-node pairing cannot stage (tier 10's nak scenario drives that path).
#     `bye` needs an orderly shutdown, and the neutral driver's connect mode
#     returns without calling Kill(), so no graceful close happens here; tier 10's
#     idle scenario puts one on the wire. Reaching either from this tier would
#     mean changing driver teardown, which would shift timing in tiers 5-10, so
#     the gap is recorded instead. The other six -- data (whole AND segmented),
#     ack, disco, probe, echo, rekey -- are covered for every implementation.
#   - anything about a type never emitted during the run. The report prints the
#     per-type counts, so a type that stopped appearing is visible rather than
#     silently "passing" -- which is how the rekey gap here was found and closed
#     (BONEMESH_REKEY_FRAMES is forced low so a live rekey lands in the window).
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
cabin="$repo/go/bonemesh-ca"
inspect="$repo/go/bonemesh-inspect"
checker="$repo/spec/conformance/emittedcheck"
allow="$repo/spec/corpus/emitted.json"
mesh="tier12-mesh"
work=$(mktemp -d)
fail=0
trap 'rm -rf "$work"; kill $(jobs -p) 2>/dev/null || true; pkill -f "$mesh" 2>/dev/null || true' EXIT

ca() { "$cabin" "$@" >/dev/null 2>&1; }
sh "$here/ensure-bin.sh" go bonemesh-ca
sh "$here/ensure-bin.sh" go bonemesh-inspect

# The checker is Go, per decision #12 (conformance tooling is Go).
if [ ! -x "$checker" ] || [ "$repo/spec/conformance/cmd/emittedcheck/main.go" -nt "$checker" ]; then
  echo "building emittedcheck..."
  gocmd=go
  command -v go126 >/dev/null 2>&1 && gocmd=go126
  (cd "$repo/spec/conformance" && "$gocmd" build -o emittedcheck ./cmd/emittedcheck)
fi

# --- oracle self-test ---------------------------------------------------------
# An oracle that never fires is indistinguishable from a passing suite, so feed it
# the output a broken implementation would produce before trusting any pass.
selftest() {
  # 1. an invented field must be caught
  printf '%s\n' '{"dir":"r2i","inner":{"type":"probe","token":1,"nonce":"invented"}}' \
    | "$checker" --allowlist "$allow" --label selftest --dir r2i >/dev/null 2>&1 \
    && { echo "tier 12: SELF-TEST FAIL — an unnamed field was not caught"; exit 1; }
  # 2. an inner type the spec does not define must be caught
  printf '%s\n' '{"dir":"r2i","inner":{"type":"telemetry","mid":"x"}}' \
    | "$checker" --allowlist "$allow" --label selftest --dir r2i >/dev/null 2>&1 \
    && { echo "tier 12: SELF-TEST FAIL — an undefined inner type was not caught"; exit 1; }
  # 3. an empty capture must FAIL rather than pass silently (D16/D19's shape)
  : | "$checker" --allowlist "$allow" --label selftest --dir r2i >/dev/null 2>&1 \
    && { echo "tier 12: SELF-TEST FAIL — an empty capture passed"; exit 1; }
  # 4. and a clean frame must PASS, so the checker is not merely always-red
  printf '%s\n' '{"dir":"r2i","inner":{"type":"probe","token":1}}' \
    | "$checker" --allowlist "$allow" --label selftest --dir r2i >/dev/null 2>&1 \
    || { echo "tier 12: SELF-TEST FAIL — a conforming frame was rejected"; exit 1; }
  echo "oracle self-test passed: unnamed fields, undefined types and empty input all fail; a clean frame passes"
}
selftest

# --- usable implementations ---------------------------------------------------
usable=""
for d in "$here"/drivers/*.sh; do
  impl=$(basename "$d" .sh)
  if "$d" keygen --id-pub "$work/probe.pub" --id-priv "$work/probe.priv" >/dev/null 2>&1 && [ -s "$work/probe.pub" ]; then
    usable="$usable $impl"
    "$d" caps > "$work/caps-$impl" 2>/dev/null || : > "$work/caps-$impl"
  else
    echo "SKIP $impl — toolchain unavailable on this host"
  fi
done
has_cap() { grep -qw "$2" "$work/caps-$1" 2>/dev/null; }
has_cap go capture || { echo "tier 12: the Go driver does not advertise 'capture' — skipping"; exit 0; }

case " $usable " in
  *" elixir "*) (cd "$repo/elixir" && mix compile >/dev/null 2>&1) || true; export BONEMESH_ELIXIR_NO_COMPILE=1 ;;
esac

echo "provisioning the mesh root (usable:$usable)"
ca init-root --out "$work/ca"
issue() { # label driver
  "$here/drivers/$2.sh" keygen --id-pub "$work/$1.pub" --id-priv "$work/$1.priv"
  ca issue --root-priv "$work/ca/root.priv" --root-pub "$work/ca/root.pub" \
    --mesh "$mesh" --label "$1" --key "$work/$1.pub" --days 1 --out "$work/$1.cert.json"
}
common() { printf -- '--mesh %s --root-pub %s --cert %s --id-pub %s --id-priv %s' "$mesh" "$work/ca/root.pub" "$work/$1.cert.json" "$work/$1.pub" "$work/$1.priv"; }
PORT=38100
next_port() { PORT=$((PORT + 1)); echo "$PORT"; }
if command -v bash >/dev/null 2>&1; then
  port_open() { bash -c "exec 3<>/dev/tcp/127.0.0.1/$1" 2>/dev/null; }
else
  port_open() { return 1; }
fi
wait_bind() { t=0; while ! port_open "$1"; do t=$((t + 1)); [ "$t" -gt 100 ] && break; sleep 0.1; done; }
poll() { t=0; while [ "$t" -lt "$3" ]; do grep -q "$2" "$1" 2>/dev/null && return 0; t=$((t + 1)); sleep 0.25; done; return 1; }

# A payload past the 24000-byte segment bound, so `data` frames carrying `seg`
# are exercised and not only whole-payload ones (§6.1).
big=$(yes 0123456789abcdef | head -4000 | tr -d '\n')
printf '{"probe":"tier12-emitted","blob":"%s"}' "$big" > "$work/big.msg"

for L in $usable; do
  port=$(next_port)
  issue "e_srv_$L" "$L"; issue "e_cli_$L" go
  cap="$work/cap-$L"; kl="$work/kl-$L"; out="$work/out-$L"
  : > "$cap"; : > "$kl"; : > "$out"

  BONEMESH_KEYLOG="$kl" "$here/drivers/$L.sh" listen --port "$port" \
    $(common "e_srv_$L") --out "$out" --seconds 30 &
  wait_bind "$port"
  # A low rekey-frame threshold on the initiator so a live rekey happens inside
  # the window and `rekey` frames are among those checked.
  # A low rekey threshold so a live rekey happens inside the window, and the
  # connector is left to reach its own deadline rather than being killed: its
  # orderly shutdown is what emits `bye`, and a signal would cost the two kinds
  # this pairing can otherwise reach.
  # shellcheck disable=SC2046
  BONEMESH_REKEY_FRAMES=2 "$here/drivers/go.sh" connect $(common "e_cli_$L") \
    --host 127.0.0.1 --port "$port" --to "e_srv_$L" --message "$work/big.msg" \
    --capture "$cap" --seconds 10 >/dev/null 2>&1 &
  connector=$!
  poll "$out" tier12-emitted 80 || true
  wait "$connector" 2>/dev/null || true
  kill $(jobs -p) 2>/dev/null || true; pkill -f "$mesh" 2>/dev/null || true; sleep 1

  if [ ! -s "$cap" ] || [ ! -s "$kl" ]; then
    echo "FAIL $L — no capture or no keylog was produced, so nothing was checked"
    fail=1
    continue
  fi
  "$inspect" --keylog "$kl" --capture "$cap" 2>/dev/null > "$work/inner-$L.ndjson" || true
  # r2i is the listener's own emissions; i2r is the Go capturer's.
  "$checker" --allowlist "$allow" --label "$L" --dir r2i < "$work/inner-$L.ndjson" || fail=1
  if [ "$L" != go ]; then
    "$checker" --allowlist "$allow" --label "go(vs $L)" --dir i2r < "$work/inner-$L.ndjson" || fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "tier 12: FAILURES present"
  exit 1
fi
echo "tier 12: every implementation emitted only fields the spec names"
