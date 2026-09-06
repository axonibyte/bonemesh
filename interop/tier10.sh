#!/bin/sh
# Tier 10 — feature-behavior conformance (methodology tier 10), language-agnostic.
#
# Where tiers 5-9 prove the 3.0 wire contract, tier 10 proves the 3.1 features
# added across all six implementations actually work ON THE WIRE, cross-language:
#   1. ack        — a delivered message is acknowledged back to the origin.
#   2. nak / D4    — a relay that drops a message names ITSELF as the failing
#                    hop, never the destination (defect D4).
#   3. rekey       — a live session rekeys under traffic; both ends advance
#                    their epoch and delivery continues across the key swap.
#   4. probe-death — a peer whose process is frozen (SIGSTOP) is declared dead
#                    and its routes withdrawn, though its socket stays open.
#   5. idle        — a link carrying no data past the idle timeout is torn down.
#   6. keylog      — a node's BONEMESH_KEYLOG plus a captured stream lets
#                    bonemesh-inspect reproduce the plaintext (any language's
#                    log, one Go inspector).
#
# The simultaneous-dial tiebreak (F1) is not an interop scenario here: the
# neutral driver's mesh mode dials its peers once at startup and exits if a peer
# is not yet listening, so it cannot stage the mutual, racing dial the tiebreak
# needs (a chicken-and-egg the contract can't express). F1 is proven instead by
# the per-language unit tests (both registration orders, both label orderings),
# each mutation-checked.
#
# Each scenario is gated on the capabilities its drivers advertise (`caps`),
# skips loudly where unmet, and self-tests its oracle before trusting a pass.
# Roles are assigned round-robin across usable implementations so the behaviors
# are exercised cross-language rather than within one.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
cabin="$repo/go/bonemesh-ca"
inspect="$repo/go/bonemesh-inspect"
mesh="tier10-mesh"
work=$(mktemp -d)
fail=0
trap 'rm -rf "$work"; kill $(jobs -p) 2>/dev/null || true; pkill -f "$mesh" 2>/dev/null || true' EXIT

ca() { "$cabin" "$@" >/dev/null 2>&1; }
[ -x "$cabin" ] || (cd "$repo/go" && GOTOOLCHAIN=local GOFLAGS=-mod=vendor go build -o bonemesh-ca ./cmd/bonemesh-ca)
[ -x "$inspect" ] || (cd "$repo/go" && GOTOOLCHAIN=local GOFLAGS=-mod=vendor go build -o bonemesh-inspect ./cmd/bonemesh-inspect)

# --- usable implementations + capability probe --------------------------------
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
# shellcheck disable=SC2086
set -- $usable
n=$#
if [ "$n" -lt 2 ]; then
  echo "tier 10: need at least two usable implementations; only '$usable' — skipping"
  exit 0
fi
nth() { i=0; for x in $usable; do [ "$i" -eq "$1" ] && { echo "$x"; return; }; i=$((i + 1)); done; }
has_cap() { grep -qw "$2" "$work/caps-$1" 2>/dev/null; }
# gate LIST CAP: keep only impls advertising cap; echo them, or nothing.
gate() { _c="$2"; _o=""; for _i in $1; do has_cap "$_i" "$_c" && _o="$_o $_i"; done; echo "$_o"; }

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

# Monotonic port allocator. A /dev/tcp connect-probe is not portable (dash, the
# guest's /bin/sh, has no /dev/tcp), so a probe-based free_port would hand out
# the same base port to every scenario and they would collide. Handing out a
# fresh incrementing port per call is portable and collision-free within a run.
PORT=37100
next_port() { PORT=$((PORT + 1)); echo "$PORT"; }
# wait_bind blocks until a real TCP connect to the port succeeds — the node is
# then truly listening, so a dialer (mesh/connect dials once and exits on
# failure) never races ahead of the bind. /dev/tcp is a bash builtin and the
# guest's /bin/sh is dash, so the probe runs under bash explicitly (present on
# both the interop guest and the driver host). Falls back to a fixed grace only
# if no bash is found.
if command -v bash >/dev/null 2>&1; then
  port_open() { bash -c "exec 3<>/dev/tcp/127.0.0.1/$1" 2>/dev/null; }
else
  port_open() { return 1; }  # no probe available; wait_bind uses its grace cap
fi
wait_bind() { t=0; while ! port_open "$1"; do t=$((t + 1)); [ "$t" -gt 100 ] && break; sleep 0.1; done; }
common() { printf -- '--mesh %s --root-pub %s --cert %s --id-pub %s --id-priv %s' "$mesh" "$work/ca/root.pub" "$work/$1.cert.json" "$work/$1.pub" "$work/$1.priv"; }
# poll FILE PATTERN TRIES — succeed when PATTERN is found in FILE.
poll() { t=0; while [ "$t" -lt "$3" ]; do grep -q "$2" "$1" 2>/dev/null && return 0; t=$((t + 1)); sleep 0.25; done; return 1; }
say_fail() { echo "  tier 10 [$1]: FAIL — $2"; fail=1; }

# ============================================================================
# Scenario 1 — ack: a delivered message is acknowledged to the origin.
# ============================================================================
scenario_ack() {
  eligible=$(gate "$usable" ack)
  # shellcheck disable=SC2086
  set -- $eligible
  [ "$#" -ge 2 ] || { echo "SKIP ack — need two impls advertising 'ack'"; return; }
  srv=$(nth 0); cli=$(nth 1)
  echo "[ack] responder=$srv initiator=$cli"
  issue s_ack "$srv"; issue c_ack "$cli"
  printf '{"probe":"ack-me"}' > "$work/ack.msg"
  # Oracle self-test: an empty acks file must not satisfy the ack check.
  : > "$work/ack.acks"
  if grep -q '"type":"ack"' "$work/ack.acks" 2>/dev/null; then say_fail ack "oracle fires on an empty file"; return; fi
  port=$(next_port)
  # shellcheck disable=SC2046
  "$here/drivers/$srv.sh" listen --port "$port" $(printf -- '--mesh %s --root-pub %s --cert %s --id-pub %s --id-priv %s' "$mesh" "$work/ca/root.pub" "$work/s_ack.cert.json" "$work/s_ack.pub" "$work/s_ack.priv") --out "$work/ack.srv.out" --seconds 15 &
  wait_bind "$port"
  # shellcheck disable=SC2046
  "$here/drivers/$cli.sh" connect $(printf -- '--mesh %s --root-pub %s --cert %s --id-pub %s --id-priv %s' "$mesh" "$work/ca/root.pub" "$work/c_ack.cert.json" "$work/c_ack.pub" "$work/c_ack.priv") --host 127.0.0.1 --port "$port" --to s_ack --message "$work/ack.msg" --acks "$work/ack.acks" --seconds 10 &
  if poll "$work/ack.acks" '"type":"ack"' 40; then
    echo "  [ack] OK — origin received an ack"
  else
    say_fail ack "origin never received an ack for its delivered message"
  fi
  kill $(jobs -p) 2>/dev/null || true; pkill -f "$mesh" 2>/dev/null || true; sleep 1
}

# ============================================================================
# Scenario 2 — nak / D4: a relay that TTL-drops a message names itself, not the
# destination. Line alpha—bravo—charlie; alpha sends toward charlie; we make the
# relay bravo the sender's next hop and kill charlie so bravo cannot forward.
# ============================================================================
scenario_nak() {
  eligible=$(gate "$usable" nak)
  # shellcheck disable=SC2086
  set -- $eligible
  [ "$#" -ge 2 ] || { echo "SKIP nak — need two impls advertising 'nak'"; return; }
  ra=$(nth 0); rb=$(nth $((1 % $#)))
  echo "[nak] alpha=$ra bravo(relay)=$rb charlie=$ra"
  issue n_alpha "$ra"; issue n_bravo "$rb"; issue n_charlie "$ra"
  # Oracle self-test: the check must not pass on an acks file lacking a nak.
  : > "$work/nak.acks"
  if grep -q '"hop":"n_bravo"' "$work/nak.acks" 2>/dev/null; then say_fail nak "oracle fires on an empty file"; return; fi
  printf '{"probe":"nak-me"}' > "$work/nak.msg"
  pB=$(next_port); pC=$(next_port)
  # shellcheck disable=SC2046
  "$here/drivers/$rb.sh" listen --port "$pB" $(common n_bravo) --out "$work/nak.bravo.out" --seconds 60 &
  wait_bind "$pB"
  # shellcheck disable=SC2046
  "$here/drivers/$ra.sh" mesh $(common n_charlie) --peers "127.0.0.1:$pB" --out "$work/nak.charlie.out" --seconds 60 &
  # alpha dials bravo, learns a route to charlie via bravo, then we kill charlie
  # and alpha keeps sending: bravo can no longer forward and NAKs, naming itself.
  # shellcheck disable=SC2046
  "$here/drivers/$ra.sh" mesh $(common n_alpha) --peers "127.0.0.1:$pB" --send-to n_charlie --message "$work/nak.msg" --acks "$work/nak.acks" --routes "$work/nak.alpha.routes" --seconds 60 &
  # Wait until alpha routes to charlie via bravo, then kill charlie.
  if ! poll "$work/nak.alpha.routes" '"n_charlie":"n_bravo"' 120; then
    say_fail nak "alpha never learned a route to charlie via bravo"; kill $(jobs -p) 2>/dev/null || true; return
  fi
  # Kill only charlie (its cert path is unique; alpha merely references the
  # label via --send-to n_charlie, so match the cert file, not the bare label).
  pkill -f "n_charlie.cert.json" 2>/dev/null || true
  # After charlie is gone, bravo's route to charlie dies; alpha's sends to bravo
  # get a no-route/link-dead NAK from bravo naming bravo.
  if poll "$work/nak.acks" '"type":"nak"' 60 && grep -q '"hop":"n_bravo"' "$work/nak.acks" 2>/dev/null; then
    echo "  [nak] OK — NAK names the relay bravo (D4 cured)"
  else
    say_fail nak "no NAK naming the relay bravo arrived (D4)"
  fi
  kill $(jobs -p) 2>/dev/null || true; pkill -f "$mesh" 2>/dev/null || true; sleep 1
}

# ============================================================================
# Scenario 3 — rekey under traffic: epoch advances on both ends, delivery holds.
# ============================================================================
scenario_rekey() {
  eligible=$(gate "$usable" rekey)
  eligible=$(gate "$eligible" sessions)
  # shellcheck disable=SC2046
  set -- $eligible
  [ "$#" -ge 2 ] || { echo "SKIP rekey — need two impls advertising rekey+sessions"; return; }
  srv=$(nth 0); cli=$(nth 1)
  echo "[rekey] responder=$srv initiator=$cli"
  issue r_srv "$srv"; issue r_cli "$cli"
  printf '{"probe":"rekey-after"}' > "$work/rekey.msg"
  export BONEMESH_REKEY_FRAMES=6
  port=$(next_port)
  # shellcheck disable=SC2046
  "$here/drivers/$srv.sh" listen --port "$port" $(common r_srv) --out "$work/rekey.srv.out" --sessions "$work/rekey.srv.sess" --seconds 20 &
  wait_bind "$port"
  # shellcheck disable=SC2046
  "$here/drivers/$cli.sh" mesh $(common r_cli) --peers "127.0.0.1:$port" --send-to r_srv --message "$work/rekey.msg" --sessions "$work/rekey.cli.sess" --seconds 20 &
  # Oracle self-test: epoch 0 must not satisfy the >=1 check.
  printf '{"r_srv":{"epoch":0,"th":"x"}}' > "$work/rekey.synth"
  if grep -q '"epoch":[1-9]' "$work/rekey.synth"; then say_fail rekey "epoch oracle fires on epoch 0"; unset BONEMESH_REKEY_FRAMES; return; fi
  if poll "$work/rekey.cli.sess" '"epoch":[1-9]' 60 && poll "$work/rekey.srv.sess" '"epoch":[1-9]' 60; then
    if poll "$work/rekey.srv.out" 'rekey-after' 40; then
      echo "  [rekey] OK — both ends rekeyed (epoch>=1) and delivery continued"
    else
      say_fail rekey "epoch advanced but delivery broke across the swap"
    fi
  else
    say_fail rekey "one or both ends never advanced their rekey epoch"
  fi
  unset BONEMESH_REKEY_FRAMES
  kill $(jobs -p) 2>/dev/null || true; pkill -f "$mesh" 2>/dev/null || true; sleep 1
}

# ============================================================================
# Scenario 6 — idle teardown: a data-idle link is torn down when enabled.
# ============================================================================
scenario_idle() {
  eligible=$(gate "$usable" idle)
  eligible=$(gate "$eligible" sessions)
  # shellcheck disable=SC2046
  set -- $eligible
  [ "$#" -ge 2 ] || { echo "SKIP idle — need two impls advertising idle+sessions"; return; }
  srv=$(nth 0); cli=$(nth 1)
  echo "[idle] responder=$srv initiator=$cli"
  issue i_srv "$srv"; issue i_cli "$cli"
  export BONEMESH_IDLE_MS=8000
  port=$(next_port)
  # shellcheck disable=SC2046
  "$here/drivers/$srv.sh" listen --port "$port" $(common i_srv) --sessions "$work/idle.srv.sess" --seconds 40 &
  wait_bind "$port"
  # mesh with no --send-to: only heartbeats flow, so the link is data-idle.
  # shellcheck disable=SC2046
  "$here/drivers/$cli.sh" mesh $(common i_cli) --peers "127.0.0.1:$port" --sessions "$work/idle.cli.sess" --seconds 40 &
  # Wait for the session to appear, then for it to disappear (torn down).
  if poll "$work/idle.cli.sess" '"i_srv"' 60; then
    t=0; gone=no
    while [ "$t" -lt 60 ]; do
      grep -q '"i_srv"' "$work/idle.cli.sess" 2>/dev/null || { gone=yes; break; }
      t=$((t + 1)); sleep 0.25
    done
    [ "$gone" = yes ] && echo "  [idle] OK — data-idle link torn down" || say_fail idle "idle link was not torn down"
  else
    say_fail idle "session never established"
  fi
  unset BONEMESH_IDLE_MS
  kill $(jobs -p) 2>/dev/null || true; pkill -f "$mesh" 2>/dev/null || true; sleep 1
}

# ============================================================================
# Scenario 5 — probe-timeout death: a frozen (SIGSTOP) peer is declared dead.
# ============================================================================
scenario_probe_death() {
  eligible=$(gate "$usable" probe-death)
  eligible=$(gate "$eligible" sessions)
  # shellcheck disable=SC2046
  set -- $eligible
  [ "$#" -ge 2 ] || { echo "SKIP probe-death — need two impls advertising probe-death+sessions"; return; }
  srv=$(nth 0); cli=$(nth 1)
  echo "[probe-death] survivor=$cli frozen=$srv"
  issue p_srv "$srv"; issue p_cli "$cli"
  export BONEMESH_PROBE_TIMEOUT_MS=3000
  port=$(next_port)
  # shellcheck disable=SC2046
  "$here/drivers/$srv.sh" listen --port "$port" $(common p_srv) --seconds 30 &
  srvpid=$!
  wait_bind "$port"
  # shellcheck disable=SC2046
  "$here/drivers/$cli.sh" mesh $(common p_cli) --peers "127.0.0.1:$port" --sessions "$work/pd.cli.sess" --seconds 30 &
  if ! poll "$work/pd.cli.sess" '"p_srv"' 40; then say_fail probe-death "session never established"; unset BONEMESH_PROBE_TIMEOUT_MS; kill $(jobs -p) 2>/dev/null || true; return; fi
  # Freeze the responder's whole process tree so its socket stays open but it
  # stops echoing probes. (The driver shells out to the runtime; stop the group.)
  kill -STOP "$srvpid" 2>/dev/null || true
  pkill -STOP -P "$srvpid" 2>/dev/null || true
  t=0; gone=no
  while [ "$t" -lt 60 ]; do
    grep -q '"p_srv"' "$work/pd.cli.sess" 2>/dev/null || { gone=yes; break; }
    t=$((t + 1)); sleep 0.25
  done
  kill -CONT "$srvpid" 2>/dev/null || true; pkill -CONT -P "$srvpid" 2>/dev/null || true
  [ "$gone" = yes ] && echo "  [probe-death] OK — frozen peer declared dead and withdrawn" || say_fail probe-death "frozen peer was not declared dead"
  unset BONEMESH_PROBE_TIMEOUT_MS
  kill $(jobs -p) 2>/dev/null || true; pkill -f "$mesh" 2>/dev/null || true; sleep 1
}

# ============================================================================
# Scenario 7 — keylog round-trip: a language-L node's BONEMESH_KEYLOG plus a Go
# node's --capture lets bonemesh-inspect reproduce the payload.
# ============================================================================
scenario_keylog() {
  eligible=$(gate "$usable" keylog)
  # shellcheck disable=SC2046
  set -- $eligible
  [ "$#" -ge 1 ] || { echo "SKIP keylog — no impl advertising 'keylog'"; return; }
  # The capturing side must be Go (only Go advertises 'capture').
  has_cap go capture || { echo "SKIP keylog — Go driver (capture) unavailable"; return; }
  L=$(nth 0)  # the keylog-emitting language node (listener)
  echo "[keylog] emitter=$L capturer=go"
  issue k_srv "$L"; issue k_cli go
  printf '{"probe":"keylog-inspect-me"}' > "$work/kl.msg"
  # Oracle self-test: inspecting an empty capture must not print the marker.
  : > "$work/kl.empty"; : > "$work/kl.emptycap"
  if "$inspect" --keylog "$work/kl.empty" --capture "$work/kl.emptycap" 2>/dev/null | grep -q keylog-inspect-me; then
    say_fail keylog "inspector oracle fires on empty inputs"; return
  fi
  port=$(next_port)
  # The Go connector captures the wire; the L listener writes the keylog.
  BONEMESH_KEYLOG="$work/kl.keylog" "$here/drivers/$L.sh" listen --port "$port" $(common k_srv) --out "$work/kl.srv.out" --seconds 25 &
  wait_bind "$port"
  # shellcheck disable=SC2046
  "$here/drivers/go.sh" connect $(common k_cli) --host 127.0.0.1 --port "$port" --to k_srv --message "$work/kl.msg" --capture "$work/kl.capture" --seconds 15 &
  # wait until the payload is delivered and both the keylog and capture have content.
  poll "$work/kl.srv.out" keylog-inspect-me 60 || true
  t=0; while [ "$t" -lt 40 ]; do { [ -s "$work/kl.keylog" ] && [ -s "$work/kl.capture" ]; } && break; t=$((t + 1)); sleep 0.25; done
  if [ -s "$work/kl.keylog" ] && [ -s "$work/kl.capture" ] && \
     "$inspect" --keylog "$work/kl.keylog" --capture "$work/kl.capture" 2>/dev/null | grep -q keylog-inspect-me; then
    echo "  [keylog] OK — inspector reproduced the payload from ${L}'s keylog + Go capture"
  else
    say_fail keylog "inspector could not reproduce the payload from the keylog+capture"
  fi
  kill $(jobs -p) 2>/dev/null || true; pkill -f "$mesh" 2>/dev/null || true; sleep 1
}

scenario_ack
scenario_nak
scenario_rekey
scenario_idle
scenario_probe_death
scenario_keylog

if [ "$fail" -ne 0 ]; then
  echo "tier 10: FAILURES present"
  exit 1
fi
echo "tier 10: all gated feature-behavior scenarios passed"
