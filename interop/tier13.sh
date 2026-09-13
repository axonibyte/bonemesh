#!/bin/sh
# Tier 13 — public API parity (decision #23), the axis that had no gate.
#
# The rule is "reference implementations shall do nothing more than what the
# protocol expressly denotes". It was gated for BONEMESH_* tunables, message types
# and corpus schemas. Nothing asked whether a port exposes a METHOD the protocol
# never denoted -- which is how a public broadcast() lived in exactly one
# implementation through the whole 8x7 corpus grid run twice, specsrc, the 49-cell
# matrix and tiers 5-10, and was caught only by a human diffing two ports
# method-for-method.
#
# Both directions are checked, and they catch different things: a MISSING
# capability is a port quietly doing less than its siblings (broadcast's shape),
# an EXTRA one is surface the rule forbids.
#
# What this tier does NOT prove: that a capability behaves the same way, or that
# signatures match. The matrix and tiers 5-12 answer behaviour; this answers only
# "is the same set of things callable?", because a name table is maintainable and
# a cross-language signature model is not.
#
# Runs anywhere the toolchains are; each implementation is skipped loudly if its
# own toolchain is absent, and a skip is never a pass.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
surface="$repo/spec/corpus/api.json"
checker="$repo/spec/conformance/apicheck"
work=$(mktemp -d)
fail=0
checked=0
trap 'rm -rf "$work"' EXIT

if [ ! -x "$checker" ] || [ "$repo/spec/conformance/cmd/apicheck/main.go" -nt "$checker" ]; then
  gocmd=go
  command -v go126 >/dev/null 2>&1 && gocmd=go126
  (cd "$repo/spec/conformance" && "$gocmd" build -o apicheck ./cmd/apicheck)
fi

# --- oracle self-test ---------------------------------------------------------
# Feed it what a broken port would look like before trusting any pass.
printf '%s\n' Start Connect Send SendM Broadcast AddListener AckListener Port RouteTable SessionInfo \
  | "$checker" --surface "$surface" --impl go >/dev/null 2>&1 \
  && { echo "tier 13: SELF-TEST FAIL — a missing capability was not caught"; exit 1; }
printf '%s\n' Start Connect Send SendM Broadcast AddListener AckListener Port RouteTable SessionInfo Kill Teleport \
  | "$checker" --surface "$surface" --impl go >/dev/null 2>&1 \
  && { echo "tier 13: SELF-TEST FAIL — an undenoted extra method was not caught"; exit 1; }
: | "$checker" --surface "$surface" --impl go >/dev/null 2>&1 \
  && { echo "tier 13: SELF-TEST FAIL — an empty extraction passed"; exit 1; }
printf '%s\n' Start Connect Send SendM Broadcast AddListener AckListener Port RouteTable SessionInfo Kill \
  | "$checker" --surface "$surface" --impl go >/dev/null 2>&1 \
  || { echo "tier 13: SELF-TEST FAIL — a conforming surface was rejected"; exit 1; }
echo "oracle self-test passed: a missing capability, an extra method and an empty extraction all fail; a conforming surface passes"

for impl in elixir go java js php python rust; do
  if ! sh "$here/api-surface.sh" "$impl" > "$work/$impl.names" 2>"$work/$impl.err"; then
    echo "SKIP $impl — could not read its surface ($(head -1 "$work/$impl.err" 2>/dev/null))"
    continue
  fi
  checked=$((checked + 1))
  "$checker" --surface "$surface" --impl "$impl" < "$work/$impl.names" || fail=1
done

if [ "$checked" -lt 2 ]; then
  echo "tier 13: only $checked implementation(s) could be read — parity is not a claim about one"
  exit 1
fi
if [ "$fail" -ne 0 ]; then
  echo "tier 13: FAILURES present"
  exit 1
fi
echo "tier 13: all $checked implementations expose the same public surface"
