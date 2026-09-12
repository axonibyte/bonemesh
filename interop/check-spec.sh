#!/bin/sh
# Methodology tier 3 -- source-as-data: the normative spec read as DATA and every
# implementation checked against it.
#
# docs/PLAN.md §5 and docs/architecture.md §5 both list tier 3 as a per-language
# obligation; no implementation ever had one. The checker is
# spec/conformance/cmd/specsrc (Go, per decision #12), written once and pointed at
# all of them, because "did this spec edit land in the code, and does the code
# read tunables the spec never documents?" is the same question in every language.
#
# Runs here rather than in the bonemesh-spec reaper tenant, because that tenant
# syncs spec/ alone and cannot see the implementations at all. This needs the
# whole repo, like the rest of interop/.
#
# Usage:
#   sh interop/check-spec.sh              check this repository
#   sh interop/check-spec.sh --self-test  prove the checker can fail
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
bin="$repo/spec/conformance/specsrc"

build() {
  go=go126
  command -v "$go" >/dev/null 2>&1 || go=go
  (cd "$repo/spec/conformance" && GOTOOLCHAIN=local GOFLAGS=-mod=vendor "$go" build -o specsrc ./cmd/specsrc)
}

# Rebuild when the source is newer than the binary, for the same reason
# ensure-jar.sh exists: a checker that reports PASS for code that is not the code
# under test is worse than no checker.
if [ ! -x "$bin" ] || [ -n "$(find "$repo/spec/conformance/cmd/specsrc" -newer "$bin" -print -quit 2>/dev/null)" ]; then
  build
fi

if [ "${1:-}" != "--self-test" ]; then
  echo "checking every implementation against the pinned spec"
  exec "$bin"
fi

# --- self-test ---------------------------------------------------------------
# A synthetic tree with one fake implementation, mutated one way at a time. Each
# mutation must make the checker exit non-zero AND name the right thing; a
# checker observed only passing is a checker of unmeasured value.

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/spec/corpus" "$work/js/src" "$work/interop"
cp "$repo/spec/protocol.md" "$repo/spec/security.md" "$work/spec/"
cp "$repo/spec/corpus/messages.json" "$work/spec/corpus/"

# A fake implementation that satisfies every check, built by asking the checker
# what it wants: run it against the synthetic tree and let it name each missing
# constant until it is satisfied. Hand-listing the constants here would duplicate
# the spec a third time and rot.
: > "$work/js/src/fake.js"
i=0
while [ "$i" -lt 10 ]; do
  i=$((i + 1))
  out=$("$bin" -root "$work" 2>&1 || true)
  added=0
  # Satisfy every complaint this pass makes, not just the first, so the loop
  # converges in a handful of rounds rather than one per constant.
  for tok in \
    $(echo "$out" | sed -n 's/.*missing .*(spec pins "\(.*\)")/\1/p') \
    $(echo "$out" | sed -n 's/.*does not read \(BONEMESH_[A-Z0-9_]*\),.*/\1/p') \
    $(echo "$out" | sed -n 's/.*never names message type "\(.*\)"/\1/p')
  do
    printf '"%s"\n' "$tok" >> "$work/js/src/fake.js"
    added=1
  done
  [ "$added" -eq 0 ] && break
done

if ! "$bin" -root "$work" >"$work/base.log" 2>&1; then
  echo "SELF-TEST FAIL: could not build a synthetic implementation that passes"
  sed 's/^/    /' "$work/base.log"
  exit 1
fi
echo "self-test baseline: a synthetic implementation satisfying the spec passes"

expect_fail() {
  what="$1"; want="$2"
  if "$bin" -root "$work" >"$work/m.log" 2>&1; then
    echo "SELF-TEST FAIL: $what did not fail the check"
    sed 's/^/    /' "$work/m.log"
    exit 1
  fi
  if ! grep -q "$want" "$work/m.log"; then
    echo "SELF-TEST FAIL: $what failed, but not for the stated reason (wanted /$want/)"
    sed 's/^/    /' "$work/m.log"
    exit 1
  fi
  echo "  ok: $what"
}

cp "$work/js/src/fake.js" "$work/fake.js.good"

# 1. a constant the spec pins, dropped from the implementation
grep -v '65536' "$work/fake.js.good" > "$work/js/src/fake.js"
expect_fail "a dropped frame cap" "missing transport frame cap"
cp "$work/fake.js.good" "$work/js/src/fake.js"

# 2. a tunable the implementation reads that the spec never documents
echo '"BONEMESH_UNDOCUMENTED_KNOB"' >> "$work/js/src/fake.js"
expect_fail "an undocumented tunable" "no spec document mentions"
cp "$work/fake.js.good" "$work/js/src/fake.js"

# 3. the spec itself drifting: change a pinned value and the code no longer matches
sed 's/^| Transport frame max | 65536 bytes/| Transport frame max | 65537 bytes/' \
  "$repo/spec/protocol.md" > "$work/spec/protocol.md"
expect_fail "a spec constant changed without the code" "missing transport frame cap"
cp "$repo/spec/protocol.md" "$work/spec/protocol.md"

# 3b. A constant written with digit-group separators must still be FOUND. This is
#     the positive direction, and it needs asserting in both: a checker that closed
#     up separators too eagerly would also match 1677721 inside 16_777_216_0, and a
#     checker that did not close them at all would fail every Elixir and Rust
#     constant over four digits. The repository's own Elixir port writes
#     16_777_216, so without this the tool either rejects idiomatic source or has
#     an untested special case.
sed 's/"16777216"/"16_777_216"/' "$work/fake.js.good" > "$work/js/src/fake.js"
if ! "$bin" -root "$work" >"$work/sep.log" 2>&1; then
  echo "SELF-TEST FAIL: a digit-separated constant (16_777_216) was not recognised"
  sed 's/^/    /' "$work/sep.log"
  exit 1
fi
echo "  ok: a digit-separated constant is recognised"

# 3c. ...and separators must not make a WRONG value look right: 1_677_721 closes up
#     to 1677721, which is a prefix of 16777216 only if the search is done on the
#     wrong side. Dropping the real constant entirely must still fail.
sed 's/"16777216"/"1_677_721"/' "$work/fake.js.good" > "$work/js/src/fake.js"
expect_fail "a digit-separated near-miss" "missing reassembly buffer max"
cp "$work/fake.js.good" "$work/js/src/fake.js"

# 4. the corpus using a schema the spec does not list
sed 's/"schema": "bye"/"schema": "nosuchtype"/' "$repo/spec/corpus/messages.json" \
  > "$work/spec/corpus/messages.json"
expect_fail "a corpus schema absent from the spec" "which the spec's type table does not list"
cp "$repo/spec/corpus/messages.json" "$work/spec/corpus/"

# 5. a reworded spec that breaks an extraction must fail loudly, never silently
#    stop checking -- the failure mode most likely to rot this tool.
sed 's/^| Handshake frame max |/| Handshake frame maximum |/' "$repo/spec/protocol.md" \
  > "$work/spec/protocol.md"
expect_fail "a reworded spec table" "cannot extract handshake frame cap"
cp "$repo/spec/protocol.md" "$work/spec/protocol.md"

# 6. A repository root nested under a directory named like a build artifact must
#    still be searched. The exclusions (build/, target/, vendor/, node_modules/)
#    are matched against the path RELATIVE to the root; matching the absolute path
#    means any ancestor with one of those names poisons the whole tree. Bitbucket
#    Pipelines clones into /opt/atlassian/pipelines/agent/build, so "/build/"
#    matched every file and tier 3 found no source at all -- it failed loudly only
#    because of the "no implementation source found" guard. This is that bug.
nested="$work/agent/build"
mkdir -p "$nested/spec/corpus" "$nested/js/src" "$nested/interop"
cp "$work/spec/protocol.md" "$work/spec/security.md" "$nested/spec/"
cp "$work/spec/corpus/messages.json" "$nested/spec/corpus/"
cp "$work/fake.js.good" "$nested/js/src/fake.js"
if ! "$bin" -root "$nested" >"$work/nested.log" 2>&1; then
  echo "SELF-TEST FAIL: a root under a directory named build/ found no source"
  sed 's/^/    /' "$work/nested.log"
  exit 1
fi
echo "  ok: a root nested under build/ is still searched"

# 7. And the exclusions must still actually exclude: a vendored file under the
#    implementation root must not be able to satisfy a constant.
mkdir -p "$nested/js/src/vendor"
grep -v '65536' "$work/fake.js.good" > "$nested/js/src/fake.js"
cp "$work/fake.js.good" "$nested/js/src/vendor/vendored.js"
if "$bin" -root "$nested" >"$work/vendored.log" 2>&1; then
  echo "SELF-TEST FAIL: a vendored file satisfied a constant the real source lacks"
  sed 's/^/    /' "$work/vendored.log"
  exit 1
fi
echo "  ok: a vendored file cannot satisfy a check"
cp "$work/fake.js.good" "$nested/js/src/fake.js"
rm -rf "$nested/js/src/vendor"

# Back to the baseline, to prove the mutations were what failed.
if ! "$bin" -root "$work" >"$work/final.log" 2>&1; then
  echo "SELF-TEST FAIL: the restored synthetic tree does not pass"
  sed 's/^/    /' "$work/final.log"
  exit 1
fi
echo "SELF-TEST PASS: the checker fails on dropped constants, undocumented tunables,"
echo "                spec drift, corpus drift, a reworded spec and a digit-separated"
echo "                near-miss; recognises idiomatic 16_777_216; searches a root"
echo "                nested under build/; and still excludes vendored files"
