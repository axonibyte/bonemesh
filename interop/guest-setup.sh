#!/bin/sh
# Provisions an ubuntu-26.04 reaper guest with the toolchains the interop suite
# drives, then builds the artifacts that need a build step. Host execution: this
# runs directly on the VM as root, which has network and tc/netem.
#
# Four toolchains come from apt at versions that match the driver and link the
# system OpenSSL 3.5 (so their post-quantum crypto works): OpenJDK 25, Go 1.26,
# PHP 8.5 (+sodium), and Rust. Node 24 comes from NodeSource (apt's Node 22
# bundles an OpenSSL without ML-KEM/ML-DSA). Erlang/Elixir are attempted from the
# Erlang Solutions repo for an OTP with the native PQC API (apt's OTP 27.3 lacks
# it); if that install does not land, the Elixir node is left out of the guest
# run and the omission is logged — never silently dropped.
set -eu

export DEBIAN_FRONTEND=noninteractive
log() { echo "guest-setup: $*"; }

log "apt toolchains (java 25, go 1.26, php 8.5 + sodium, rust; netem + iptables)"
# Remove any stale third-party repo a prior run may have added (e.g. an Erlang
# Solutions list with no suite for this Ubuntu codename), so apt-get update is
# clean and idempotent.
rm -f /etc/apt/sources.list.d/erlang-solutions.list
apt-get update -qq
apt-get install -y -qq \
  openjdk-25-jdk-headless golang-go \
  php8.5-cli \
  rustc cargo \
  iproute2 iptables build-essential curl ca-certificates gnupg git >/dev/null
# php8.5-cli bundles the sodium extension on Ubuntu (no separate package).

log "node 24 from NodeSource (apt's Node 22 bundles an OpenSSL without ML-KEM/ML-DSA)"
if ! node --version 2>/dev/null | grep -q '^v24'; then
  curl -fsSL https://deb.nodesource.com/setup_24.x | bash - >/dev/null 2>&1
  apt-get install -y -qq nodejs >/dev/null
fi

# Elixir is deliberately NOT installed here. The node needs Erlang/OTP 28 for the
# native ML-DSA/ML-KEM crypto API; ubuntu-26.04 apt ships OTP 27.3 (which lacks
# that API — verified: :crypto.generate_key(:mldsa65,...) raises), and Erlang
# Solutions has no 26.04 suite yet. Building OTP 28 from source on every
# ephemeral guest is too costly for a routine gate. Elixir's cross-language
# interop is fully covered by the six-language matrix on the driver (which has
# OTP 28); the netem tiers here run the other five. The runners health-probe each
# driver and log the skip, so this exclusion is explicit, never silent.

log "toolchain versions present:"
java -version 2>&1 | head -1 || true
go version 2>/dev/null || true
php -v 2>/dev/null | head -1 || true
rustc --version 2>/dev/null || true
node --version 2>/dev/null || true
elixir --version 2>/dev/null | tail -1 || true
openssl version || true
tc -V 2>/dev/null || true

log "building the Java jar (bonemesh-ca + node) once, up front"
(cd java && ./gradlew --no-daemon --quiet shadowJar)

# Pre-build the compiled interop binaries so the run phase never cold-builds them
# inside a health probe (a slow cold build there reads as an unavailable driver).
log "pre-building Go + Rust interop binaries and the tier-5 fault peer"
(cd go && GOTOOLCHAIN=local GOFLAGS=-mod=vendor go build -o interop_node ./cmd/interop_node)
(cd interop/tier5 && GOTOOLCHAIN=local GOFLAGS=-mod=vendor go build -o faultpeer .)
(cd interop/tier7 && GOTOOLCHAIN=local GOFLAGS=-mod=vendor go build -o fuzzer .)
(cd rust && cargo build --offline --quiet --bin interop_node)

log "done"
