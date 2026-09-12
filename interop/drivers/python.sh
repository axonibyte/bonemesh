#!/bin/sh
# Python driver for the interop harness. Speaks the same neutral driver contract.
#
# Uses the project venv directly rather than `uv run`, for two reasons: uv would
# re-resolve the environment on every invocation, and the harness invokes this
# script many times (the health probe alone runs once per tier). The venv is
# created on first use, the way go.sh and rust.sh build their binaries on first
# use, so a cold build never happens inside a health probe -- a slow probe reads
# as an unavailable driver.
#
# On hosts without a cryptography wheel (FreeBSD, notably) that first `uv sync`
# compiles it from source and takes several minutes. Set BONEMESH_PY to an
# interpreter that already has `cryptography` installed to skip the venv entirely.
repo=$(cd "$(dirname "$0")/../.." && pwd)
py="${BONEMESH_PY:-$repo/python/.venv/bin/python}"

if [ -z "${BONEMESH_PY:-}" ] && [ ! -x "$py" ]; then
  (cd "$repo/python" && uv sync --locked >/dev/null 2>&1) || exit 1
fi

# When BONEMESH_PY names an external interpreter, the `bonemesh` package is not
# installed in it -- only its dependencies are -- so put the source tree on the
# import path. PYTHONPATH is harmless for the venv case, where the package is
# installed and takes precedence anyway.
export PYTHONPATH="$repo/python${PYTHONPATH:+:$PYTHONPATH}"

exec "$py" "$repo/python/bin/interop_node.py" "$@"
