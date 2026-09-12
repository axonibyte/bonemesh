#!/bin/sh
# Runs one of python/bin/*.py with this host's resolved interpreter.
#
# Shared by the seven check-*-python.sh wrappers so the venv bootstrap (and the
# BONEMESH_PY escape hatch for hosts without a cryptography wheel) is written once.
# Deliberately NOT in drivers/: that directory is the implementation registry, so
# anything dropped there is discovered as a language and health-probed with
# `keygen`. Putting this helper there made the harness report a phantom
# implementation called "python-run" -- caught immediately by
# run-corpus-checks.sh's completeness gate, which then demanded seven check
# scripts for it.
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
py="${BONEMESH_PY:-$repo/python/.venv/bin/python}"

if [ -z "${BONEMESH_PY:-}" ] && [ ! -x "$py" ]; then
  (cd "$repo/python" && uv sync --locked >/dev/null 2>&1) || {
    echo "python-run: could not create python/.venv (set BONEMESH_PY to skip)" >&2
    exit 1
  }
fi

script="$1"; shift
exec "$py" "$repo/python/$script" "$@"
