"""Operational knobs (protocol.md §0).

Local behaviour, never part of the wire contract, read once from the environment
at node start. Two nodes with different values still interoperate, which is why
tests can set short values to make a slow behaviour fire quickly.
"""

from __future__ import annotations

import re

import os
from dataclasses import dataclass


# An optional sign then decimal digits, and nothing else (protocol.md section 0).
_INT = re.compile(r"^-?[0-9]+$")


def _env_int(name: str, fallback: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not _INT.match(raw):
        return fallback
    # int() accepts digit separators and surrounding whitespace -- int("1_000") is
    # 1000 and int(" 12 ") is 12 -- so the pattern above decides, not int(). The
    # other ports were lenient in the other direction, reading "12abc" as 12.
    return int(raw, 10)


@dataclass(frozen=True)
class Tunables:
    probe_timeout_ms: int = 15000
    idle_ms: int = 0
    retry_base_ms: int = 500
    retry_cap_ms: int = 30000
    retry_max_ms: int = 60000
    rekey_ms: int = 3600000
    rekey_frames: int = 65536
    rekey_timeout_ms: int = 10000
    keylog_path: str = ""


def load_tunables() -> Tunables:
    return Tunables(
        probe_timeout_ms=_env_int("BONEMESH_PROBE_TIMEOUT_MS", 15000),
        idle_ms=_env_int("BONEMESH_IDLE_MS", 0),
        retry_base_ms=_env_int("BONEMESH_RETRY_BASE_MS", 500),
        retry_cap_ms=_env_int("BONEMESH_RETRY_CAP_MS", 30000),
        retry_max_ms=_env_int("BONEMESH_RETRY_MAX_MS", 60000),
        rekey_ms=_env_int("BONEMESH_REKEY_MS", 3600000),
        rekey_frames=_env_int("BONEMESH_REKEY_FRAMES", 65536),
        rekey_timeout_ms=_env_int("BONEMESH_REKEY_TIMEOUT_MS", 10000),
        keylog_path=os.environ.get("BONEMESH_KEYLOG", ""),
    )
