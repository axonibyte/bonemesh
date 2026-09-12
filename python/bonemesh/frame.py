"""BoneMesh v3 frame reader/writer (protocol.md §2).

One newline-terminated UTF-8 JSON object per frame within a hard size cap (defect
D7). Classification verdicts match the shared corpus (spec/corpus/framing.json).

A frame body must be exactly one JSON value with nothing but whitespace after it:
``{...} X`` is ``trailing-data``, not ``invalid-json``. ``json.JSONDecoder``'s
``raw_decode`` gives the end of the first complete value, which keeps those two
verdicts distinct without a hand-rolled scanner.

Python's ``json`` accepts ``NaN``, ``Infinity`` and ``-Infinity`` by default,
which the corpus requires be rejected as ``invalid-json`` (strict RFC 8259).
``parse_constant`` is what turns them back into errors -- without it the five
``lenient-*`` cases would diverge from the other implementations.
"""

from __future__ import annotations

import json

HANDSHAKE_CAP = 32768
TRANSPORT_CAP = 65536

_WS = " \t\n\r"


def _reject_constant(name: str):
    raise ValueError(f"non-finite number not permitted: {name}")


_DECODER = json.JSONDecoder(parse_constant=_reject_constant)


def classify(raw: bytes, cap: int) -> tuple[dict | None, str | None]:
    """Returns ``(obj, None)`` on success or ``(None, reason)`` on rejection.

    Reads only up to the first newline.
    """
    nl = raw.find(b"\n")
    if nl < 0:
        return None, "no-newline"
    if nl + 1 > cap:
        return None, "oversize"
    content = raw[:nl]
    if len(content) == 0:
        return None, "empty"

    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return None, "invalid-utf8"

    start = 0
    while start < len(text) and text[start] in _WS:
        start += 1
    try:
        value, end = _DECODER.raw_decode(text, start)
    except ValueError:
        return None, "invalid-json"

    rest = end
    while rest < len(text) and text[rest] in _WS:
        rest += 1
    if rest < len(text):
        return None, "trailing-data"

    if not isinstance(value, dict):
        return None, "not-an-object"
    return value, None


def encode(obj) -> bytes:
    """Encode an object as a frame body followed by a newline."""
    return (json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
