"""BoneMesh v3 message schema validation (protocol.md §4) and inner builders.

The validator mirrors the other implementations reason-for-reason, enforced by the
shared corpus (spec/corpus/messages.json).
"""

from __future__ import annotations

import re
import secrets

DEFAULT_TTL = 16

# Python's base64 decoder is lenient about length and alphabet, so validate the
# way the other implementations' decoders do: the standard alphabet, length a
# multiple of four, padding only at the end.
_B64 = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
_MID = re.compile(r"^[0-9a-f]{32}$")


def _is_int(v) -> bool:
    # bool is an int in Python; `true` where a number belongs is malformed.
    return isinstance(v, int) and not isinstance(v, bool)


def _base64_reason(v) -> str | None:
    if not isinstance(v, str):
        return "not-base64"
    if len(v) % 4 != 0:
        return "not-base64"
    if not _B64.match(v):
        return "not-base64"
    return None


def _mid_reason(v) -> str | None:
    if not isinstance(v, str) or not _MID.match(v):
        return "mid-format"
    return None


def validate(schema: str, f) -> str | None:
    """Returns None if valid, else a reason tag.

    Schemas: bmx1, envelope, data, ack, nak, bye.
    """
    if not isinstance(f, dict):
        return "type"
    fn = _VALIDATORS.get(schema)
    if fn is None:
        return "unknown-schema"
    return fn(f)


def _validate_bmx1(f: dict) -> str | None:
    if f.get("t") != "bmx1":
        return "type"
    v = f.get("v")
    if not _is_int(v) or v != 3:
        return "version"
    mesh = f.get("mesh")
    if not isinstance(mesh, str) or mesh == "":
        return "empty-mesh"
    for k in ("e", "k", "n"):
        if k not in f:
            return "missing-field"
        r = _base64_reason(f[k])
        if r:
            return r
    return None


def _validate_envelope(f: dict) -> str | None:
    seq = f.get("seq")
    if not _is_int(seq):
        return "missing-field"
    if seq < 0:
        return "seq-range"
    if "ct" not in f:
        return "missing-field"
    return _base64_reason(f["ct"])


def _validate_data(f: dict) -> str | None:
    if f.get("type") != "data":
        return "type"
    m = _mid_reason(f.get("mid"))
    if m:
        return m
    if not isinstance(f.get("to"), str):
        return "missing-field"
    if not isinstance(f.get("from"), str):
        return "missing-field"
    ttl = f.get("ttl")
    if not _is_int(ttl):
        return "missing-field"
    if ttl < 1 or ttl > 255:
        return "ttl-range"
    return _check_chunking(f)


def _check_chunking(f: dict) -> str | None:
    """Validate the splitting half of the data schema (protocol.md section 6.1): the
    shape of ``chunk``, its bounds, and the rule that exactly one of ``payload`` and
    ``seg`` is present.

    The exclusion is the load-bearing part. It is what stops a node that does not
    reassemble from handing a fragment to the application as though it were a whole
    message -- the silent corruption D11 described. A segment has no payload to
    deliver, so the mistake is unavailable rather than merely forbidden.

    Carrying neither stays ``missing-field`` rather than becoming a splitting error:
    it is an absent field, the corpus has pinned that reason since 3.0.0, and
    renaming it here would have rewritten a vector rather than added one.
    """
    from .chunk import MAX_CHUNKS

    n = 1
    if "chunk" in f:
        chunk = f["chunk"]
        if not isinstance(chunk, dict):
            return "chunk-format"
        if not _is_int(chunk.get("i")) or not _is_int(chunk.get("n")):
            return "chunk-format"
        n = chunk["n"]
        if n < 1 or n > MAX_CHUNKS:
            return "chunk-range"
        if chunk["i"] < 0 or chunk["i"] >= n:
            return "chunk-range"
    has_payload = "payload" in f
    has_seg = "seg" in f
    if not has_payload and not has_seg:
        return "missing-field"
    # Three clauses, none redundant. An explicit "both present" test was removed:
    # mutation showed it could not reject anything these two do not already reject,
    # since n is always 1 or more, so it read as coverage while asserting nothing.
    if n == 1 and has_seg:
        return "payload-or-seg"  # a whole message carries its payload
    if n > 1 and has_payload:
        return "payload-or-seg"  # a segment does not
    if has_seg and not isinstance(f["seg"], str):
        return "seg-format"
    return None


def _validate_ack(f: dict) -> str | None:
    if f.get("type") != "ack":
        return "type"
    return _mid_reason(f.get("mid"))


def _validate_nak(f: dict) -> str | None:
    # Routed back toward the origin like data (to/from/ttl), naming the failing
    # hop and a reason. The reason string is required but its value is not
    # enum-checked, so a future reason value is not a wire break (protocol.md §8).
    if f.get("type") != "nak":
        return "type"
    m = _mid_reason(f.get("mid"))
    if m:
        return m
    hop = f.get("hop")
    if not isinstance(hop, str) or hop == "":
        return "missing-field"
    reason = f.get("reason")
    if not isinstance(reason, str) or reason == "":
        return "missing-field"
    if not isinstance(f.get("to"), str) or not isinstance(f.get("from"), str):
        return "missing-field"
    ttl = f.get("ttl")
    if not _is_int(ttl):
        return "missing-field"
    if ttl < 1 or ttl > 255:
        return "ttl-range"
    return None


def _validate_bye(f: dict) -> str | None:
    # A graceful session-close control -- link-local, so only its type is
    # required; an optional reason string is not validated further.
    if f.get("type") != "bye":
        return "type"
    return None


_VALIDATORS = {
    "bmx1": _validate_bmx1,
    "envelope": _validate_envelope,
    "data": _validate_data,
    "ack": _validate_ack,
    "nak": _validate_nak,
    "bye": _validate_bye,
}


def new_mid() -> str:
    """A fresh 128-bit message id as 32 lowercase-hex characters."""
    return secrets.token_bytes(16).hex()


def data(mid: str, frm: str, to: str, ttl: int, payload) -> dict:
    return {"type": "data", "mid": mid, "from": frm, "to": to, "ttl": ttl, "payload": payload}


def data_segment(mid: str, frm: str, to: str, ttl: int, i: int, n: int, seg: str) -> dict:
    """One segment of a split application message (protocol.md section 6.1).

    A segment carries ``seg`` and deliberately carries no ``payload``: the two are
    mutually exclusive, so a node that does not reassemble sees a data message with
    no payload and rejects it rather than handing a fragment to the application as
    though it were whole.
    """
    return {
        "type": "data", "mid": mid, "from": frm, "to": to, "ttl": ttl,
        "chunk": {"i": i, "n": n},
        "seg": seg,
    }


def ack(mid: str) -> dict:
    return {"type": "ack", "mid": mid}


def ack_to(mid: str, frm: str, to: str, ttl: int) -> dict:
    """An acknowledgement routed back toward the origin (protocol.md §7)."""
    return {"type": "ack", "mid": mid, "from": frm, "to": to, "ttl": ttl}


def nak(mid: str, frm: str, to: str, hop: str, reason: str, ttl: int) -> dict:
    """A NAK naming the hop that failed and why, routed back toward the origin."""
    return {"type": "nak", "mid": mid, "hop": hop, "reason": reason,
            "from": frm, "to": to, "ttl": ttl}


def bye(reason: str | None = None) -> dict:
    """A graceful session-close control; omit the reason for a plain shutdown."""
    m = {"type": "bye"}
    if reason:
        m["reason"] = reason
    return m


def echo(token: int) -> dict:
    return {"type": "echo", "token": token}


def probe(token: int) -> dict:
    """A liveness probe carrying the sender's send-time timestamp (ms)."""
    return {"type": "probe", "token": token}


def disco(routes: dict) -> dict:
    """A route advertisement: destination label -> path cost in ms."""
    return {"type": "disco", "routes": routes}
