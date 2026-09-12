"""BoneMesh restricted-JCS certificate canonicalization (security.md §11.1).

The exact byte string the mesh root signs. Byte-for-byte identical to the Java,
Go, Rust, JS, PHP and Elixir canonicalizers over the shared corpus
(spec/corpus/canon.json).

The spec orders members by ascending UTF-16 code unit, noting that for the ASCII
member names a certificate actually carries (`exp`, `idk`, `label`, `mesh`,
`nbf`, `v`) this is plain byte order. Python's ``sorted`` orders by code point,
which agrees with both for everything in the BMP below U+E000 and so agrees for
every name the profile permits -- the same position the Go and Rust ports are in,
since UTF-8 byte order is code-point order.
"""

from __future__ import annotations

_SHORT = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}


def canonicalize(cert: dict) -> bytes:
    """Returns the UTF-8 bytes the root signature covers."""
    filtered = {k: v for k, v in cert.items() if k != "sig"}
    return _encode_object(filtered).encode("utf-8")


def _encode_object(obj: dict) -> str:
    parts = []
    for key in sorted(obj.keys()):
        parts.append(_encode_string(key) + ":" + _encode_value(obj[key]))
    return "{" + ",".join(parts) + "}"


def _encode_value(v) -> str:
    # bool before int: in Python bool IS an int, and the profile forbids booleans.
    if isinstance(v, bool):
        raise ValueError("canon: value type bool not permitted in a certificate")
    if isinstance(v, str):
        return _encode_string(v)
    if isinstance(v, int):
        if v < 0:
            raise ValueError(f"canon: negative integer {v}")
        return str(v)
    if isinstance(v, dict):
        return _encode_object(v)
    if isinstance(v, float):
        raise ValueError(f"canon: {v} is not an integer")
    kind = "array" if isinstance(v, (list, tuple)) else type(v).__name__
    raise ValueError(f"canon: value type {kind} not permitted in a certificate")


def _encode_string(s: str) -> str:
    out = ['"']
    for ch in s:
        c = ord(ch)
        if c == 0x22:
            out.append('\\"')
        elif c == 0x5C:
            out.append("\\\\")
        elif c in _SHORT:
            out.append(_SHORT[c])
        elif c < 0x20:
            out.append("\\u%04x" % c)
        else:
            # Non-ASCII is emitted as raw UTF-8, never \u-escaped.
            out.append(ch)
    out.append('"')
    return "".join(out)
