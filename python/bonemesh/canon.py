"""BoneMesh restricted-JCS certificate canonicalization (security.md §11.1).

The exact byte string the mesh root signs. Byte-for-byte identical to the Java,
Go, Rust, JS, PHP and Elixir canonicalizers over the shared corpus
(spec/corpus/canon.json).

The spec orders members by ascending UTF-16 code unit (security.md section 11.1),
and this port now does too. It used to use Python's plain ``sorted``, which orders
by code point, on the argument that the two agree for every member name the
certificate profile permits -- which is true, since the profile allows only
``exp``, ``idk``, ``label``, ``mesh``, ``nbf`` and ``v``.

That argument was fine as far as it went and the claim attached to it was not: the
docstring said Go and Rust were in the same position. They are not. ``go/canon``
sorts with ``lessUTF16`` and ``rust/src/canon.rs`` with ``utf16(a).cmp(...)``, as
do Java (natively UTF-16), JS (natively UTF-16), PHP (``strcmp`` over a UTF-16
transcode) and Elixir (``sort_by(&utf16/1)``). Six of seven implemented the stated
rule and this one implemented something else that happened to agree on the inputs
anyone would feed it.

The two orders genuinely differ: a character above U+FFFF encodes as a surrogate
pair starting at 0xD83D..0xDBFF, which sorts BEFORE U+E000..U+FFFF by code unit and
AFTER by code point. Unobservable for a conforming certificate, and the sort of
thing that stops being unobservable the moment the profile grows a field.
"""

from __future__ import annotations

_SHORT = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}


def canonicalize(cert: dict) -> bytes:
    """Returns the UTF-8 bytes the root signature covers."""
    filtered = {k: v for k, v in cert.items() if k != "sig"}
    return _encode_object(filtered).encode("utf-8")


def _utf16_units(s: str) -> bytes:
    """The key's UTF-16 code units, big-endian, for ordering.

    Comparing UTF-16BE bytes lexicographically is comparing 16-bit code units
    numerically, which is what security.md section 11.1 asks for.
    """
    return s.encode("utf-16-be")


def _encode_object(obj: dict) -> str:
    parts = []
    for key in sorted(obj.keys(), key=_utf16_units):
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
