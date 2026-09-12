"""Splitting and reassembly of oversized application payloads (protocol.md section 6.1).

A payload too large for one transport frame is serialized, its UTF-8 bytes cut into
segments of at most MAX_SEGMENT_BYTES on character boundaries, and each segment sent
as a data message sharing one message id, carrying ``chunk {i, n}`` and a top-level
``seg`` string and **no** ``payload``. A payload that fits travels whole, with
``payload`` and no ``seg``.

Segments are text, not Base64: section 0's Base64 rule covers binary fields, a slice
of JSON text is already UTF-8, and a JSON string carries it directly, so a split
message stays readable through the key-log inspector (decisions #3, #5, #25).
Cutting on a byte budget rather than a character count is what keeps the split
identical across the seven implementations, because UTF-8 has no surrogates: a code
point is either wholly inside a segment or wholly outside it. This port therefore
encodes to bytes first and slices those, rather than slicing the str -- a str index
is a code point, which would produce different cuts from every other port.
"""

from __future__ import annotations

import json

from . import message

#: Maximum payload bytes carried by one segment (protocol.md section 0).
MAX_SEGMENT_BYTES = 24000
#: Maximum segments one application message may be split into (section 0).
MAX_CHUNKS = 1024
#: Maximum segment bytes buffered at once, across every in-flight message (section 0).
MAX_REASSEMBLY_BUFFER = 16777216
#: Maximum messages that may be mid-reassembly at once (section 0).
MAX_CONCURRENT_REASSEMBLIES = 256
#: Milliseconds a partially-filled message may sit before being discarded (section 0).
REASSEMBLY_TIMEOUT_MILLIS = 30000


def _char_boundary(src: bytes, start: int, end: int) -> int:
    """Walk a proposed cut back to the nearest character boundary at or before it,
    so a segment never ends mid-character and is itself valid UTF-8."""
    if end >= len(src):
        return end  # the tail is always a boundary
    e = end
    while e > start and src[e] & 0xC0 == 0x80:  # 10xxxxxx is a continuation byte
        e -= 1
    # A UTF-8 character is at most 4 bytes and a segment is 24000, so e cannot reach
    # start from well-formed input; falling back keeps a malformed serializer from
    # producing a zero-length segment and looping forever.
    return e if e > start else end


def split(mid: str, frm: str, to: str, ttl: int, payload) -> list[dict]:
    """Split a payload into one whole data message or a series of segments.

    Raises ``ValueError`` when no conforming destination would reassemble it, so the
    caller is told locally rather than the mesh carrying a message that cannot arrive
    (section 6.1, Bounds).
    """
    src = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(src) <= MAX_SEGMENT_BYTES:
        return [message.data(mid, frm, to, ttl, payload)]
    if len(src) > MAX_REASSEMBLY_BUFFER:
        raise ValueError(
            f"payload of {len(src)} bytes exceeds the reassembly buffer maximum "
            f"of {MAX_REASSEMBLY_BUFFER}"
        )

    segs: list[str] = []
    pos = 0
    while pos < len(src):
        end = _char_boundary(src, pos, min(pos + MAX_SEGMENT_BYTES, len(src)))
        segs.append(src[pos:end].decode("utf-8"))
        pos = end
    if len(segs) > MAX_CHUNKS:
        raise ValueError(f"payload needs {len(segs)} segments, over the maximum of {MAX_CHUNKS}")

    n = len(segs)
    return [message.data_segment(mid, frm, to, ttl, i, n, seg) for i, seg in enumerate(segs)]


class _Partial:
    __slots__ = ("segments", "received", "nbytes", "started")

    def __init__(self, n: int, started: int) -> None:
        self.segments: list[str | None] = [None] * n
        self.received = 0
        self.nbytes = 0
        self.started = started


class Reassembler:
    """Rebuild split payloads at the destination, the counterpart to :func:`split`.

    Every section 0 bound is enforced **before** any allocation keyed on a number the
    peer chose. That ordering is the point: the Java reference sized its buffer on
    the peer's ``n`` and validated afterwards, so one frame claiming two billion
    segments exhausted the heap -- defect D7 reintroduced by the feature meant to fix
    it.

    Three bounds, none redundant. The byte budget caps one large message; the
    in-flight count caps a flood of distinct ids each carrying an *empty* segment,
    which costs nothing against a byte budget and still costs memory; the timeout
    stops an abandoned message pinning memory for the session's life.
    """

    #: sentinel distinguishing "nothing to deliver" from "the payload is None",
    #: which a bare None return could not
    INCOMPLETE = object()

    def __init__(self) -> None:
        # dicts keep insertion order, which is what lets the sweep stop early
        self._partials: dict[str, _Partial] = {}
        self._buffered = 0

    def offer(self, msg: dict, now_millis: int):
        """Feed one inbound data message.

        Returns the payload when a message completes, else :data:`INCOMPLETE`.
        ``now_millis`` is passed in rather than read so the timeout is testable
        without sleeping.
        """
        self._sweep(now_millis)

        has_chunk = "chunk" in msg
        chunk = msg.get("chunk")
        if has_chunk and not isinstance(chunk, dict):
            return self.INCOMPLETE  # chunk is present but not an object
        n = 1 if not has_chunk else (chunk.get("n") if message._is_int(chunk.get("n")) else None)
        if has_chunk and n is None:
            return self.INCOMPLETE

        if not has_chunk or n == 1:
            # A whole message carries payload and no seg. One claiming n == 1 while
            # carrying seg instead is malformed, not a one-segment split -- and so is
            # one carrying both.
            if "seg" in msg:
                return self.INCOMPLETE
            return msg["payload"] if "payload" in msg else self.INCOMPLETE

        # Bounds first, allocation second.
        i = chunk.get("i") if message._is_int(chunk.get("i")) else None
        if i is None or n < 1 or n > MAX_CHUNKS or i < 0 or i >= n:
            return self.INCOMPLETE
        seg = msg.get("seg")
        if not isinstance(seg, str):
            return self.INCOMPLETE  # a segment without its slice
        mid = msg.get("mid")
        if not isinstance(mid, str):
            return self.INCOMPLETE

        partial = self._partials.get(mid)
        if partial is None:
            if len(self._partials) >= MAX_CONCURRENT_REASSEMBLIES:
                return self.INCOMPLETE
            partial = _Partial(n, now_millis)
            self._partials[mid] = partial
        elif len(partial.segments) != n:
            self._discard(mid)  # the peer changed n mid-message
            return self.INCOMPLETE

        if partial.segments[i] is None:
            size = len(seg.encode("utf-8"))
            if self._buffered + size > MAX_REASSEMBLY_BUFFER:
                self._discard(mid)
                return self.INCOMPLETE
            partial.segments[i] = seg
            partial.nbytes += size
            partial.received += 1
            self._buffered += size
        if partial.received != n:
            return self.INCOMPLETE

        joined = "".join(partial.segments)  # type: ignore[arg-type]
        self._discard(mid)
        try:
            return json.loads(joined)
        except ValueError:
            return self.INCOMPLETE  # the segments did not rebuild valid JSON

    def in_flight(self) -> int:
        """Messages currently mid-reassembly.

        Exposed for the tests that assert the bounds release memory rather than
        merely refusing to add to it -- a reassembler that rejects a segment but
        keeps its partial forever is still a leak, and the refusal alone cannot show
        that.
        """
        return len(self._partials)

    def buffered(self) -> int:
        """Segment bytes held across every in-flight message."""
        return self._buffered

    def _discard(self, mid: str) -> None:
        partial = self._partials.pop(mid, None)
        if partial is not None:
            self._buffered -= partial.nbytes

    def _sweep(self, now_millis: int) -> None:
        for mid in list(self._partials):
            partial = self._partials[mid]
            if now_millis - partial.started < REASSEMBLY_TIMEOUT_MILLIS:
                break  # insertion-ordered: the rest are younger
            self._buffered -= partial.nbytes
            del self._partials[mid]
