"""Splitting and reassembly tests (protocol.md section 6.1).

Two groups. The first pins the format: a small payload travels whole, a large one
splits and rebuilds byte-identically, segments are text rather than Base64, and cuts
land on character boundaries even when every character is multi-byte. That last one
matters particularly here, because a Python str index is a code point: a port that
sliced the str instead of its UTF-8 bytes would produce different cuts from every
other implementation while looking correct in isolation.

The second pins the bounds, which is the half that had no coverage anywhere before
3.3.0 and where the defect was. Each asserts that a hostile message is refused AND
that refusing it released whatever it claimed: a reassembler that rejects a segment
but keeps its partial forever is still a leak, and the refusal alone cannot show
that.
"""

import json

import pytest

from bonemesh.chunk import (
    MAX_CHUNKS,
    MAX_CONCURRENT_REASSEMBLIES,
    MAX_REASSEMBLY_BUFFER,
    MAX_SEGMENT_BYTES,
    REASSEMBLY_TIMEOUT_MILLIS,
    Reassembler,
    split,
)
from bonemesh.message import data, data_segment, validate

MID = "0123456789abcdef0123456789abcdef"
INCOMPLETE = Reassembler.INCOMPLETE


def blob(n: int) -> str:
    return "".join(chr(97 + (i % 26)) for i in range(n))


def seg(mid: str, i: int, n: int, s: str) -> dict:
    return data_segment(mid, "a", "b", 16, i, n, s)


# ---- format ----


def test_a_small_payload_travels_whole():
    payload = {"line": "hello"}
    msgs = split(MID, "a", "b", 16, payload)
    assert len(msgs) == 1
    assert "chunk" not in msgs[0], "a whole message must not carry chunk"
    assert "seg" not in msgs[0], "a whole message must not carry seg"
    assert msgs[0]["payload"] == payload


def test_a_large_payload_splits_and_reassembles():
    payload = {"blob": blob(120_000)}
    msgs = split(MID, "a", "b", 16, payload)
    assert len(msgs) > 1, "large payload was not split"
    for i, m in enumerate(msgs):
        assert validate("data", m) is None, f"segment {i} failed the data schema"
        assert "payload" not in m, f"segment {i} carries a payload"
        assert isinstance(m["seg"], str)
        assert len(m["seg"].encode("utf-8")) <= MAX_SEGMENT_BYTES, \
            f"segment {i} is over the pinned maximum"

    r = Reassembler()
    for m in msgs[:-1]:
        assert r.offer(m, 0) is INCOMPLETE, "completed early"
    assert r.offer(msgs[-1], 0) == payload
    assert r.in_flight() == 0, "a completed message stayed buffered"
    assert r.buffered() == 0, "a completed message stayed counted"


def test_segments_are_text_not_base64():
    # decision #25: a segment is a slice of the payload's JSON text, so it stays
    # readable through the key-log inspector. Concatenation must reproduce the
    # serialized payload with no decode step.
    payload = {"blob": blob(60_000)}
    msgs = split(MID, "a", "b", 16, payload)
    joined = "".join(m["seg"] for m in msgs)
    assert joined == json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    assert msgs[0]["seg"].startswith("{"), "the first segment should open the payload JSON"


def test_cuts_land_on_character_boundaries():
    # Every character is 3 UTF-8 bytes, so 24000 divides unevenly and a naive byte cut
    # would split one. Decoding each segment on its own is the oracle: a split
    # character would not decode.
    payload = {"cjk": "日" * 40_000}
    msgs = split(MID, "a", "b", 16, payload)
    assert len(msgs) > 1
    for i, m in enumerate(msgs):
        raw = m["seg"].encode("utf-8")
        assert len(raw) <= MAX_SEGMENT_BYTES, f"segment {i} is over the pinned maximum"
        assert raw.decode("utf-8") == m["seg"], f"segment {i} does not round-trip through UTF-8"
    r = Reassembler()
    got = INCOMPLETE
    for m in msgs:
        got = r.offer(m, 0)
    assert got == payload


def test_out_of_order_segments_still_reassemble():
    payload = {"blob": blob(120_000)}
    msgs = split(MID, "a", "b", 16, payload)
    r = Reassembler()
    got = INCOMPLETE
    for m in reversed(msgs):
        got = r.offer(m, 0)
    assert got == payload


# ---- bounds ----


def test_an_absurd_chunk_count_is_refused_before_allocating():
    # The Java reference sized its buffer on the peer's n before validating it, so one
    # frame claiming two billion segments exhausted the heap. Both oracles matter: the
    # offer is refused, AND nothing was retained, which is what shows no allocation
    # happened.
    r = Reassembler()
    for n in (2**63 - 1, 2_000_000_000, 1_000_000, MAX_CHUNKS + 1):
        assert r.offer(seg(MID, 0, n, "x"), 0) is INCOMPLETE, f"accepted n={n}"
        assert r.in_flight() == 0, f"n={n} was buffered anyway"
        assert r.buffered() == 0, f"n={n} was counted anyway"
    # The boundary itself is legal, so this is a bound and not a blanket ban.
    r.offer(seg(MID, 0, MAX_CHUNKS, "x"), 0)
    assert r.in_flight() == 1, "the maximum legal chunk count was refused"


def test_malformed_chunk_metadata_is_refused():
    r = Reassembler()
    bad = [
        {**seg(MID, 0, 3, "x"), "chunk": "not-an-object"},
        {**seg(MID, 0, 3, "x"), "chunk": None},
        {**seg(MID, 0, 3, "x"), "chunk": [0, 3]},
        {**seg(MID, 0, 3, "x"), "chunk": {"i": "zero", "n": 3}},
        {**seg(MID, 0, 3, "x"), "chunk": {"i": 0}},
        {**seg(MID, 0, 3, "x"), "chunk": {"i": 0.5, "n": 3}},
        {**seg(MID, 0, 3, "x"), "chunk": {"i": True, "n": 3}},
        seg(MID, 3, 3, "x"),
        seg(MID, -1, 3, "x"),
        seg(MID, 0, 0, "x"),
    ]
    for k, m in enumerate(bad):
        assert r.offer(m, 0) is INCOMPLETE, f"case {k}: accepted malformed chunk {m.get('chunk')!r}"
        assert r.in_flight() == 0, f"case {k}: malformed chunk was buffered"


def test_a_segment_without_its_slice_is_refused():
    r = Reassembler()
    m = seg(MID, 0, 3, "x")
    del m["seg"]
    assert r.offer(m, 0) is INCOMPLETE
    assert r.in_flight() == 0


def test_a_whole_message_claiming_to_be_a_segment_is_not_delivered():
    r = Reassembler()
    m = seg(MID, 0, 1, '{"a":1}')
    assert r.offer(m, 0) is INCOMPLETE, "delivered a fragment as a whole payload"
    assert validate("data", m) == "payload-or-seg"


def test_a_message_carrying_both_payload_and_segment_is_not_delivered():
    # Found by mutation in the Rust port, then fixed in all seven: the whole-message
    # path returned the payload whenever one was present, so a message contradicting
    # itself was delivered. The schema rejects it, but the schema is not on the wire
    # path (decision #27), so the reassembler has to refuse it too.
    r = Reassembler()
    both = {**data(MID, "a", "b", 16, {"x": 1}), "seg": "{"}
    assert r.offer(both, 0) is INCOMPLETE, "a self-contradicting message was delivered"
    with_chunk = {**seg(MID, 0, 1, "{"), "payload": {"x": 1}}
    assert r.offer(with_chunk, 0) is INCOMPLETE, "a self-contradicting n==1 message was delivered"


def test_a_non_object_chunk_is_refused_even_with_a_payload():
    # The distinguishing input: a garbage chunk on a message that DOES carry a payload.
    # Java conflated "chunk absent" with "chunk unparseable" and delivered it; nothing
    # tested the case, which is how that survived.
    r = Reassembler()
    for garbage in ("1/3", 7, True, []):
        m = {**data(MID, "a", "b", 16, {"x": 1}), "chunk": garbage}
        assert r.offer(m, 0) is INCOMPLETE, f"delivered a message whose chunk was {garbage!r}"
        assert validate("data", m) is not None, "the schema should reject it too"


def test_a_payload_that_is_none_is_distinguishable_from_nothing_to_deliver():
    # A payload may legitimately be JSON null, which is why offer returns a sentinel
    # rather than None. Without it the node would silently drop null payloads.
    #
    # Deliberately NOT written as `is INCOMPLETE`: that compares the result against
    # the very object under test, so it agreed with itself and kept passing when the
    # sentinel was mutated to None. Mutation found that. The check instead duplicates
    # the distinction -- the two results must differ from each other -- which is only
    # true if the sentinel is something None is not.
    r = Reassembler()
    delivered_null = r.offer(data(MID, "a", "b", 16, None), 0)
    nothing = r.offer({"type": "data", "mid": MID, "to": "b", "from": "a", "ttl": 16}, 0)
    assert delivered_null is None, "a JSON null payload must be delivered as None"
    assert nothing is not None, "nothing-to-deliver must not collide with a null payload"
    assert delivered_null is not nothing


def test_concurrent_reassemblies_are_bounded():
    r = Reassembler()
    for k in range(MAX_CONCURRENT_REASSEMBLIES):
        r.offer(seg(f"{k:032x}", 0, 4, "x"), 0)
    assert r.in_flight() == MAX_CONCURRENT_REASSEMBLIES
    r.offer(seg("f" * 32, 0, 4, "x"), 0)
    assert r.in_flight() == MAX_CONCURRENT_REASSEMBLIES, "the bound was exceeded"


def test_buffered_bytes_are_bounded():
    # The in-flight bound (256) is reached long before 16 MiB of segments can be spread
    # across separate message ids, so the byte budget is only reachable inside one
    # message: 1024 segments of 24000 bytes is 24.5 MB, over the ceiling.
    r = Reassembler()
    full = "y" * MAX_SEGMENT_BYTES
    accepted = 0
    for i in range(MAX_CHUNKS):
        r.offer(seg(MID, i, MAX_CHUNKS, full), 0)
        if r.in_flight() == 0:
            break  # abandoned: the budget refused it
        accepted += 1
        assert r.buffered() <= MAX_REASSEMBLY_BUFFER, "the buffer maximum was exceeded"
    assert accepted == MAX_REASSEMBLY_BUFFER // MAX_SEGMENT_BYTES, \
        "the message should be abandoned on the first segment that would not fit"
    assert r.in_flight() == 0, "the abandoned message was retained"
    assert r.buffered() == 0, "abandoning did not return its bytes"


def test_the_byte_budget_counts_utf8_bytes_not_code_points():
    # A 3-byte character separates the two: 8000 of them are 24000 bytes but only 8000
    # code points, so a port measuring len(str) would under-count the budget by 3x.
    r = Reassembler()
    s = "日" * 8000
    assert len(s.encode("utf-8")) == 24000
    assert len(s) == 8000
    r.offer(seg(MID, 0, MAX_CHUNKS, s), 0)
    assert r.buffered() == 24000, "the budget counted code points, not bytes"


def test_stale_partials_are_swept():
    r = Reassembler()
    r.offer(seg(MID, 0, 3, "x"), 1000)
    assert r.in_flight() == 1
    r.offer(seg(MID, 1, 3, "y"), 1000 + REASSEMBLY_TIMEOUT_MILLIS - 1)
    assert r.in_flight() == 1, "swept too early"
    r.offer(seg("1" * 32, 0, 3, "z"), 1000 + REASSEMBLY_TIMEOUT_MILLIS)
    assert r.in_flight() == 1, "the stale partial was not swept"
    assert r.buffered() == 1, "swept bytes were not returned to the budget"


def test_an_oversized_payload_fails_at_the_origin():
    # section 6.1: an origin whose payload no conforming destination would reassemble
    # is told locally rather than emitting it.
    with pytest.raises(ValueError):
        split(MID, "a", "b", 16, {"blob": blob(MAX_REASSEMBLY_BUFFER + 1)})
