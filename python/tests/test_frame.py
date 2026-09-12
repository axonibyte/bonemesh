"""Frame classification (protocol.md §2).

Verdicts mirror the shared corpus (spec/corpus/framing.json); that corpus is
checked case-by-case by interop/check-framing-python.sh.
"""

import pytest

from bonemesh.frame import HANDSHAKE_CAP, TRANSPORT_CAP, classify, encode


def c(raw: bytes, cap: int = TRANSPORT_CAP):
    return classify(raw, cap)


def test_accepts_a_well_formed_object():
    obj, reason = c(b'{"a":1}\n')
    assert reason is None and obj == {"a": 1}


@pytest.mark.parametrize("raw,want", [
    pytest.param(b'{"a":1}', "no-newline", id="no-newline"),
    pytest.param(b"\n", "empty", id="empty"),
    pytest.param(b"not json\n", "invalid-json", id="invalid-json"),
    pytest.param(b"[1,2]\n", "not-an-object", id="not-an-object"),
    pytest.param(b'{"a":1} X\n', "trailing-data", id="trailing-data"),
    pytest.param(b'{"a":"\xff"}\n', "invalid-utf8", id="invalid-utf8"),
])
def test_rejection_verdicts(raw, want):
    obj, reason = c(raw)
    assert obj is None and reason == want


@pytest.mark.parametrize("raw", [
    pytest.param(b"{a:1}\n", id="unquoted-key"),
    pytest.param(b"{'a':1}\n", id="single-quotes"),
    pytest.param(b'{"a":1,}\n', id="trailing-comma"),
    pytest.param(b'{"a":01}\n', id="leading-zero"),
    pytest.param(b'{"a":NaN}\n', id="nan"),
])
def test_strict_rfc8259_rejects_lenient_json(raw):
    # Python's json accepts NaN/Infinity by default, so the `nan` case is the one
    # this port had to actively disable (frame._reject_constant). Without that,
    # Python would accept a frame the other six reject -- a wire divergence.
    obj, reason = c(raw)
    assert obj is None and reason == "invalid-json"


def test_trailing_data_stays_distinct_from_invalid_json():
    # Both are malformed, but the corpus pins two different verdicts, so a
    # classifier that collapses them disagrees with every other implementation.
    assert c(b'{"a":1} {"b":2}\n')[1] == "trailing-data"
    assert c(b'{"a":1\n')[1] == "invalid-json"


def test_whitespace_around_the_value_is_not_trailing_data():
    obj, reason = c(b'  {"a":1}  \n')
    assert reason is None and obj == {"a": 1}


@pytest.mark.parametrize("cap", [HANDSHAKE_CAP, TRANSPORT_CAP])
def test_at_the_cap_accepts_and_one_over_rejects(cap):
    filler = b"a" * (cap - len(b'{"p":""}') - 1)
    at_cap = b'{"p":"' + filler + b'"}\n'
    assert len(at_cap) == cap
    assert c(at_cap, cap)[1] is None
    over = b'{"p":"' + filler + b'a"}\n'
    assert len(over) == cap + 1
    assert c(over, cap)[1] == "oversize"


def test_handshake_and_transport_caps_are_the_pinned_values():
    assert HANDSHAKE_CAP == 32768
    assert TRANSPORT_CAP == 65536


def test_encode_emits_compact_json_with_one_trailing_newline():
    out = encode({"b": 1, "a": "x"})
    assert out.endswith(b"\n") and out.count(b"\n") == 1
    assert b" " not in out  # compact separators
    assert classify(out, TRANSPORT_CAP)[0] == {"b": 1, "a": "x"}


def test_encode_round_trips_non_ascii_as_raw_utf8():
    out = encode({"label": "café"})
    assert "café".encode("utf-8") in out
    assert classify(out, TRANSPORT_CAP)[0] == {"label": "café"}
