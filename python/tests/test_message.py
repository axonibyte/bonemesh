"""Message schema validation (protocol.md §4) and inner builders.

Cases mirror the shared corpus (spec/corpus/messages.json); that corpus is checked
case-by-case by interop/check-messages-python.sh.
"""

import pytest

from bonemesh import message

GOOD_MID = "0123456789abcdef0123456789abcdef"


def test_valid_frames_of_every_schema():
    assert message.validate("bmx1", {"t": "bmx1", "v": 3, "mesh": "m",
                                     "e": "AAAA", "k": "AAAA", "n": "AAAA"}) is None
    assert message.validate("envelope", {"seq": 0, "ct": "AAAA"}) is None
    assert message.validate("data", {"type": "data", "mid": GOOD_MID, "to": "b",
                                     "from": "a", "ttl": 16, "payload": {}}) is None
    assert message.validate("ack", {"type": "ack", "mid": GOOD_MID}) is None
    assert message.validate("nak", {"type": "nak", "mid": GOOD_MID, "hop": "r",
                                    "reason": "ttl", "to": "a", "from": "r",
                                    "ttl": 16}) is None
    assert message.validate("bye", {"type": "bye"}) is None


@pytest.mark.parametrize("schema,frame,want", [
    pytest.param("bmx1", {"t": "nope", "v": 3, "mesh": "m", "e": "A", "k": "A", "n": "A"},
                 "type", id="bmx1-type"),
    pytest.param("bmx1", {"t": "bmx1", "v": 2, "mesh": "m", "e": "AAAA", "k": "AAAA",
                          "n": "AAAA"}, "version", id="bmx1-version"),
    pytest.param("bmx1", {"t": "bmx1", "v": 3, "mesh": "", "e": "AAAA", "k": "AAAA",
                          "n": "AAAA"}, "empty-mesh", id="bmx1-empty-mesh"),
    pytest.param("bmx1", {"t": "bmx1", "v": 3, "mesh": "m", "k": "AAAA", "n": "AAAA"},
                 "missing-field", id="bmx1-missing"),
    pytest.param("bmx1", {"t": "bmx1", "v": 3, "mesh": "m", "e": "@@@@", "k": "AAAA",
                          "n": "AAAA"}, "not-base64", id="bmx1-not-base64"),
    pytest.param("envelope", {"seq": -1, "ct": "AAAA"}, "seq-range", id="envelope-seq"),
    pytest.param("envelope", {"ct": "AAAA"}, "missing-field", id="envelope-no-seq"),
    pytest.param("envelope", {"seq": 0, "ct": "@@@@"}, "not-base64", id="envelope-ct"),
    pytest.param("data", {"type": "data", "mid": "short", "to": "b", "from": "a",
                          "ttl": 16, "payload": {}}, "mid-format", id="data-mid"),
    pytest.param("data", {"type": "data", "mid": GOOD_MID, "to": "b", "from": "a",
                          "ttl": 0, "payload": {}}, "ttl-range", id="data-ttl-0"),
    pytest.param("data", {"type": "data", "mid": GOOD_MID, "to": "b", "from": "a",
                          "ttl": 256, "payload": {}}, "ttl-range", id="data-ttl-256"),
    pytest.param("data", {"type": "data", "mid": GOOD_MID, "to": "b", "from": "a",
                          "ttl": 16}, "missing-field", id="data-no-payload"),
])
def test_rejection_reasons(schema, frame, want):
    assert message.validate(schema, frame) == want


def test_mid_must_be_32_lowercase_hex():
    for bad in ["", "x" * 32, GOOD_MID.upper(), GOOD_MID[:31], GOOD_MID + "0", 123, None]:
        assert message.validate("ack", {"type": "ack", "mid": bad}) == "mid-format"


def test_base64_validation_is_stricter_than_the_decoder():
    # Python's b64decode is lenient about length; "@@@@" and "AAA" must both be
    # rejected, which is what the corpus case envelope-ct-not-base64 depends on.
    for bad in ["@@@@", "AAA", "A===", "AA=A", "AA AA"]:
        assert message.validate("envelope", {"seq": 0, "ct": bad}) == "not-base64"
    assert message.validate("envelope", {"seq": 0, "ct": "AA=="}) is None


def test_an_unknown_nak_reason_is_accepted_for_forward_compatibility():
    # Validators check structure, not the semantic value of `reason`, so a future
    # reason is not a wire break (protocol.md §8).
    assert message.validate("nak", {"type": "nak", "mid": GOOD_MID, "hop": "r",
                                    "reason": "something-new-in-3.3", "to": "a",
                                    "from": "r", "ttl": 16}) is None


def test_booleans_are_not_accepted_where_integers_belong():
    # bool is an int in Python: a naive isinstance check would let `true` through
    # as ttl 1 or seq 1.
    assert message.validate("envelope", {"seq": True, "ct": "AAAA"}) == "missing-field"
    # "missing-field", not "ttl-range": the integer guard fires before the range
    # check, which is what the JS/Go/Rust validators do too.
    assert message.validate("data", {"type": "data", "mid": GOOD_MID, "to": "b",
                                     "from": "a", "ttl": True, "payload": {}}) == "missing-field"
    assert message.validate("bmx1", {"t": "bmx1", "v": True, "mesh": "m", "e": "AAAA",
                                     "k": "AAAA", "n": "AAAA"}) == "version"


def test_unknown_schema_and_non_dict_frames():
    assert message.validate("nosuch", {}) == "unknown-schema"
    assert message.validate("data", "not a dict") == "type"


def test_new_mid_is_32_lowercase_hex_and_fresh():
    mids = {message.new_mid() for _ in range(50)}
    assert len(mids) == 50
    for mid in mids:
        assert message.validate("ack", {"type": "ack", "mid": mid}) is None


def test_builders_produce_frames_their_own_validator_accepts():
    assert message.validate("data", message.data(GOOD_MID, "a", "b", 16, {"x": 1})) is None
    assert message.validate("ack", message.ack(GOOD_MID)) is None
    assert message.validate("ack", message.ack_to(GOOD_MID, "r", "a", 16)) is None
    assert message.validate("nak", message.nak(GOOD_MID, "r", "a", "r", "ttl", 16)) is None
    assert message.validate("bye", message.bye()) is None
    assert message.validate("bye", message.bye("idle")) is None


def test_bye_omits_an_empty_reason_rather_than_sending_it():
    assert message.bye() == {"type": "bye"}
    assert message.bye("") == {"type": "bye"}
    assert message.bye(None) == {"type": "bye"}
    assert message.bye("shutdown") == {"type": "bye", "reason": "shutdown"}


def test_default_ttl_is_the_pinned_value():
    assert message.DEFAULT_TTL == 16


def test_disco_encodes_an_empty_route_map_as_an_object():
    # `{}` not `[]`: an empty map serialized as an array breaks the other
    # implementations' parsers (docs/architecture.md §6).
    import json
    assert json.dumps(message.disco({})["routes"]) == "{}"
