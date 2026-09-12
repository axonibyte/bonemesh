"""Restricted-JCS certificate canonicalization (security.md §11.1).

The vectors here mirror the shared corpus (spec/corpus/canon.json); that corpus is
checked byte-for-byte by interop/check-canon-python.sh, which runs where the whole
repo is present. A reaper tenant syncs only python/, so it cannot read spec/.
"""

import pytest

from bonemesh.canon import canonicalize


def test_basic_sorted_keys():
    cert = {"v": 3, "mesh": "acme-prod", "label": "alpha", "idk": "YWJj",
            "nbf": 1788500000, "exp": 1790000000}
    assert canonicalize(cert) == (
        b'{"exp":1790000000,"idk":"YWJj","label":"alpha","mesh":"acme-prod",'
        b'"nbf":1788500000,"v":3}'
    )


def test_sig_field_is_stripped():
    cert = {"v": 3, "mesh": "m", "label": "alpha", "idk": "AA==", "nbf": 0, "exp": 1,
            "sig": "IGNORED"}
    assert canonicalize(cert) == b'{"exp":1,"idk":"AA==","label":"alpha","mesh":"m","nbf":0,"v":3}'


def test_non_ascii_emitted_raw_utf8():
    cert = {"v": 3, "mesh": "m", "label": "café", "idk": "AA==", "nbf": 0, "exp": 1}
    out = canonicalize(cert)
    assert out == '{"exp":1,"idk":"AA==","label":"café","mesh":"m","nbf":0,"v":3}'.encode("utf-8")
    assert b"\\u" not in out  # never \u-escaped


def test_string_escaping_quote_backslash():
    cert = {"v": 3, "mesh": "m", "label": 'a"b\\c', "idk": "AA==", "nbf": 0, "exp": 1}
    assert canonicalize(cert) == b'{"exp":1,"idk":"AA==","label":"a\\"b\\\\c","mesh":"m","nbf":0,"v":3}'


def test_control_characters_use_short_forms_then_hex():
    # Raw control characters cannot appear in JSON source, so the corpus notes
    # this case is covered by an in-code vector in each implementation instead.
    assert canonicalize({"a": "\b\t\n\f\r"}) == b'{"a":"\\b\\t\\n\\f\\r"}'
    assert canonicalize({"a": "\x00\x1f"}) == b'{"a":"\\u0000\\u001f"}'


def test_nested_objects_are_permitted_and_sorted():
    assert canonicalize({"b": {"z": 1, "a": 2}, "a": 1}) == b'{"a":1,"b":{"a":2,"z":1}}'


@pytest.mark.parametrize("bad", [
    pytest.param({"a": []}, id="array"),
    pytest.param({"a": 1.5}, id="float"),
    pytest.param({"a": -1}, id="negative"),
    pytest.param({"a": True}, id="bool"),
    pytest.param({"a": None}, id="null"),
])
def test_rejects_value_types_outside_the_profile(bad):
    # bool is an int in Python, so the bool case is the one a naive port gets
    # wrong: it would emit `1` and silently produce different signed bytes.
    with pytest.raises(ValueError):
        canonicalize(bad)
