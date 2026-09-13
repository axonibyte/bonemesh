"""Tunable parsing (protocol.md section 0).

These are local knobs, never part of the wire contract, but how a malformed value is
treated is still a behaviour two implementations can disagree about -- and two did.
"""

from bonemesh.tunables import load_tunables


def test_a_tunable_value_is_parsed_strictly(monkeypatch):
    # protocol.md section 0: an optional sign then decimal digits and nothing else.
    # int() accepts digit separators and surrounding whitespace, so int("1_000") is
    # 1000 and int(" 12 ") is 12 -- this port partially parsed an operator's typo
    # rather than ignoring it, and the JS port did the same in the other direction by
    # reading "12abc" as 12. Both now fall back to the default.
    for bad in ("1_000", " 12 ", "12abc", "abc", "1.5", "+12", "0x10", ""):
        monkeypatch.setenv("BONEMESH_PROBE_TIMEOUT_MS", bad)
        assert load_tunables().probe_timeout_ms == 15000, f"{bad!r} was not ignored"

    # ...and a well-formed value is still read, so this is strictness and not a ban.
    monkeypatch.setenv("BONEMESH_PROBE_TIMEOUT_MS", "1200")
    assert load_tunables().probe_timeout_ms == 1200
    monkeypatch.setenv("BONEMESH_PROBE_TIMEOUT_MS", "-1")
    assert load_tunables().probe_timeout_ms == -1
