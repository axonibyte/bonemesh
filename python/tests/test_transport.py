"""Encrypted transport channel (protocol.md §4).

The exact shared vector is verified by interop/check-transport-python.sh. This
suite covers the stateful sequencing and rekey swaps around it.
"""

import pytest

from bonemesh.transport import Transport, TransportError, open_ciphertext, seal_ciphertext


def pair(key_a=b"\x01" * 32, key_b=b"\x02" * 32):
    """An initiator/responder pair with mirrored directional keys."""
    return Transport(key_a, key_b), Transport(key_b, key_a)


def test_seal_open_round_trip_across_a_pair():
    a, b = pair()
    carrier = a.seal({"type": "data", "line": "hello"})
    assert carrier["seq"] == 0
    assert b.open(carrier) == {"type": "data", "line": "hello"}


def test_sequence_numbers_advance_independently_per_direction():
    a, b = pair()
    for expected in range(3):
        assert a.seal({"n": expected})["seq"] == expected
    assert a.send_seq == 3 and a.receive_seq == 0
    assert b.seal({"n": 0})["seq"] == 0


def test_nonce_layout_is_four_zero_bytes_then_little_endian_seq():
    # The vector pins seq 7; this asserts the layout itself, so a big-endian or
    # wrongly-offset nonce fails here and not only against the corpus.
    key = b"\x03" * 32
    from bonemesh.crypto import aead_seal
    assert seal_ciphertext(key, 7, b"x") == aead_seal(
        key, b"\x00\x00\x00\x00" + (7).to_bytes(8, "little"), None, b"x"
    )


def test_open_enforces_strict_in_order_delivery():
    a, b = pair()
    first, second = a.seal({"n": 0}), a.seal({"n": 1})
    with pytest.raises(TransportError, match="out-of-order"):
        b.open(second)
    assert b.open(first) == {"n": 0}
    assert b.open(second) == {"n": 1}


def test_open_rejects_a_replay():
    a, b = pair()
    carrier = a.seal({"n": 0})
    assert b.open(carrier) == {"n": 0}
    with pytest.raises(TransportError, match="out-of-order"):
        b.open(carrier)


def test_open_rejects_a_tampered_ciphertext():
    import base64
    a, b = pair()
    carrier = a.seal({"n": 0})
    raw = bytearray(base64.b64decode(carrier["ct"]))
    raw[0] ^= 1
    carrier["ct"] = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(TransportError, match="authentication failed"):
        b.open(carrier)


def test_open_rejects_a_non_base64_ct():
    a, b = pair()
    carrier = a.seal({"n": 0})
    carrier["ct"] = "@@@@"
    with pytest.raises(TransportError):
        b.open(carrier)


def test_swap_send_resets_the_counter_so_the_next_frame_is_seq_zero():
    a, _ = pair()
    a.seal({"n": 0}); a.seal({"n": 1})
    a.swap_send(b"\x09" * 32)
    assert a.seal({"n": 2})["seq"] == 0


def test_swap_receive_resets_the_expected_counter():
    a, b = pair()
    a.seal({"n": 0})
    new_key = b"\x09" * 32
    a.swap_send(new_key)
    b.swap_receive(new_key)
    assert b.open(a.seal({"after": "rekey"})) == {"after": "rekey"}


def test_a_rekey_swap_on_one_side_only_breaks_the_channel():
    # The safe-degrade guarantee: a half-applied swap must fail loudly rather
    # than silently decrypt to garbage.
    a, b = pair()
    a.swap_send(b"\x09" * 32)
    with pytest.raises(TransportError):
        b.open(a.seal({"n": 0}))


def test_open_ciphertext_returns_none_rather_than_raising():
    assert open_ciphertext(b"\x01" * 32, 0, b"too-short") is None
    assert open_ciphertext(b"\x01" * 32, 0, bytes(32)) is None
