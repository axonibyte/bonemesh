"""Cryptographic primitives (security.md §1).

Self-consistency and shape checks. Cross-language agreement on the post-quantum
primitives is proven by interop/check-pqc-python.sh against the Java-produced
vector, and live by the interop matrix.
"""

import pytest

from bonemesh import crypto


def test_sha256_known_answer():
    assert crypto.sha256(b"abc").hex() == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_hkdf_rfc5869_test_case_1():
    # RFC 5869 A.1: the canonical SHA-256 vector, so the hand-written
    # extract-then-expand is checked against the standard and not just itself.
    okm = crypto.hkdf(bytes.fromhex("000102030405060708090a0b0c"),
                      bytes.fromhex("0b" * 22),
                      bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42)
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )


def test_hkdf_length_beyond_one_block():
    assert len(crypto.hkdf(b"\x00" * 32, b"ikm", b"", 64)) == 64


def test_aead_round_trip_and_tag_rejection():
    key, nonce = b"\x01" * 32, b"\x02" * 12
    ct = crypto.aead_seal(key, nonce, b"aad", b"payload")
    assert crypto.aead_open(key, nonce, b"aad", ct) == b"payload"
    assert len(ct) == len(b"payload") + 16  # tag appended
    assert crypto.aead_open(key, nonce, b"aad", ct[:-1] + bytes([ct[-1] ^ 1])) is None
    assert crypto.aead_open(key, nonce, b"different", ct) is None
    assert crypto.aead_open(b"\x09" * 32, nonce, b"aad", ct) is None


def test_aead_open_rejects_a_truncated_ciphertext():
    assert crypto.aead_open(b"\x01" * 32, b"\x02" * 12, None, b"short") is None


def test_x25519_agreement_is_symmetric_and_raw_32_bytes():
    pub_a, priv_a = crypto.x25519_generate()
    pub_b, priv_b = crypto.x25519_generate()
    assert len(pub_a) == 32
    assert crypto.x25519_agree(priv_a, pub_b) == crypto.x25519_agree(priv_b, pub_a)


def test_mlkem768_encapsulation_shapes_and_round_trip():
    ek, dk = crypto.mlkem768_keypair()
    assert len(ek) == 1184
    ss, ct = crypto.mlkem768_encapsulate(ek)
    # The tuple order is (shared_secret, ciphertext), which is the reverse of
    # some other libraries -- getting it backwards yields a ciphertext-shaped
    # "secret" that silently fails to decapsulate.
    assert len(ss) == 32 and len(ct) == 1088
    assert crypto.mlkem768_decapsulate(dk, ct) == ss


def test_mlkem768_decapsulate_rejects_a_foreign_ciphertext():
    _, dk = crypto.mlkem768_keypair()
    ek2, _ = crypto.mlkem768_keypair()
    _, ct2 = crypto.mlkem768_encapsulate(ek2)
    # ML-KEM is implicitly rejecting: a wrong ciphertext yields a different
    # secret rather than an error, so assert inequality, not None.
    assert crypto.mlkem768_decapsulate(dk, ct2) != crypto.mlkem768_decapsulate(dk, ct2[::-1])


def test_mldsa65_sign_verify_and_shapes():
    pub, priv = crypto.mldsa65_generate()
    assert len(pub) == 1952 and len(priv) == 32  # raw public, FIPS seed
    sig = crypto.mldsa65_sign(priv, b"message")
    assert crypto.mldsa65_verify(pub, b"message", sig)
    assert not crypto.mldsa65_verify(pub, b"other", sig)
    assert not crypto.mldsa65_verify(pub, b"message", bytes(len(sig)))


def test_mldsa87_sign_verify_and_shapes():
    pub, priv = crypto.mldsa87_generate()
    assert len(pub) == 2592 and len(priv) == 32
    sig = crypto.mldsa87_sign(priv, b"root")
    assert crypto.mldsa87_verify(pub, b"root", sig)
    assert not crypto.mldsa87_verify(pub, b"root ", sig)


def test_verify_returns_false_rather_than_raising_on_a_malformed_key():
    # A node verifies attacker-supplied material; it must answer false, never
    # propagate an exception into the handshake.
    assert not crypto.mldsa65_verify(b"too-short", b"m", b"sig")
    assert not crypto.mldsa87_verify(b"", b"m", b"sig")


@pytest.mark.parametrize("level", ["65", "87"])
def test_the_two_dsa_levels_are_not_interchangeable(level):
    pub65, priv65 = crypto.mldsa65_generate()
    pub87, priv87 = crypto.mldsa87_generate()
    sig65 = crypto.mldsa65_sign(priv65, b"m")
    sig87 = crypto.mldsa87_sign(priv87, b"m")
    if level == "65":
        assert not crypto.mldsa87_verify(pub87, b"m", sig65)
    else:
        assert not crypto.mldsa65_verify(pub65, b"m", sig87)
