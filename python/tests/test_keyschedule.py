"""BMX key schedule (security.md §5).

The exact shared vector is verified by interop/check-keyschedule-python.sh, which
runs where spec/ is present. This suite proves the schedule is correct against the
SHA-256/HKDF formulae directly, and that an initiator/responder pair stays in
lockstep -- questions the vector alone does not answer.
"""

from bonemesh.crypto import hkdf, sha256
from bonemesh.keyschedule import PROTOCOL_NAME, KeySchedule


def test_protocol_name_is_the_pinned_string():
    assert PROTOCOL_NAME == "BoneMesh_BMX_v3_X25519MLKEM768_ChaChaPoly_SHA256"


def test_initial_state_seeds_both_h_and_ck_from_the_protocol_name():
    s = KeySchedule()
    assert s.h == sha256(PROTOCOL_NAME.encode())
    assert s.ck == s.h
    assert s.key is None and s.nonce == 0


def test_mix_hash_is_sha256_of_the_concatenation():
    s = KeySchedule()
    before = s.h
    s.mix_hash(b"data")
    assert s.h == sha256(before + b"data")


def test_mix_key_splits_a_64_byte_hkdf_and_resets_the_nonce():
    s = KeySchedule()
    salt = s.ck
    s.nonce = 7
    s.mix_key(b"ikm")
    okm = hkdf(salt, b"ikm", b"", 64)
    assert s.ck == okm[:32]
    assert s.key == okm[32:64]
    assert s.nonce == 0


def test_mix_key_order_matters_dh_then_kem():
    a, b = KeySchedule(), KeySchedule()
    a.mix_key(b"dh"); a.mix_key(b"kem")
    b.mix_key(b"kem"); b.mix_key(b"dh")
    assert a.ck != b.ck  # the order is part of the pinned contract


def test_encrypt_and_hash_absorbs_the_ciphertext_and_advances_the_nonce():
    s = KeySchedule()
    s.mix_key(b"ikm")
    h_before, nonce_before = s.h, s.nonce
    ct = s.encrypt_and_hash(b"plaintext")
    assert s.nonce == nonce_before + 1
    assert s.h == sha256(h_before + ct)


def test_decrypt_and_hash_mirrors_encrypt_and_hash():
    a, b = KeySchedule(), KeySchedule()
    a.mix_key(b"ikm"); b.mix_key(b"ikm")
    ct = a.encrypt_and_hash(b"secret")
    assert b.decrypt_and_hash(ct) == b"secret"
    assert a.h == b.h  # transcripts stay in lockstep


def test_decrypt_and_hash_returns_none_on_a_tampered_ciphertext_without_advancing():
    a, b = KeySchedule(), KeySchedule()
    a.mix_key(b"ikm"); b.mix_key(b"ikm")
    ct = bytearray(a.encrypt_and_hash(b"secret"))
    ct[0] ^= 1
    h_before, nonce_before = b.h, b.nonce
    assert b.decrypt_and_hash(bytes(ct)) is None
    assert b.h == h_before and b.nonce == nonce_before


def test_decrypt_and_hash_uses_h_as_aad_so_a_diverged_transcript_fails():
    a, b = KeySchedule(), KeySchedule()
    a.mix_key(b"ikm"); b.mix_key(b"ikm")
    b.mix_hash(b"divergence")
    assert b.decrypt_and_hash(a.encrypt_and_hash(b"secret")) is None


def test_split_derives_two_distinct_32_byte_directional_keys():
    s = KeySchedule()
    s.mix_key(b"ikm")
    i2r, r2i = s.split()
    assert len(i2r) == 32 and len(r2i) == 32 and i2r != r2i
    assert (i2r, r2i) == (hkdf(s.ck, b"", b"", 64)[:32], hkdf(s.ck, b"", b"", 64)[32:64])


def test_a_full_initiator_responder_pair_reaches_identical_transport_keys():
    i, r = KeySchedule(), KeySchedule()
    for s in (i, r):
        s.mix_hash(b"acme-prod")
        s.mix_key(b"shared-dh")
        s.mix_key(b"shared-kem")
    assert i.split() == r.split()
    assert i.h == r.h
