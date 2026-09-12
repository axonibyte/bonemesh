"""The BMX handshake (security.md §4), driven in-process.

No sockets: the two halves are stepped by hand so each failure mode is
deterministic. The live version is in test_node.py.
"""

import json
import time

import pytest

from bonemesh import cert as certmod
from bonemesh import crypto
from bonemesh.frame import TRANSPORT_CAP, classify
from bonemesh.handshake import Handshake, HandshakeError
from bonemesh.transport import Transport

MESH = "acme-prod"


def frame(raw: bytes) -> dict:
    obj, reason = classify(raw, TRANSPORT_CAP)
    assert reason is None, reason
    return obj


def run(initiator: Handshake, responder: Handshake):
    m1 = frame(initiator.write_message1())
    m2 = frame(responder.read_message1_write_message2(m1))
    m3 = frame(initiator.read_message2_write_message3(m2))
    responder.read_message3(m3)
    return initiator.session, responder.session


def hs(cfg, now=None):
    return Handshake(cfg.mesh, cfg.root_public, now or int(time.time()), cfg.cert,
                     cfg.id_private)


def test_a_full_handshake_derives_mirrored_keys_and_a_shared_transcript(issue):
    si, sr = run(hs(issue("alpha")), hs(issue("beta")))
    assert si.send_key == sr.receive_key
    assert si.receive_key == sr.send_key
    assert si.h == sr.h
    assert si.peer_cert["label"] == "beta"
    assert sr.peer_cert["label"] == "alpha"


def test_the_derived_keys_carry_real_traffic(issue):
    si, sr = run(hs(issue("alpha")), hs(issue("beta")))
    a = Transport(si.send_key, si.receive_key)
    b = Transport(sr.send_key, sr.receive_key)
    assert b.open(a.seal({"hello": "world"})) == {"hello": "world"}
    assert a.open(b.seal({"back": "at you"})) == {"back": "at you"}


def test_bmx1_carries_the_pinned_shape(issue):
    m1 = frame(hs(issue("alpha")).write_message1())
    assert m1["t"] == "bmx1" and m1["v"] == 3 and m1["mesh"] == MESH
    assert set(m1) == {"t", "v", "mesh", "e", "k", "n"}


def test_bmx2_and_bmx3_carry_a_single_auth_field(issue):
    # The shipped wire uses one sealed `auth` member rather than separate `cert`
    # and `sig` fields, which is what the other six implementations send.
    i, r = hs(issue("alpha")), hs(issue("beta"))
    m1 = frame(i.write_message1())
    m2 = frame(r.read_message1_write_message2(m1))
    assert set(m2) == {"t", "e", "ct", "auth"} and m2["t"] == "bmx2"
    m3 = frame(i.read_message2_write_message3(m2))
    assert set(m3) == {"t", "auth"} and m3["t"] == "bmx3"


def test_a_foreign_mesh_is_rejected_at_msg1(issue):
    i = hs(issue("alpha"))
    r = hs(issue("beta"))
    r.mesh = "other-mesh"
    with pytest.raises(HandshakeError, match="mesh mismatch"):
        r.read_message1_write_message2(frame(i.write_message1()))


def test_an_unsupported_version_is_rejected_at_msg1(issue):
    i, r = hs(issue("alpha")), hs(issue("beta"))
    m1 = frame(i.write_message1())
    m1["v"] = 99
    with pytest.raises(HandshakeError, match="unsupported version"):
        r.read_message1_write_message2(m1)


def test_a_wrong_frame_type_is_rejected_at_msg1(issue):
    i, r = hs(issue("alpha")), hs(issue("beta"))
    m1 = frame(i.write_message1())
    m1["t"] = "bmx3"
    with pytest.raises(HandshakeError, match="expected bmx1"):
        r.read_message1_write_message2(m1)


def test_a_responder_pinning_a_foreign_root_rejects_the_initiator(issue):
    # The initiator's certificate is signed by the real root; a responder that
    # trusts a different root must refuse it. The responder seals its own identity
    # in msg2 before it ever sees the initiator's, so the refusal lands at msg3 --
    # not earlier.
    i = hs(issue("alpha"))
    r = hs(issue("beta"))
    foreign_pub, _ = crypto.mldsa87_generate()
    r.root_public = foreign_pub
    m1 = frame(i.write_message1())
    m2 = frame(r.read_message1_write_message2(m1))
    m3 = frame(i.read_message2_write_message3(m2))
    with pytest.raises(HandshakeError, match="peer certificate invalid"):
        r.read_message3(m3)
    assert r.session is None


def test_an_initiator_pinning_a_foreign_root_rejects_the_responder(issue):
    i = hs(issue("alpha"))
    r = hs(issue("beta"))
    foreign_pub, _ = crypto.mldsa87_generate()
    i.root_public = foreign_pub
    m1 = frame(i.write_message1())
    m2 = frame(r.read_message1_write_message2(m1))
    with pytest.raises(HandshakeError, match="peer certificate invalid"):
        i.read_message2_write_message3(m2)


def test_a_tampered_responder_auth_is_rejected_by_the_initiator(issue):
    i, r = hs(issue("alpha")), hs(issue("beta"))
    m1 = frame(i.write_message1())
    m2 = frame(r.read_message1_write_message2(m1))
    raw = bytearray(__import__("base64").b64decode(m2["auth"]))
    raw[0] ^= 1
    m2["auth"] = __import__("base64").b64encode(bytes(raw)).decode()
    with pytest.raises(HandshakeError, match="authentication failed"):
        i.read_message2_write_message3(m2)


def test_a_tampered_kem_ciphertext_breaks_the_transcript(issue):
    i, r = hs(issue("alpha")), hs(issue("beta"))
    m1 = frame(i.write_message1())
    m2 = frame(r.read_message1_write_message2(m1))
    raw = bytearray(__import__("base64").b64decode(m2["ct"]))
    raw[0] ^= 1
    m2["ct"] = __import__("base64").b64encode(bytes(raw)).decode()
    # Either decapsulation fails outright or the diverged key makes auth fail;
    # both are refusals, and neither may complete.
    with pytest.raises(HandshakeError):
        i.read_message2_write_message3(m2)


def test_an_expired_certificate_is_rejected(issue):
    i = hs(issue("alpha", nbf_delta=-5000, exp_delta=-1000))
    r = hs(issue("beta"))
    m1 = frame(i.write_message1())
    m2 = frame(r.read_message1_write_message2(m1))
    m3 = frame(i.read_message2_write_message3(m2))
    with pytest.raises(HandshakeError, match="certificate expired"):
        r.read_message3(m3)


def test_a_not_yet_valid_certificate_is_rejected(issue):
    i = hs(issue("alpha", nbf_delta=5000, exp_delta=9000))
    r = hs(issue("beta"))
    m1 = frame(i.write_message1())
    m2 = frame(r.read_message1_write_message2(m1))
    m3 = frame(i.read_message2_write_message3(m2))
    with pytest.raises(HandshakeError, match="not yet valid"):
        r.read_message3(m3)


def test_a_peer_whose_transcript_signature_is_wrong_is_rejected(issue, monkeypatch):
    # A valid certificate whose holder cannot sign the LIVE transcript must be
    # refused: that binding is what stops a captured certificate being replayed.
    # The responder is made to sign the wrong bytes while everything else stays
    # correct, so only the transcript binding is under test.
    real_sign = crypto.mldsa65_sign
    i, r = hs(issue("alpha")), hs(issue("beta"))
    m1 = frame(i.write_message1())
    monkeypatch.setattr("bonemesh.handshake.c.mldsa65_sign",
                        lambda priv, msg: real_sign(priv, b"not the transcript"))
    m2 = frame(r.read_message1_write_message2(m1))
    monkeypatch.undo()
    with pytest.raises(HandshakeError, match="transcript signature does not verify"):
        i.read_message2_write_message3(m2)
    assert i.session is None
