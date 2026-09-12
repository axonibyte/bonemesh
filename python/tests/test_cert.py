"""Membership certificates (security.md §3)."""

import base64
import time

from bonemesh import cert as certmod
from bonemesh import crypto

MESH = "acme-prod"


def test_build_shapes_the_certificate_and_base64s_the_identity_key():
    idk = b"\x01\x02\x03"
    c = certmod.build(MESH, "alpha", idk, 100, 200)
    assert c == {"v": 3, "mesh": MESH, "label": "alpha",
                 "idk": base64.b64encode(idk).decode(), "nbf": 100, "exp": 200}
    assert certmod.identity_key(c) == idk


def test_a_signed_certificate_verifies(root):
    root_pub, root_priv = root
    now = int(time.time())
    pub, _ = crypto.mldsa65_generate()
    c = certmod.sign(certmod.build(MESH, "alpha", pub, now - 10, now + 10), root_priv)
    assert certmod.verify(c, root_pub, MESH, now) is None


def test_sign_does_not_sign_over_a_previous_signature(root):
    root_pub, root_priv = root
    now = int(time.time())
    pub, _ = crypto.mldsa65_generate()
    once = certmod.sign(certmod.build(MESH, "alpha", pub, now - 10, now + 10), root_priv)
    twice = certmod.sign(once, root_priv)
    # Re-signing must strip the old sig, or the pre-image would differ and the
    # result would not verify.
    assert certmod.verify(twice, root_pub, MESH, now) is None


def test_mesh_mismatch_is_rejected(root, issue):
    root_pub, _ = root
    cfg = issue("alpha")
    assert certmod.verify(cfg.cert, root_pub, "other-mesh", int(time.time())) == "mesh mismatch"


def test_time_window_is_enforced_at_both_ends(root):
    root_pub, root_priv = root
    pub, _ = crypto.mldsa65_generate()
    c = certmod.sign(certmod.build(MESH, "alpha", pub, 1000, 2000), root_priv)
    assert certmod.verify(c, root_pub, MESH, 999) == "certificate not yet valid"
    assert certmod.verify(c, root_pub, MESH, 1000) is None   # boundary: inclusive
    assert certmod.verify(c, root_pub, MESH, 2000) is None   # boundary: inclusive
    assert certmod.verify(c, root_pub, MESH, 2001) == "certificate expired"


def test_an_unsigned_certificate_is_rejected(root):
    root_pub, _ = root
    pub, _ = crypto.mldsa65_generate()
    c = certmod.build(MESH, "alpha", pub, 0, 1 << 40)
    assert certmod.verify(c, root_pub, MESH, 100) == "certificate is unsigned"


def test_a_non_base64_signature_is_rejected(root):
    root_pub, _ = root
    pub, _ = crypto.mldsa65_generate()
    c = certmod.build(MESH, "alpha", pub, 0, 1 << 40)
    c["sig"] = "@@@not base64@@@"
    assert certmod.verify(c, root_pub, MESH, 100) == "signature is not base64"


def test_a_foreign_root_does_not_verify(root, issue):
    cfg = issue("alpha")
    foreign_pub, _ = crypto.mldsa87_generate()
    assert certmod.verify(cfg.cert, foreign_pub, MESH, int(time.time())) == (
        "root signature does not verify"
    )


def test_tampering_with_any_signed_field_invalidates_it(root, issue):
    root_pub, _ = root
    now = int(time.time())
    for field, value in [("label", "impostor"), ("exp", now + 99999), ("idk", "AAAA")]:
        cfg = issue("alpha")
        cfg.cert[field] = value
        assert certmod.verify(cfg.cert, root_pub, MESH, now) == "root signature does not verify"


def test_a_boolean_timestamp_is_not_read_as_an_integer(root, issue):
    root_pub, _ = root
    cfg = issue("alpha")
    cfg.cert["nbf"] = True
    # bool is an int in Python, so without an explicit guard `true` would read as
    # nbf=1 and pass the window check.
    assert certmod.verify(cfg.cert, root_pub, MESH, int(time.time())) == (
        "certificate not yet valid"
    )
