"""BoneMesh v3 membership certificate (security.md §3).

A mesh-root-signed binding of a label to a node's ML-DSA-65 identity key. The
JSON form is a plain dict; its signed pre-image is the canonicalization of every
field except ``sig``. Base64 fields use the standard alphabet with padding.
"""

from __future__ import annotations

import base64
import binascii

from bonemesh.canon import canonicalize
from bonemesh.crypto import mldsa87_sign, mldsa87_verify


def build(mesh: str, label: str, identity_key: bytes, not_before: int, not_after: int) -> dict:
    """An unsigned certificate. ``identity_key`` is the raw ML-DSA-65 public key."""
    return {
        "v": 3,
        "mesh": mesh,
        "label": label,
        "idk": base64.b64encode(identity_key).decode("ascii"),
        "nbf": not_before,
        "exp": not_after,
    }


def sign(cert: dict, root_private_seed: bytes) -> dict:
    """Returns a copy of ``cert`` carrying the mesh root's ML-DSA-87 signature.

    Used by the test suite and by tooling that issues certificates; a node itself
    only ever verifies.
    """
    signed = {k: v for k, v in cert.items() if k != "sig"}
    signed["sig"] = base64.b64encode(
        mldsa87_sign(root_private_seed, canonicalize(signed))
    ).decode("ascii")
    return signed


def verify(cert: dict, root_public: bytes, expected_mesh: str, now: int) -> str | None:
    """Returns None if valid, else a reason string."""
    if cert.get("mesh") != expected_mesh:
        return "mesh mismatch"
    nbf = cert.get("nbf")
    # bool is an int in Python; a certificate carrying `true` is malformed, not
    # a timestamp of 1.
    if not isinstance(nbf, int) or isinstance(nbf, bool) or now < nbf:
        return "certificate not yet valid"
    exp = cert.get("exp")
    if not isinstance(exp, int) or isinstance(exp, bool) or now > exp:
        return "certificate expired"
    if not isinstance(cert.get("sig"), str):
        return "certificate is unsigned"
    try:
        sig = base64.b64decode(cert["sig"], validate=True)
    except (binascii.Error, ValueError):
        return "signature is not base64"
    try:
        pre_image = canonicalize(cert)
    except ValueError as e:
        return f"canon: {e}"
    if not mldsa87_verify(root_public, pre_image, sig):
        return "root signature does not verify"
    return None


def identity_key(cert: dict) -> bytes:
    """The node's raw ML-DSA-65 public key."""
    return base64.b64decode(cert["idk"])
