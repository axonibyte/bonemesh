"""BMX handshake (security.md §4).

A three-message, mutually authenticated, forward-secret exchange: hybrid
X25519 + ML-KEM-768 forward secrecy through the key schedule, authentication by a
root-signed certificate plus an ML-DSA signature over the live transcript.
Field-for-field identical to every other implementation.

Two places where the shipped wire differs from a literal reading of the spec
prose, and where this port follows the code the other six actually run:

* ``bmx2``/``bmx3`` carry a single ``auth`` field -- the sealed
  ``{"cert": ..., "sig": ...}`` payload -- rather than separate ``cert`` and
  ``sig`` members.
* The transcript absorbs individual field *values* in order, not the raw wire
  bytes of each message.

The ``write_*`` methods return an encoded frame ready for the wire; the ``read_*``
methods take the peer's already-decoded frame dict.
"""

from __future__ import annotations

import base64
import json
import secrets

from bonemesh import cert as certmod
from bonemesh import crypto as c
from bonemesh.frame import encode
from bonemesh.keyschedule import KeySchedule


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s)


class HandshakeError(Exception):
    pass


class Session:
    """The completed handshake's outputs."""

    __slots__ = ("send_key", "receive_key", "peer_cert", "h")

    def __init__(self, send_key: bytes, receive_key: bytes, peer_cert: dict, h: bytes) -> None:
        self.send_key = send_key
        self.receive_key = receive_key
        self.peer_cert = peer_cert
        self.h = h


class Handshake:
    def __init__(self, mesh: str, root_public: bytes, now: int, cert_obj: dict,
                 id_private: bytes) -> None:
        self.mesh = mesh
        self.root_public = root_public
        self.now = now
        self.cert = cert_obj
        self.id_private = id_private
        self.ks = KeySchedule()
        self.ks.mix_hash(mesh.encode("utf-8"))
        self.session: Session | None = None
        self._eph_dh_priv = None
        self._eph_kem_dk = None

    @classmethod
    def initiator(cls, mesh, root_public, now, cert_obj, id_private) -> "Handshake":
        return cls(mesh, root_public, now, cert_obj, id_private)

    @classmethod
    def responder(cls, mesh, root_public, now, cert_obj, id_private) -> "Handshake":
        return cls(mesh, root_public, now, cert_obj, id_private)

    def write_message1(self) -> bytes:
        """Message 1 (initiator)."""
        dh_pub, dh_priv = c.x25519_generate()
        kem_ek, kem_dk = c.mlkem768_keypair()
        n = secrets.token_bytes(32)
        self._eph_dh_priv = dh_priv
        self._eph_kem_dk = kem_dk
        self.ks.mix_hash(dh_pub)
        self.ks.mix_hash(kem_ek)
        self.ks.mix_hash(n)
        return encode({"t": "bmx1", "v": 3, "mesh": self.mesh,
                       "e": _b64(dh_pub), "k": _b64(kem_ek), "n": _b64(n)})

    def read_message1_write_message2(self, m: dict) -> bytes:
        """Message 2 (responder): consume msg1, produce msg2."""
        if m.get("t") != "bmx1":
            raise HandshakeError("expected bmx1")
        if m.get("v") != 3:
            raise HandshakeError("unsupported version")
        if m.get("mesh") != self.mesh:
            raise HandshakeError("mesh mismatch")
        self.ks.mix_hash(_unb64(m["e"]))
        self.ks.mix_hash(_unb64(m["k"]))
        self.ks.mix_hash(_unb64(m["n"]))

        er_pub, er_priv = c.x25519_generate()
        self.ks.mix_hash(er_pub)
        self.ks.mix_key(c.x25519_agree(er_priv, _unb64(m["e"])))

        ss, ct = c.mlkem768_encapsulate(_unb64(m["k"]))
        self.ks.mix_hash(ct)
        self.ks.mix_key(ss)

        auth = self._seal_identity()
        return encode({"t": "bmx2", "e": _b64(er_pub), "ct": _b64(ct), "auth": _b64(auth)})

    def read_message2_write_message3(self, m: dict) -> bytes:
        """Message 3 (initiator): verify the responder, produce msg3."""
        er_pub = _unb64(m["e"])
        ct = _unb64(m["ct"])
        auth = _unb64(m["auth"])

        self.ks.mix_hash(er_pub)
        self.ks.mix_key(c.x25519_agree(self._eph_dh_priv, er_pub))
        self.ks.mix_hash(ct)
        ss_kem = c.mlkem768_decapsulate(self._eph_kem_dk, ct)
        if ss_kem is None:
            raise HandshakeError("decapsulation failed")
        self.ks.mix_key(ss_kem)

        peer_cert = self._open_identity(auth)
        auth_i = self._seal_identity()
        out = encode({"t": "bmx3", "auth": _b64(auth_i)})
        i2r, r2i = self.ks.split()
        self.session = Session(i2r, r2i, peer_cert, self.ks.h)
        return out

    def read_message3(self, m: dict) -> None:
        """Message 3 (responder): verify the initiator, completing the handshake."""
        peer_cert = self._open_identity(_unb64(m["auth"]))
        i2r, r2i = self.ks.split()
        self.session = Session(r2i, i2r, peer_cert, self.ks.h)

    def _seal_identity(self) -> bytes:
        sig = c.mldsa65_sign(self.id_private, self.ks.h)
        payload = json.dumps({"cert": self.cert, "sig": _b64(sig)},
                             separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return self.ks.encrypt_and_hash(payload)

    def _open_identity(self, auth: bytes) -> dict:
        # The signature pre-image is h as it stands immediately BEFORE the
        # decrypt absorbs the ciphertext, so it has to be captured first.
        h_pre = self.ks.h
        pt = self.ks.decrypt_and_hash(auth)
        if pt is None:
            raise HandshakeError("handshake authentication failed")
        try:
            payload = json.loads(pt.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as e:
            raise HandshakeError("bad auth payload") from e
        peer_cert = payload.get("cert")
        if not isinstance(peer_cert, dict):
            raise HandshakeError("bad auth payload")
        reason = certmod.verify(peer_cert, self.root_public, self.mesh, self.now)
        if reason:
            raise HandshakeError(f"peer certificate invalid: {reason}")
        idk = certmod.identity_key(peer_cert)
        if not c.mldsa65_verify(idk, h_pre, _unb64(payload["sig"])):
            raise HandshakeError("peer transcript signature does not verify")
        return peer_cert
