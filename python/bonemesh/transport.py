"""Encrypted transport channel over a completed handshake (protocol.md §4).

Each frame is a sequence-numbered AEAD carrier ``{"seq": n, "ct": ...}`` whose
plaintext is the inner JSON message. The per-direction sequence is the
ChaCha20-Poly1305 nonce; reordered or replayed frames are rejected. Matches the
shared transport-frame vector.
"""

from __future__ import annotations

import base64
import json

from bonemesh.crypto import aead_open, aead_seal


class TransportError(Exception):
    """A carrier arrived out of order or failed authentication."""


class Transport:
    def __init__(self, send_key: bytes, receive_key: bytes) -> None:
        self.send_key = send_key
        self.receive_key = receive_key
        self.send_seq = 0
        self.receive_seq = 0

    def seal(self, inner) -> dict:
        """Seal an inner message into a ``{seq, ct}`` carrier."""
        seq = self.send_seq
        pt = json.dumps(inner, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ct = seal_ciphertext(self.send_key, seq, pt)
        self.send_seq += 1
        return {"seq": seq, "ct": base64.b64encode(ct).decode("ascii")}

    def open(self, carrier: dict):
        """Open a carrier, enforcing in-order delivery. Returns the inner message."""
        seq = carrier.get("seq")
        if seq != self.receive_seq:
            raise TransportError(
                f"out-of-order frame: expected {self.receive_seq}, got {seq}"
            )
        try:
            ct = base64.b64decode(carrier["ct"], validate=True)
        except Exception as e:
            raise TransportError("bad ct") from e
        pt = open_ciphertext(self.receive_key, seq, ct)
        if pt is None:
            raise TransportError("frame authentication failed")
        self.receive_seq += 1
        try:
            return json.loads(pt.decode("utf-8"))
        except ValueError as e:
            raise TransportError("bad inner json") from e

    def swap_send(self, key: bytes) -> None:
        """Install a new outbound key and reset the send counter to 0 (F5).

        Called at the rekey boundary immediately after sealing the last old-key
        frame, so the very next frame uses the new key at seq 0.
        """
        self.send_key = key
        self.send_seq = 0

    def swap_receive(self, key: bytes) -> None:
        """Install a new inbound key and reset the receive counter (F5)."""
        self.receive_key = key
        self.receive_seq = 0


def seal_ciphertext(key: bytes, seq: int, plaintext: bytes) -> bytes:
    """The frame body alone, addressed by sequence number rather than session state.

    This is the form the shared transport-frame vector
    (spec/corpus/transcripts/transport-frame.json) is stated in;
    :meth:`Transport.seal` and :meth:`Transport.open` are the stateful wrappers,
    so the nonce is built in exactly one place.
    """
    return aead_seal(key, _nonce(seq), None, plaintext)


def open_ciphertext(key: bytes, seq: int, ct: bytes) -> bytes | None:
    """Returns the plaintext, or None if authentication fails."""
    return aead_open(key, _nonce(seq), None, ct)


def _nonce(seq: int) -> bytes:
    return b"\x00\x00\x00\x00" + seq.to_bytes(8, "little")
