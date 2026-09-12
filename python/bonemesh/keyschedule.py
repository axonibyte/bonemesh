"""BMX key schedule (security.md §5).

A Noise-style symmetric state carrying a transcript hash ``h`` and a chaining key
``ck``. The pinned constants match every other implementation, enforced by the
shared vector (spec/corpus/transcripts/keyschedule.json).
"""

from __future__ import annotations

from bonemesh.crypto import aead_open, aead_seal, hkdf, sha256

PROTOCOL_NAME = "BoneMesh_BMX_v3_X25519MLKEM768_ChaChaPoly_SHA256"


class KeySchedule:
    def __init__(self) -> None:
        self.h = sha256(PROTOCOL_NAME.encode("utf-8"))
        self.ck = self.h
        self.key: bytes | None = None
        self.nonce = 0

    def mix_hash(self, data: bytes) -> None:
        """h = SHA-256(h || data)"""
        self.h = sha256(self.h + data)

    def mix_key(self, ikm: bytes | None) -> None:
        """Derive a fresh key and chaining key, resetting the nonce."""
        okm = hkdf(self.ck, ikm or b"", b"", 64)
        self.ck = okm[:32]
        self.key = okm[32:64]
        self.nonce = 0

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        """Seal with ``h`` as AAD, then absorb the ciphertext."""
        ct = aead_seal(self.key, self._nonce12(), self.h, plaintext)
        self.nonce += 1
        self.mix_hash(ct)
        return ct

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes | None:
        """Open (AAD is the current ``h``), then absorb. None on auth failure."""
        pt = aead_open(self.key, self._nonce12(), self.h, ciphertext)
        if pt is None:
            return None
        self.nonce += 1
        self.mix_hash(ciphertext)
        return pt

    def split(self) -> tuple[bytes, bytes]:
        """The two directional transport keys, ``(i2r, r2i)``."""
        okm = hkdf(self.ck, b"", b"", 64)
        return okm[:32], okm[32:64]

    def _nonce12(self) -> bytes:
        return b"\x00\x00\x00\x00" + self.nonce.to_bytes(8, "little")
