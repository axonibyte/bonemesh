"""BoneMesh v3 cryptographic primitives (security.md §1).

SHA-256, HKDF-SHA-256, ChaCha20-Poly1305, X25519, ML-KEM-768 and ML-DSA-65/87,
all from ``cryptography`` over OpenSSL 3.5 -- the same primitive set Node gives
the JS port and OTP 28 gives the Elixir one. Public keys, ciphertexts, secrets
and signatures are the raw FIPS/RFC encodings, matching every other
implementation.

Only the node identity's ML-DSA private key is ever serialized, and then as the
32-byte FIPS seed, which never crosses a node boundary -- its representation is
this port's own business (the JS port stores PKCS#8 DER, PHP stores PEM). The
ephemeral X25519 and ML-KEM keys live in memory as key objects for the duration
of a handshake.
"""

from __future__ import annotations

import hashlib
import hmac

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# --- hashing / KDF ---------------------------------------------------------


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hkdf(salt: bytes, ikm: bytes, info: bytes | None, length: int) -> bytes:
    """Full extract-then-expand HKDF-SHA-256 (RFC 5869).

    Written out rather than using ``cryptography``'s HKDF helper because the key
    schedule needs an explicit all-zero-free salt and a 64-byte output in one
    call, and because the two-step form makes the agreement with the shared
    key-schedule vector obvious at a glance.
    """
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    info = info or b""
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


# --- AEAD ------------------------------------------------------------------


def aead_seal(key: bytes, nonce: bytes, aad: bytes | None, plaintext: bytes) -> bytes:
    """ChaCha20-Poly1305 with the 16-byte tag appended to the ciphertext."""
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad or None)


def aead_open(key: bytes, nonce: bytes, aad: bytes | None, ct: bytes) -> bytes | None:
    """Returns the plaintext, or None on tag failure."""
    if len(ct) < 16:
        return None
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ct, aad or None)
    except InvalidTag:
        return None


# --- X25519 ----------------------------------------------------------------


def x25519_generate() -> tuple[bytes, x25519.X25519PrivateKey]:
    """Returns ``(raw_public_32, private_key_object)``."""
    priv = x25519.X25519PrivateKey.generate()
    return priv.public_key().public_bytes_raw(), priv


def x25519_agree(priv: x25519.X25519PrivateKey, peer_pub_raw: bytes) -> bytes:
    return priv.exchange(x25519.X25519PublicKey.from_public_bytes(peer_pub_raw))


# --- ML-KEM-768 ------------------------------------------------------------


def mlkem768_keypair() -> tuple[bytes, mlkem.MLKEM768PrivateKey]:
    """Returns ``(raw_encapsulation_key_1184, decapsulation_key_object)``."""
    dk = mlkem.MLKEM768PrivateKey.generate()
    return dk.public_key().public_bytes_raw(), dk


def mlkem768_encapsulate(ek_raw: bytes) -> tuple[bytes, bytes]:
    """Encapsulates to a raw encapsulation key, returning ``(shared_secret, ct)``.

    Note the tuple order: ``cryptography`` returns ``(shared_secret,
    ciphertext)``, which is the reverse of the ``(ct, ss)`` shape some other
    libraries use.
    """
    ss, ct = mlkem.MLKEM768PublicKey.from_public_bytes(ek_raw).encapsulate()
    return ss, ct


def mlkem768_decapsulate(dk: mlkem.MLKEM768PrivateKey, ct: bytes) -> bytes | None:
    """Recovers the shared secret, or None on failure."""
    try:
        return dk.decapsulate(ct)
    except Exception:
        return None


# --- ML-DSA ----------------------------------------------------------------


def mldsa65_generate() -> tuple[bytes, bytes]:
    """Returns ``(raw_public_1952, private_seed_32)`` for a node identity."""
    priv = mldsa.MLDSA65PrivateKey.generate()
    return priv.public_key().public_bytes_raw(), priv.private_bytes_raw()


def mldsa65_sign(priv_seed: bytes, message: bytes) -> bytes:
    return mldsa.MLDSA65PrivateKey.from_seed_bytes(priv_seed).sign(message)


def mldsa65_verify(pub_raw: bytes, message: bytes, signature: bytes) -> bool:
    return _verify(mldsa.MLDSA65PublicKey, pub_raw, message, signature)


def mldsa87_generate() -> tuple[bytes, bytes]:
    """Returns ``(raw_public_2592, private_seed_32)`` for a mesh root."""
    priv = mldsa.MLDSA87PrivateKey.generate()
    return priv.public_key().public_bytes_raw(), priv.private_bytes_raw()


def mldsa87_sign(priv_seed: bytes, message: bytes) -> bytes:
    return mldsa.MLDSA87PrivateKey.from_seed_bytes(priv_seed).sign(message)


def mldsa87_verify(pub_raw: bytes, message: bytes, signature: bytes) -> bool:
    """Verification against the mesh root key."""
    return _verify(mldsa.MLDSA87PublicKey, pub_raw, message, signature)


def _verify(cls, pub_raw: bytes, message: bytes, signature: bytes) -> bool:
    # No context string: pure ML-DSA, matching BouncyCastle's output in the
    # shared post-quantum vector (spec/corpus/transcripts/pqc-interop.json).
    try:
        cls.from_public_bytes(pub_raw).verify(signature, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
