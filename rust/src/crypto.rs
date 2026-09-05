//! BoneMesh v3 cryptographic primitives (security.md §1): SHA-256,
//! HKDF-SHA-256, ChaCha20-Poly1305, and X25519, over the RustCrypto crates.
//! Encodings are the raw FIPS/RFC byte strings, matching the Java, Go, and
//! Elixir implementations.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// SHA-256 digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// HKDF-SHA-256 (RFC 5869), full extract-then-expand. Matches the Java
/// reference's `Hkdf.derive(salt, ikm, info, length)`.
pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm).expect("hkdf expand length");
    okm
}

/// ChaCha20-Poly1305 seal (RFC 8439): ciphertext with the 16-byte tag appended.
pub fn aead_seal(key: &[u8], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .expect("aead seal")
}

/// ChaCha20-Poly1305 open. Returns `None` on tag failure.
pub fn aead_open(key: &[u8], nonce: &[u8], aad: &[u8], ct_with_tag: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct_with_tag, aad })
        .ok()
}

/// Computes the raw X25519 shared secret from a private scalar and a peer's
/// raw public key.
pub fn x25519_agree(private_scalar: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*private_scalar);
    let public = PublicKey::from(*peer_public);
    secret.diffie_hellman(&public).to_bytes()
}

/// Derives the raw X25519 public key for a private scalar.
pub fn x25519_public(private_scalar: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*private_scalar);
    PublicKey::from(&secret).to_bytes()
}
