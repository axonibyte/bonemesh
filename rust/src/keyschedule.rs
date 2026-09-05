//! The BMX key schedule (security.md §5): a Noise-style symmetric state
//! carrying a transcript hash `h` and a chaining key `ck`. Pinned constants
//! match the Java reference and the Go/Elixir implementations, verified against
//! the shared vector (spec/corpus/transcripts/keyschedule.json), so every
//! language derives identical keys.

use crate::crypto;

pub const PROTOCOL_NAME: &str = "BoneMesh_BMX_v3_X25519MLKEM768_ChaChaPoly_SHA256";

/// The symmetric state.
pub struct KeySchedule {
    pub h: [u8; 32],
    pub ck: [u8; 32],
    key: Option<[u8; 32]>,
    nonce: u64,
}

impl KeySchedule {
    /// Initializes from the pinned protocol name.
    pub fn new() -> Self {
        let h = crypto::sha256(PROTOCOL_NAME.as_bytes());
        KeySchedule { h, ck: h, key: None, nonce: 0 }
    }

    /// Absorbs data into the transcript hash: `h = SHA-256(h || data)`.
    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut buf = Vec::with_capacity(self.h.len() + data.len());
        buf.extend_from_slice(&self.h);
        buf.extend_from_slice(data);
        self.h = crypto::sha256(&buf);
    }

    /// Mixes input key material, deriving a fresh key and resetting the nonce.
    pub fn mix_key(&mut self, ikm: &[u8]) {
        let okm = crypto::hkdf(&self.ck, ikm, &[], 64);
        self.ck.copy_from_slice(&okm[0..32]);
        let mut k = [0u8; 32];
        k.copy_from_slice(&okm[32..64]);
        self.key = Some(k);
        self.nonce = 0;
    }

    /// Encrypts a plaintext with `h` as associated data, then absorbs the
    /// ciphertext.
    pub fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let key = self.key.expect("no key material mixed yet");
        let ct = crypto::aead_seal(&key, &self.nonce_bytes(), &self.h, plaintext);
        self.nonce += 1;
        self.mix_hash(&ct);
        ct
    }

    /// Decrypts a ciphertext (AAD is the current `h`), then absorbs it.
    pub fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let key = self.key.expect("no key material mixed yet");
        let ad = self.h;
        let pt = crypto::aead_open(&key, &self.nonce_bytes(), &ad, ciphertext)?;
        self.nonce += 1;
        self.mix_hash(ciphertext);
        Some(pt)
    }

    /// Derives the two directional transport keys from the final chaining key.
    pub fn split(&self) -> ([u8; 32], [u8; 32]) {
        let okm = crypto::hkdf(&self.ck, &[], &[], 64);
        let mut i2r = [0u8; 32];
        let mut r2i = [0u8; 32];
        i2r.copy_from_slice(&okm[0..32]);
        r2i.copy_from_slice(&okm[32..64]);
        (i2r, r2i)
    }

    /// The next nonce counter value (for tests).
    pub fn nonce_counter(&self) -> u64 {
        self.nonce
    }

    // Nonce = 4 zero bytes || 64-bit little-endian counter.
    fn nonce_bytes(&self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[4..12].copy_from_slice(&self.nonce.to_le_bytes());
        n
    }
}

impl Default for KeySchedule {
    fn default() -> Self {
        Self::new()
    }
}
