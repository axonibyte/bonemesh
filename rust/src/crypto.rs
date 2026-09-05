//! BoneMesh v3 cryptographic primitives (security.md §1): SHA-256,
//! HKDF-SHA-256, ChaCha20-Poly1305, and X25519, over the RustCrypto crates.
//! Encodings are the raw FIPS/RFC byte strings, matching the Java, Go, and
//! Elixir implementations.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use ml_dsa::signature::Verifier;
use ml_dsa::{
    B32, EncodedSignature, EncodedVerifyingKey, Generate, Keypair, MlDsa65, MlDsa87, MlDsaParams,
    Signature, SigningKey, VerifyingKey,
};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem768};
use rand_core::OsRng;
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

/// Generates an ephemeral X25519 key pair as `(public, private)`.
pub fn x25519_generate() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    (PublicKey::from(&secret).to_bytes(), secret.to_bytes())
}

// --- ML-DSA (FIPS 204). Public keys and signatures are the raw FIPS encodings
// (interoperable, verified against the Java reference). A private key is the
// 32-byte seed in this crate's native format; private keys never leave a node.

macro_rules! mldsa_ops {
    ($level:ty, $gen:ident, $sign:ident, $verify:ident) => {
        /// Generates an ML-DSA identity as `(public_raw, private_seed)`.
        pub fn $gen() -> (Vec<u8>, [u8; 32]) {
            let sk = SigningKey::<$level>::generate();
            let pub_raw = sk.verifying_key().encode().to_vec();
            let mut seed = [0u8; 32];
            seed.copy_from_slice(sk.to_seed().as_slice());
            (pub_raw, seed)
        }

        /// Signs a message deterministically with empty context (FIPS 204 pure).
        pub fn $sign(private_seed: &[u8; 32], message: &[u8]) -> Vec<u8> {
            let sk = SigningKey::<$level>::from_seed(&B32::from(*private_seed));
            sk.expanded_key()
                .sign_deterministic(message, &[])
                .expect("ml-dsa sign")
                .encode()
                .to_vec()
        }

        /// Verifies a signature against a raw public key.
        pub fn $verify(public_raw: &[u8], message: &[u8], signature: &[u8]) -> bool {
            mldsa_verify::<$level>(public_raw, message, signature)
        }
    };
}

fn mldsa_verify<P: MlDsaParams>(public_raw: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(vk_enc) = EncodedVerifyingKey::<P>::try_from(public_raw) else { return false };
    let vk = VerifyingKey::<P>::decode(&vk_enc);
    let Ok(sig_enc) = EncodedSignature::<P>::try_from(signature) else { return false };
    let Some(sig) = Signature::<P>::decode(&sig_enc) else { return false };
    vk.verify(message, &sig).is_ok()
}

mldsa_ops!(MlDsa65, mldsa65_generate, mldsa65_sign, mldsa65_verify);
mldsa_ops!(MlDsa87, mldsa87_generate, mldsa87_sign, mldsa87_verify);

// --- ML-KEM-768 (FIPS 203). Encapsulation keys, ciphertexts, and secrets are
// raw FIPS encodings (interoperable). The decapsulation key is native and local.

type Dk = <MlKem768 as KemCore>::DecapsulationKey;
type Ek = <MlKem768 as KemCore>::EncapsulationKey;

/// Generates an ephemeral ML-KEM-768 key pair as `(encapsulation_key, decapsulation_key)`.
pub fn mlkem_generate() -> (Vec<u8>, Vec<u8>) {
    let (dk, ek) = MlKem768::generate(&mut OsRng);
    (ek.as_bytes().to_vec(), dk.as_bytes().to_vec())
}

/// Encapsulates to a peer's raw encapsulation key, returning `(shared_secret, ciphertext)`.
pub fn mlkem_encapsulate(encapsulation_key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let enc = Encoded::<Ek>::try_from(encapsulation_key).expect("ek size");
    let ek = Ek::from_bytes(&enc);
    let (ct, ss) = ek.encapsulate(&mut OsRng).expect("encapsulate");
    (ss.to_vec(), ct.to_vec())
}

/// Recovers the ML-KEM-768 shared secret from a ciphertext.
pub fn mlkem_decapsulate(decapsulation_key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let enc = Encoded::<Dk>::try_from(decapsulation_key).expect("dk size");
    let dk = Dk::from_bytes(&enc);
    let ct = Ciphertext::<MlKem768>::try_from(ciphertext).expect("ct size");
    dk.decapsulate(&ct).expect("decapsulate").to_vec()
}
