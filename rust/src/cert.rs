//! A BoneMesh v3 membership certificate (security.md §3): a mesh-root-signed
//! binding of a display label to a node's ML-DSA-65 identity key, valid within
//! a time window. Represented as a `serde_json::Value` object (the JSON form);
//! its signed pre-image is the `canon` canonicalization of every field except
//! `sig`. Interoperates with the Java reference and the shared corpus.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{json, Value};

use crate::{canon, crypto};

const VERSION: i64 = 3;

/// Builds an unsigned certificate object. `identity_key` is the raw ML-DSA-65
/// public key.
pub fn build(mesh: &str, label: &str, identity_key: &[u8], not_before: i64, not_after: i64) -> Value {
    json!({
        "v": VERSION,
        "mesh": mesh,
        "label": label,
        "idk": B64.encode(identity_key),
        "nbf": not_before,
        "exp": not_after,
    })
}

/// Signs a certificate with the mesh root's ML-DSA-87 private seed.
pub fn sign(mut cert: Value, root_private_seed: &[u8; 32]) -> Value {
    let pre_image = canon::canonicalize(&cert).expect("canonicalize cert");
    let sig = crypto::mldsa87_sign(root_private_seed, pre_image.as_bytes());
    cert["sig"] = json!(B64.encode(sig));
    cert
}

/// Verifies a certificate against a pinned root public key, mesh, and time.
pub fn verify(cert: &Value, root_public: &[u8], expected_mesh: &str, now: i64) -> Result<(), String> {
    if cert["mesh"].as_str() != Some(expected_mesh) {
        return Err("mesh mismatch".into());
    }
    if now < cert["nbf"].as_i64().unwrap_or(i64::MAX) {
        return Err("certificate not yet valid".into());
    }
    if now > cert["exp"].as_i64().unwrap_or(i64::MIN) {
        return Err("certificate expired".into());
    }
    let sig_b64 = cert["sig"].as_str().ok_or("certificate is unsigned")?;
    let sig = B64.decode(sig_b64).map_err(|_| "signature is not base64")?;

    let mut without_sig = cert.clone();
    without_sig.as_object_mut().unwrap().remove("sig");
    let pre_image = canon::canonicalize(&without_sig)?;

    if crypto::mldsa87_verify(root_public, pre_image.as_bytes(), &sig) {
        Ok(())
    } else {
        Err("root signature does not verify".into())
    }
}

/// The node's raw ML-DSA-65 identity public key.
pub fn identity_key(cert: &Value) -> Result<Vec<u8>, String> {
    let idk = cert["idk"].as_str().ok_or("missing idk")?;
    B64.decode(idk).map_err(|_| "idk is not base64".into())
}
