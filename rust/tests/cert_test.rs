// Certificate and post-quantum primitive tests. Cross-language post-quantum
// interop (verifying a Java-made signature and decapsulating a Java-made
// ciphertext) is checked separately by interop/check-pqc-rust.sh; this suite
// proves the Rust primitives are internally correct and that certificates
// sign/verify.

use bonemesh::cert;
use bonemesh::crypto;

const NOW: i64 = 1_788_600_000;

fn issued(nbf: i64, exp: i64) -> (serde_json::Value, Vec<u8>, [u8; 32]) {
    let (root_pub, root_priv) = crypto::mldsa87_generate();
    let (node_pub, _node_priv) = crypto::mldsa65_generate();
    let c = cert::sign(cert::build("acme-prod", "alpha", &node_pub, nbf, exp), &root_priv);
    (c, root_pub, root_priv)
}

#[test]
fn signed_certificate_verifies() {
    let (c, root_pub, _) = issued(NOW - 100, NOW + 100);
    assert!(cert::verify(&c, &root_pub, "acme-prod", NOW).is_ok());
}

#[test]
fn unsigned_certificate_is_rejected() {
    let (node_pub, _) = crypto::mldsa65_generate();
    let c = cert::build("acme-prod", "alpha", &node_pub, NOW - 100, NOW + 100);
    let (root_pub, _) = crypto::mldsa87_generate();
    assert!(cert::verify(&c, &root_pub, "acme-prod", NOW).is_err());
}

#[test]
fn expired_certificate_is_rejected() {
    let (c, root_pub, _) = issued(NOW - 200, NOW - 100);
    assert!(cert::verify(&c, &root_pub, "acme-prod", NOW).is_err());
}

#[test]
fn mesh_mismatch_is_rejected() {
    let (c, root_pub, _) = issued(NOW - 100, NOW + 100);
    assert!(cert::verify(&c, &root_pub, "other", NOW).is_err());
}

#[test]
fn wrong_root_is_rejected() {
    let (c, _, _) = issued(NOW - 100, NOW + 100);
    let (other_root, _) = crypto::mldsa87_generate();
    assert!(cert::verify(&c, &other_root, "acme-prod", NOW).is_err());
}

#[test]
fn mldsa_sign_verify_round_trip() {
    let (pk, sk) = crypto::mldsa65_generate();
    let sig = crypto::mldsa65_sign(&sk, b"the transcript hash");
    assert!(crypto::mldsa65_verify(&pk, b"the transcript hash", &sig));
    assert!(!crypto::mldsa65_verify(&pk, b"a different message", &sig));
}

#[test]
fn mlkem_encaps_decaps_round_trip() {
    let (ek, dk) = crypto::mlkem_generate();
    let (ss1, ct) = crypto::mlkem_encapsulate(&ek);
    let ss2 = crypto::mlkem_decapsulate(&dk, &ct);
    assert_eq!(ss1, ss2);
    assert_eq!(ss1.len(), 32);
}

#[test]
fn x25519_agreement_is_symmetric() {
    let (a_pub, a_priv) = crypto::x25519_generate();
    let (b_pub, b_priv) = crypto::x25519_generate();
    assert_eq!(crypto::x25519_agree(&a_priv, &b_pub), crypto::x25519_agree(&b_priv, &a_pub));
}
