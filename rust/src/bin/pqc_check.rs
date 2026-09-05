//! Cross-language post-quantum interop check: verifies the Java-produced vector
//! (spec/corpus/transcripts/pqc-interop.json) from the Rust side, using the
//! RustCrypto ml-dsa and ml-kem crates. Success means Rust verifies a signature
//! Java made and decapsulates a ciphertext Java produced to the identical
//! secret — post-quantum interop across implementations.

use std::process::exit;

use bonemesh::crypto;
use serde_json::Value;

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn main() {
    let path = std::env::args().nth(1).expect("path to pqc-interop.json");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();

    let dsa = &doc["mldsa65"];
    let dsa_ok = crypto::mldsa65_verify(
        &hex_decode(dsa["public_hex"].as_str().unwrap()),
        &hex_decode(dsa["message_hex"].as_str().unwrap()),
        &hex_decode(dsa["signature_hex"].as_str().unwrap()),
    );
    println!("ML-DSA-65: Rust verifies Java signature: {dsa_ok}");

    let kem = &doc["mlkem768"];
    let ss = crypto::mlkem_decapsulate(
        &hex_decode(kem["decapsulation_key_hex"].as_str().unwrap()),
        &hex_decode(kem["ciphertext_hex"].as_str().unwrap()),
    );
    let kem_ok = ss == hex_decode(kem["shared_secret_hex"].as_str().unwrap());
    println!("ML-KEM-768: Rust decapsulates Java ciphertext to Java secret: {kem_ok}");

    if dsa_ok && kem_ok {
        println!("post-quantum interop confirmed (Java -> Rust)");
    } else {
        eprintln!("post-quantum interop FAILED");
        exit(1);
    }
}
