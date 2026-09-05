//! Cross-language interop check: verifies the BMX hybrid key-agreement vector
//! (spec/corpus/transcripts/handshake-agreement.json) from the Rust side. It
//! derives ss_dh independently with X25519 and runs the key schedule,
//! confirming Rust reaches the same transport keys as Java, Go, and Elixir.
//! (ss_kem is taken from the vector; ML-KEM cross-decapsulation is exercised by
//! the post-quantum vector once ML-KEM lands.)

use std::process::exit;

use bonemesh::{crypto, keyschedule::KeySchedule};
use serde_json::Value;

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn arr32(v: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(v);
    a
}

fn main() {
    let path = std::env::args().nth(1).expect("path to handshake-agreement.json");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let i = &doc["inputs"];
    let o = &doc["outputs"];
    let mut fails = 0;

    // Independent X25519: derive ss_dh from the initiator scalar + responder pub.
    let ss_dh = crypto::x25519_agree(
        &arr32(&hex_decode(i["ei_priv_hex"].as_str().unwrap())),
        &arr32(&hex_decode(i["er_pub_hex"].as_str().unwrap())),
    );
    if hex_encode(&ss_dh) != i["ss_dh_hex"].as_str().unwrap() {
        eprintln!("X25519 ss_dh mismatch");
        exit(1);
    }
    println!("PASS x25519_ss_dh");

    let ss_kem = hex_decode(i["ss_kem_hex"].as_str().unwrap());

    let mut check = |label: &str, got: &[u8], want: &str| {
        if hex_encode(got) == want {
            println!("PASS {label}");
        } else {
            println!("FAIL {label}");
            fails += 1;
        }
    };

    let mut s = KeySchedule::new();
    s.mix_hash(&hex_decode(i["mesh_hex"].as_str().unwrap()));
    s.mix_hash(&hex_decode(i["ei_pub_hex"].as_str().unwrap()));
    s.mix_hash(&hex_decode(i["ki_ek_hex"].as_str().unwrap()));
    s.mix_hash(&hex_decode(i["n_hex"].as_str().unwrap()));
    check("h_after_msg1", &s.h, o["h_after_msg1"].as_str().unwrap());
    s.mix_hash(&hex_decode(i["er_pub_hex"].as_str().unwrap()));
    s.mix_key(&ss_dh);
    check("ck_after_dh", &s.ck, o["ck_after_dh"].as_str().unwrap());
    s.mix_hash(&hex_decode(i["kem_ct_hex"].as_str().unwrap()));
    s.mix_key(&ss_kem);
    check("ck_after_kem", &s.ck, o["ck_after_kem"].as_str().unwrap());
    check("h_after_msg2_ephemerals", &s.h, o["h_after_msg2_ephemerals"].as_str().unwrap());
    let (i2r, r2i) = s.split();
    check("transport_key_i2r", &i2r, o["transport_key_i2r"].as_str().unwrap());
    check("transport_key_r2i", &r2i, o["transport_key_r2i"].as_str().unwrap());

    drop(check);
    if fails > 0 {
        eprintln!("{fails} agreement output(s) mismatched");
        exit(1);
    }
    println!("all agreement outputs match");
}
