//! Cross-language interop check: reproduces the shared key-schedule vector
//! (spec/corpus/transcripts/keyschedule.json) with the Rust implementation.
//! The Java, Go, and Elixir runners reproduce the same vector, so matching
//! every output means all four derive identical transport keys.

use std::process::exit;

use bonemesh::keyschedule::KeySchedule;
use serde_json::Value;

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let path = std::env::args().nth(1).expect("path to keyschedule.json");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let i = &doc["inputs"];
    let o = &doc["outputs"];
    let mut fails = 0;

    let mut check = |label: &str, got: &[u8], want: &str| {
        if hex_encode(got) == want {
            println!("PASS {label}");
        } else {
            println!("FAIL {label}\n  got:  {}\n  want: {want}", hex_encode(got));
            fails += 1;
        }
    };

    let mut s = KeySchedule::new();
    check("h_init", &s.h, o["h_init"].as_str().unwrap());
    s.mix_hash(&hex_decode(i["mesh_hex"].as_str().unwrap()));
    check("h_after_mesh", &s.h, o["h_after_mesh"].as_str().unwrap());
    s.mix_key(&hex_decode(i["ss_dh_hex"].as_str().unwrap()));
    check("ck_after_dh", &s.ck, o["ck_after_dh"].as_str().unwrap());
    s.mix_key(&hex_decode(i["ss_kem_hex"].as_str().unwrap()));
    check("ck_after_kem", &s.ck, o["ck_after_kem"].as_str().unwrap());
    let ct1 = s.encrypt_and_hash(&hex_decode(i["plaintext1_hex"].as_str().unwrap()));
    check("ct1", &ct1, o["ct1_hex"].as_str().unwrap());
    check("h_after_ct1", &s.h, o["h_after_ct1"].as_str().unwrap());
    let ct2 = s.encrypt_and_hash(&hex_decode(i["plaintext2_hex"].as_str().unwrap()));
    check("ct2", &ct2, o["ct2_hex"].as_str().unwrap());
    check("h_after_ct2", &s.h, o["h_after_ct2"].as_str().unwrap());
    let (i2r, r2i) = s.split();
    check("transport_key_i2r", &i2r, o["transport_key_i2r"].as_str().unwrap());
    check("transport_key_r2i", &r2i, o["transport_key_r2i"].as_str().unwrap());

    drop(check);
    if fails > 0 {
        eprintln!("{fails} key-schedule output(s) mismatched");
        exit(1);
    }
    println!("all key-schedule outputs match");
}
