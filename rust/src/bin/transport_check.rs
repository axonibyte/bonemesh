//! Cross-language interop check: reproduces the shared transport-frame vector
//! (spec/corpus/transcripts/transport-frame.json) with the Rust implementation,
//! and opens it again.
//!
//! The vector states both halves ("reproduces ct_hex and can open it"), so both
//! are asserted: sealing alone would pass even if opening were broken, and
//! opening alone would pass a transport that agreed with itself but not with the
//! other implementations. Invoked by interop/check-transport-rust.sh.

use std::process::exit;

use bonemesh::transport::{open_ciphertext, seal_ciphertext};
use serde_json::Value;

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let path = std::env::args().nth(1).expect("path to transport-frame.json");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let inputs = &doc["inputs"];
    let outputs = &doc["outputs"];

    let mut failures = 0;
    let mut check = |name: &str, want: &str, got: &str| {
        if want == got {
            println!("PASS {name}");
        } else {
            println!("FAIL {name}\n  got:  {got}\n  want: {want}");
            failures += 1;
        }
    };

    let key = hex_decode(inputs["key_hex"].as_str().unwrap());
    let seq = inputs["seq"].as_u64().unwrap();
    let inner_hex = inputs["inner_plaintext_hex"].as_str().unwrap();
    let inner = hex_decode(inner_hex);
    let want_ct = outputs["ct_hex"].as_str().unwrap();

    check("ct_hex", want_ct, &hex_encode(&seal_ciphertext(&key, seq, &inner)));

    match open_ciphertext(&key, seq, &hex_decode(want_ct)) {
        Some(pt) => check("inner_plaintext_hex", inner_hex, &hex_encode(&pt)),
        None => {
            println!("FAIL inner_plaintext_hex\n  got:  <authentication failed>");
            failures += 1;
        }
    }

    if failures > 0 {
        eprintln!("{failures} output(s) mismatched");
        exit(1);
    }
    println!("transport frame seals and opens to the shared vector");
}
