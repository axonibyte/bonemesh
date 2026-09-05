//! Cross-language interop check: reads the shared corpus
//! (spec/corpus/canon.json) and confirms this Rust canonicalizer reproduces
//! each vector's expected bytes. The Java, Go, and Elixir implementations
//! validate the same file, so agreement means a certificate signed by any of
//! them verifies under this one. Invoked by interop/check-canon-rust.sh; exits
//! non-zero on any mismatch.

use std::process::exit;

use bonemesh::canon::canonicalize;
use serde_json::Value;

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: canon_check <path-to-canon.json>");
        exit(2);
    });

    let text = std::fs::read_to_string(&path).expect("read corpus");
    let doc: Value = serde_json::from_str(&text).expect("parse corpus");
    let vectors = doc["vectors"].as_array().expect("vectors array");

    let mut failures = 0;
    for v in vectors {
        let name = v["name"].as_str().unwrap_or("?");
        let got = canonicalize(&v["cert"]).expect("canonicalize");
        let want = v["canonical"].as_str().expect("canonical");
        if got == want {
            println!("PASS {name}");
        } else {
            println!("FAIL {name}\n  got:  {got}\n  want: {want}");
            failures += 1;
        }
    }

    if failures > 0 {
        eprintln!("{failures} vector(s) mismatched");
        exit(1);
    }
    println!("all {} canon vectors match", vectors.len());
}
