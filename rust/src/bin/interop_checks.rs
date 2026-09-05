//! Corpus-driven interop checks for the Rust port: `framing` and `messages`
//! subcommands confirm the Rust frame classifier and message validator reach
//! the same verdicts as the Java, Go, and Elixir implementations over the shared
//! corpora. Invoked by interop/check-framing-rust.sh and check-messages-rust.sh.

use std::process::exit;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bonemesh::frame::{self, Verdict};
use bonemesh::message;
use serde_json::Value;

fn main() {
    let mode = std::env::args().nth(1).expect("mode: framing|messages");
    let path = std::env::args().nth(2).expect("corpus path");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();

    let fails = match mode.as_str() {
        "framing" => check_framing(&doc),
        "messages" => check_messages(&doc),
        other => {
            eprintln!("unknown mode: {other}");
            exit(2);
        }
    };
    if fails > 0 {
        exit(1);
    }
}

fn check_framing(doc: &Value) -> usize {
    let mut fails = 0;
    for c in doc["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let cap = if c["kind"] == "handshake" { frame::HANDSHAKE_CAP } else { frame::TRANSPORT_CAP };
        let raw = B64.decode(c["bytes_b64"].as_str().unwrap()).unwrap();
        let ok = match (c["expect"].as_str().unwrap(), frame::classify(&raw, cap)) {
            ("accept", Verdict::Accept(_)) => true,
            ("reject", Verdict::Reject(r)) => Some(r) == c["reason"].as_str(),
            _ => false,
        };
        report(name, ok, &mut fails);
    }
    println!("framing: {} cases checked", doc["cases"].as_array().unwrap().len());
    fails
}

fn check_messages(doc: &Value) -> usize {
    let mut fails = 0;
    for c in doc["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let r = message::validate(c["schema"].as_str().unwrap(), &c["frame"]);
        let ok = match c["expect"].as_str().unwrap() {
            "valid" => r.is_none(),
            "invalid" => r == c["reason"].as_str(),
            _ => false,
        };
        report(name, ok, &mut fails);
    }
    println!("messages: {} cases checked", doc["cases"].as_array().unwrap().len());
    fails
}

fn report(name: &str, ok: bool, fails: &mut usize) {
    if ok {
        println!("PASS {name}");
    } else {
        println!("FAIL {name}");
        *fails += 1;
    }
}
