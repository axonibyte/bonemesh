//! Corpus-driven interop checks for the Rust port: `framing` and `messages`
//! subcommands confirm the Rust frame classifier and message validator reach
//! the same verdicts as the Java, Go, and Elixir implementations over the shared
//! corpora. Invoked by interop/check-framing-rust.sh and check-messages-rust.sh.

use std::process::exit;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bonemesh::chunk;
use bonemesh::frame::{self, Verdict};
use bonemesh::message;
use serde_json::Value;

fn main() {
    let mode = std::env::args().nth(1).expect("mode: framing|messages|chunk");
    let path = std::env::args().nth(2).expect("corpus path");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();

    let fails = match mode.as_str() {
        "framing" => check_framing(&doc),
        "messages" => check_messages(&doc),
        "chunk" => check_chunk(&doc),
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

/// Verifies splitting against the shared corpus (spec/corpus/chunk.json).
///
/// Two things, and the second is the one nothing else can see. First the pinned §0
/// constants must match this implementation's -- including the three (chunk count,
/// in-flight count, timeout) that specsrc deliberately does not check, because a
/// substring search for 1024, 256 or 30000 is satisfied by any buffer size already in
/// the tree. Second, the segments this implementation produces must land on exactly
/// the byte boundaries the corpus pins, which is how all seven are shown to cut in the
/// SAME places rather than merely to cut.
fn check_chunk(doc: &Value) -> usize {
    let mut fails = 0usize;
    let mine: [(&str, i64); 5] = [
        ("max_segment_bytes", chunk::MAX_SEGMENT_BYTES as i64),
        ("max_chunks", chunk::MAX_CHUNKS),
        ("max_reassembly_buffer", chunk::MAX_REASSEMBLY_BUFFER as i64),
        ("max_concurrent_reassemblies", chunk::MAX_CONCURRENT_REASSEMBLIES as i64),
        ("reassembly_timeout_millis", chunk::REASSEMBLY_TIMEOUT_MILLIS),
    ];
    let pinned = doc["constants"].as_object().expect("corpus declares no chunk constants");
    for (name, want) in pinned {
        let want = want.as_i64().unwrap();
        let got = mine.iter().find(|(k, _)| k == name).map(|(_, v)| *v);
        let ok = got == Some(want);
        if ok {
            println!("PASS constant {name}");
        } else {
            println!("FAIL constant {name}  (have {got:?}, corpus pins {want})");
            fails += 1;
        }
    }

    let cases = doc["split_cases"].as_array().expect("corpus has no split cases");
    let mid = doc["mid"].as_str().unwrap();
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let key = c["key"].as_str().unwrap();
        let unit = c["unit"].as_str().unwrap();
        let times = c["times"].as_u64().unwrap() as usize;
        let payload = serde_json::json!({ key: unit.repeat(times) });

        let msgs = match chunk::split(mid, "a", "b", 16, payload.clone()) {
            Ok(m) => m,
            Err(e) => {
                println!("FAIL {name}  (split: {e})");
                fails += 1;
                continue;
            }
        };
        let whole = msgs.len() == 1 && msgs[0].get("payload").is_some();
        let lengths: Vec<usize> = if whole {
            vec![]
        } else {
            msgs.iter().map(|m| m["seg"].as_str().unwrap().len()).collect()
        };
        let want_whole = c["expect_whole"].as_bool().unwrap();
        let want_lengths: Vec<usize> = c["segment_byte_lengths"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as usize)
            .collect();

        let mut ok = whole == want_whole && lengths == want_lengths;
        let mut detail = String::new();
        if !ok {
            detail = format!(
                "  (whole={whole} want {want_whole}; lengths={lengths:?} want {want_lengths:?})"
            );
        }
        // A round-trip as the second oracle: matching lengths would not catch segments
        // that are the right size and the wrong bytes.
        if ok && !whole {
            let joined: String = msgs.iter().map(|m| m["seg"].as_str().unwrap()).collect();
            match serde_json::from_str::<Value>(&joined) {
                Ok(rebuilt) if rebuilt == payload => {}
                _ => {
                    ok = false;
                    detail = "  (segments did not rebuild the payload)".to_string();
                }
            }
        }
        if ok {
            println!("PASS {name}");
        } else {
            println!("FAIL {name}{detail}");
            fails += 1;
        }
    }
    if fails == 0 {
        println!("splitting agrees with every pinned constant and cut position");
    }
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
