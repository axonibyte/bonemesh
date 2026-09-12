//! Reads the shared key-log vector (spec/corpus/keylog.json) and confirms this
//! implementation can open a key-logged capture.
//!
//! security.md §8 pins one implementation-neutral key-log format precisely so a
//! single inspector reads a log written by a node in any language. That claim needs
//! agreement in BOTH directions: emitting lines your own reader accepts is not
//! enough. This checks the reading half against a committed capture the Java
//! reference produced. The writing half is covered by each port's own key-log tests
//! and, live and cross-language, by interop tier 10.
//!
//! Invoked by interop/check-keylog-rust.sh.

use std::collections::HashMap;
use std::process::exit;

use base64::Engine;
use bonemesh::transport::open_ciphertext;
use serde_json::Value;

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// Maps "<dir>:<epoch>" to a key. '#' lines are comments; an unknown label shape is
/// ignored rather than fatal, so a future label is not a breaking change.
fn parse_keylog(lines: &[Value]) -> HashMap<String, Vec<u8>> {
    let mut keys = HashMap::new();
    for raw in lines {
        let line = raw.as_str().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 3 {
            continue;
        }
        let label = parts[0];
        let (dir, epoch) = match label.strip_prefix("BMX3_").and_then(|r| {
            let (d, rest) = r.split_at(3);
            rest.strip_prefix("_TRAFFIC_").map(|e| (d, e))
        }) {
            Some(x) => x,
            None => continue,
        };
        if dir != "I2R" && dir != "R2I" {
            continue;
        }
        if epoch.is_empty() || !epoch.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        match hex_decode(parts[2]) {
            Some(k) if k.len() == 32 => {
                keys.insert(format!("{}:{}", dir.to_lowercase(), epoch), k);
            }
            _ => continue,
        }
    }
    keys
}

fn main() {
    let path = std::env::args().nth(1).expect("path to keylog.json");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let capture = doc["capture"].as_array().cloned().unwrap_or_default();
    let expected = doc["expected"].as_array().cloned().unwrap_or_default();
    if capture.is_empty() || capture.len() != expected.len() {
        eprintln!("vector malformed: {} capture, {} expected", capture.len(), expected.len());
        exit(1);
    }
    let keys = parse_keylog(doc["keylog"].as_array().map(|v| v.as_slice()).unwrap_or(&[]));
    if keys.is_empty() {
        eprintln!("no usable key-log entries in the vector");
        exit(1);
    }

    let b64 = base64::engine::general_purpose::STANDARD;
    let mut failures = 0;
    for (i, frame) in capture.iter().enumerate() {
        let dir = frame["dir"].as_str().unwrap_or("");
        let seq = frame["frame"]["seq"].as_u64().unwrap_or(0);
        let ct = match b64.decode(frame["frame"]["ct"].as_str().unwrap_or("")) {
            Ok(c) => c,
            Err(_) => {
                println!("FAIL frame {i}: ct is not base64");
                failures += 1;
                continue;
            }
        };
        let epoch = expected[i]["epoch"].as_u64().unwrap_or(0);
        let key = match keys.get(&format!("{dir}:{epoch}")) {
            Some(k) => k,
            None => {
                println!("FAIL frame {i}: no key for {dir} epoch {epoch}");
                failures += 1;
                continue;
            }
        };
        match open_ciphertext(key, seq, &ct) {
            Some(pt) => {
                // serde_json::Value compares structurally, so key order does not
                // matter -- the contract is the structure, not the text.
                let got: Value = match serde_json::from_slice(&pt) {
                    Ok(v) => v,
                    Err(_) => {
                        println!("FAIL frame {i}: inner is not JSON");
                        failures += 1;
                        continue;
                    }
                };
                if got == expected[i]["inner"] {
                    println!("PASS frame {i} ({dir} seq {seq})");
                } else {
                    println!("FAIL frame {i}\n  got:  {got}\n  want: {}", expected[i]["inner"]);
                    failures += 1;
                }
            }
            None => {
                println!("FAIL frame {i}: the logged {dir} key did not open it");
                failures += 1;
            }
        }
    }

    // Self-test the oracle: a ciphertext no key seals must be refused, or a checker
    // that reported success for everything would look identical to this one.
    let any_key = keys.values().next().unwrap();
    if open_ciphertext(any_key, 0, &[0u8; 32]).is_some() {
        println!("FAIL self-test: an unopenable frame was accepted");
        failures += 1;
    } else {
        println!("PASS self-test: an unopenable frame is refused");
    }

    if failures > 0 {
        eprintln!("{failures} key-log frame(s) failed");
        exit(1);
    }
    println!("every captured frame opens with its logged key and reproduces the vector");
}
