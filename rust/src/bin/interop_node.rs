//! The Rust driver for the language-agnostic interop harness (interop/). It
//! implements the neutral driver contract (interop/README.md): `keygen`,
//! `listen`, and `connect` modes over shared, implementation-independent key
//! and certificate files. The harness pairs it with any other driver without
//! knowing which is which.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bonemesh::crypto;
use bonemesh::node::{Config, Node};
use serde_json::Value;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).cloned().unwrap_or_default();
    let f = flags(&args);

    match mode.as_str() {
        "keygen" => keygen(&f),
        "listen" => listen(&f),
        "connect" => connect(&f),
        other => {
            eprintln!("usage: interop_node <keygen|listen|connect> [--flag value ...]; got {other}");
            std::process::exit(2);
        }
    }
}

// Generates an ML-DSA-65 identity: raw public key (standard, cross-language) to
// --id-pub, and the private key in this implementation's own format to
// --id-priv (it never leaves this node).
fn keygen(f: &HashMap<String, String>) {
    let (public, private_seed) = crypto::mldsa65_generate();
    fs::write(&f["id-pub"], B64.encode(&public)).unwrap();
    fs::write(&f["id-priv"], B64.encode(private_seed)).unwrap();
}

fn config(f: &HashMap<String, String>) -> Config {
    let root_public = B64.decode(read(&f["root-pub"]).trim()).unwrap();
    let cert: Value = serde_json::from_str(&read(&f["cert"])).unwrap();
    let id_priv_vec = B64.decode(read(&f["id-priv"]).trim()).unwrap();
    let mut id_private = [0u8; 32];
    id_private.copy_from_slice(&id_priv_vec);
    Config {
        label: cert["label"].as_str().expect("cert label").to_string(),
        mesh: f["mesh"].clone(),
        root_public,
        cert,
        id_private,
    }
}

fn listen(f: &HashMap<String, String>) {
    let port: u16 = f["port"].parse().unwrap();
    let seconds: u64 = f.get("seconds").and_then(|s| s.parse().ok()).unwrap_or(10);
    let node = Node::start(config(f), port).expect("start node");
    let rx = node.add_listener();
    let out = f["out"].clone();
    let deadline = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < deadline {
        if let Ok(payload) = rx.recv_timeout(Duration::from_millis(200)) {
            let mut file = fs::OpenOptions::new().create(true).append(true).open(&out).unwrap();
            writeln!(file, "{}", serde_json::to_string(&payload).unwrap()).unwrap();
        }
    }
}

fn connect(f: &HashMap<String, String>) {
    let seconds: u64 = f.get("seconds").and_then(|s| s.parse().ok()).unwrap_or(10);
    let node = Node::start(config(f), 0).expect("start node");
    let port: u16 = f["port"].parse().unwrap();
    node.connect(&f["host"], port).expect("connect");
    let payload: Value = serde_json::from_str(&read(&f["message"])).unwrap();
    let deadline = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < deadline {
        if node.send(&f["to"], payload.clone()) {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    std::thread::sleep(Duration::from_millis(1500));
}

fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

fn flags(args: &[String]) -> HashMap<String, String> {
    let mut m = HashMap::new();
    let mut i = 2;
    while i + 1 < args.len() {
        if let Some(k) = args[i].strip_prefix("--") {
            m.insert(k.to_string(), args[i + 1].clone());
        }
        i += 2;
    }
    m
}
