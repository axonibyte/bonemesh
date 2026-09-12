//! Broadcast tests (protocol.md §6).
//!
//! Both halves of the D5 fix are asserted, because D5 was two bugs in one line: the
//! v2 implementation iterated indirect routes only, so direct session peers were
//! missed, and a node could appear among its own routes, so it broadcast to itself.
use std::collections::HashSet;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bonemesh::node::{Config, Node};
use bonemesh::{cert, crypto};
use serde_json::json;

const MESH: &str = "acme-prod";

// Derived rather than hardcoded, for the reason node_relay_test.rs records: these
// suites start real nodes, so an absolute NOW expires and takes the whole file with
// it (defect D10).
fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

fn config(root_priv: &[u8; 32], root_pub: &[u8], label: &str) -> Config {
    let (pub_key, priv_seed) = crypto::mldsa65_generate();
    let c = cert::sign(cert::build(MESH, label, &pub_key, now() - 100, now() + 100_000), root_priv);
    Config {
        label: label.to_string(),
        mesh: MESH.to_string(),
        root_public: root_pub.to_vec(),
        cert: c,
        id_private: priv_seed,
    }
}

#[test]
fn broadcast_reaches_every_peer_but_never_the_sender() {
    let (root_pub, root_priv) = crypto::mldsa87_generate();
    let alpha = Node::start(config(&root_priv, &root_pub, "alpha"), 0).unwrap();
    let beta = Node::start(config(&root_priv, &root_pub, "beta"), 0).unwrap();
    let gamma = Node::start(config(&root_priv, &root_pub, "gamma"), 0).unwrap();

    let beta_got = beta.add_listener();
    let gamma_got = gamma.add_listener();
    let alpha_got = alpha.add_listener();

    alpha.connect("127.0.0.1", beta.port()).unwrap();
    alpha.connect("127.0.0.1", gamma.port()).unwrap();

    assert_eq!(alpha.broadcast(json!({"m": "all"})), 2, "both peers should have been handed it");
    assert_eq!(
        beta_got.recv_timeout(Duration::from_secs(5)).expect("beta never received it")["m"],
        "all"
    );
    assert_eq!(
        gamma_got.recv_timeout(Duration::from_secs(5)).expect("gamma never received it")["m"],
        "all"
    );

    // Assert the absence with time allowed to pass, and after the positives, so a
    // failure reads as "the sender got its own broadcast" rather than as a timeout.
    assert!(
        alpha_got.recv_timeout(Duration::from_millis(500)).is_err(),
        "the sender received its own broadcast"
    );

    alpha.kill();
    beta.kill();
    gamma.kill();
}

#[test]
fn broadcast_gives_each_destination_its_own_message_id() {
    // Forced, not stylistic: dedup keys on (mid, chunk index), so a shared mid would
    // have the first relay suppress every other copy, and an ack names only a mid.
    let (root_pub, root_priv) = crypto::mldsa87_generate();
    let alpha = Node::start(config(&root_priv, &root_pub, "alpha"), 0).unwrap();
    let beta = Node::start(config(&root_priv, &root_pub, "beta"), 0).unwrap();
    let gamma = Node::start(config(&root_priv, &root_pub, "gamma"), 0).unwrap();

    let acks = alpha.add_ack_listener();
    alpha.connect("127.0.0.1", beta.port()).unwrap();
    alpha.connect("127.0.0.1", gamma.port()).unwrap();
    assert_eq!(alpha.broadcast(json!({"m": "all"})), 2);

    let mut seen: HashSet<String> = HashSet::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while seen.len() < 2 && Instant::now() < deadline {
        if let Ok(a) = acks.recv_timeout(Duration::from_millis(500)) {
            if let Some(mid) = a["mid"].as_str() {
                seen.insert(mid.to_string());
            }
        }
    }
    assert_eq!(seen.len(), 2, "expected one ack per destination with distinct mids: {seen:?}");

    alpha.kill();
    beta.kill();
    gamma.kill();
}

#[test]
fn broadcast_with_no_peers_reaches_nobody() {
    // The boundary: a lone node has no reachable labels, so the count is zero rather
    // than the node broadcasting to itself -- which is precisely the D5 failure.
    let (root_pub, root_priv) = crypto::mldsa87_generate();
    let alpha = Node::start(config(&root_priv, &root_pub, "alpha"), 0).unwrap();
    let got = alpha.add_listener();
    assert_eq!(alpha.broadcast(json!({"m": "all"})), 0);
    assert!(
        got.recv_timeout(Duration::from_millis(500)).is_err(),
        "a lone node broadcast to itself"
    );
    alpha.kill();
}
