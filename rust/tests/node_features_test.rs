// Feature integration tests over real loopback nodes (protocol.md §7): the
// origin receives an ack for a delivered message, and a relay that drops a
// message on TTL exhaustion returns a NAK that names the RELAY as the failing
// hop, never the final destination (defect D4).
use std::time::{Duration, Instant};

use bonemesh::node::{Config, Node};
use bonemesh::{cert, crypto};
use serde_json::json;

const MESH: &str = "acme-prod";
const NOW: i64 = 1_788_600_000;

fn config(root_priv: &[u8; 32], root_pub: &[u8], label: &str) -> Config {
    let (pub_key, priv_seed) = crypto::mldsa65_generate();
    let c = cert::sign(cert::build(MESH, label, &pub_key, NOW - 100, NOW + 100_000), root_priv);
    Config {
        label: label.to_string(),
        mesh: MESH.to_string(),
        root_public: root_pub.to_vec(),
        cert: c,
        id_private: priv_seed,
    }
}

#[test]
fn ack_reaches_origin_listener() {
    let (root_pub, root_priv) = crypto::mldsa87_generate();
    let alpha = Node::start(config(&root_priv, &root_pub, "alpha"), 0).unwrap();
    let beta = Node::start(config(&root_priv, &root_pub, "beta"), 0).unwrap();
    let acks = alpha.add_ack_listener();
    alpha.connect("127.0.0.1", beta.port()).unwrap();

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut mid = None;
    while Instant::now() < deadline {
        if let Some(m) = alpha.send_mid("beta", json!({"m": "hi"})) {
            mid = Some(m);
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let mid = mid.expect("message never routed to beta");

    let a = acks.recv_timeout(Duration::from_secs(5)).expect("origin never received an ack");
    assert_eq!(a["type"], "ack");
    assert_eq!(a["mid"], json!(mid));

    alpha.kill();
    beta.kill();
}

#[test]
fn nak_names_the_failing_relay_not_the_destination() {
    let (root_pub, root_priv) = crypto::mldsa87_generate();
    let alpha = Node::start(config(&root_priv, &root_pub, "alpha"), 0).unwrap();
    let beta = Node::start(config(&root_priv, &root_pub, "beta"), 0).unwrap();
    let gamma = Node::start(config(&root_priv, &root_pub, "gamma"), 0).unwrap();

    alpha.connect("127.0.0.1", beta.port()).unwrap();
    gamma.connect("127.0.0.1", beta.port()).unwrap();

    // Wait until alpha has learned a route to gamma via beta.
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if alpha.route_table().get("gamma").map(String::as_str) == Some("beta") {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        alpha.route_table().get("gamma").map(String::as_str),
        Some("beta"),
        "alpha never learned a route to gamma via beta"
    );

    let acks = alpha.add_ack_listener();
    // ttl=1 exhausts at beta (the relay), which must name itself as the hop.
    let mid = alpha
        .send_with_ttl("gamma", json!({"m": "doomed"}), 1)
        .expect("alpha had no route to gamma");

    let a = acks.recv_timeout(Duration::from_secs(5)).expect("origin never received a NAK");
    assert_eq!(a["type"], "nak");
    assert_eq!(a["hop"], "beta", "the NAK must name the relay, not the destination (D4)");
    assert_eq!(a["reason"], "ttl");
    assert_eq!(a["mid"], json!(mid));

    alpha.kill();
    beta.kill();
    gamma.kill();
}
