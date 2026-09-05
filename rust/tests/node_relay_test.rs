// Node integration test: a three-node line alpha—beta—gamma over loopback TCP.
// alpha and gamma are not direct neighbors, so a message from alpha to gamma
// must be relayed through beta once distance-vector discovery gives alpha a
// route. Exercises routing/heartbeat/relay end to end in one process.
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
fn three_node_line_relay() {
    let (root_pub, root_priv) = crypto::mldsa87_generate();
    let alpha = Node::start(config(&root_priv, &root_pub, "alpha"), 0).unwrap();
    let beta = Node::start(config(&root_priv, &root_pub, "beta"), 0).unwrap();
    let gamma = Node::start(config(&root_priv, &root_pub, "gamma"), 0).unwrap();
    let got = gamma.add_listener();

    // Line topology: alpha <-> beta <-> gamma; alpha and gamma never connect.
    alpha.connect("127.0.0.1", beta.port()).unwrap();
    gamma.connect("127.0.0.1", beta.port()).unwrap();

    // Wait for discovery to give alpha a route to gamma via beta.
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if alpha.send("gamma", json!({"m": "relayed"})) {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let payload = got
        .recv_timeout(Duration::from_secs(5))
        .expect("gamma never received the relayed message");
    assert_eq!(payload["m"], "relayed");
    assert_eq!(alpha.route_table().get("gamma").map(String::as_str), Some("beta"));

    alpha.kill();
    beta.kill();
    gamma.kill();
}
