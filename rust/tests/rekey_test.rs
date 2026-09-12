// F5 rekey over real loopback nodes (security.md §6). Its own test binary so the
// BONEMESH_REKEY_FRAMES override cannot bleed into other tests' nodes. Under a
// low frame threshold the session initiator rekeys the live link; both ends
// advance their rekey epoch and application delivery continues across the key
// swap without interruption.
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bonemesh::node::{Config, Node};
use bonemesh::{cert, crypto};
use serde_json::json;

const MESH: &str = "acme-prod";
// These suites start real nodes, so certificate validity is judged against the
// wall clock rather than an instant the test supplies. A hardcoded absolute NOW
// therefore expires: the previous value (1_788_600_000, with a +100_000s window)
// stopped being valid on 2026-09-07 and silently took every live-node test in
// this file with it. Derive it instead, as the Java, Go, JS and Elixir suites do.
// cert_test.rs keeps a fixed NOW on purpose -- it passes `now` to verify()
// explicitly, so it is deterministic and cannot rot.
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
fn rekey_under_traffic_advances_epoch_and_keeps_delivering() {
    std::env::set_var("BONEMESH_REKEY_FRAMES", "6"); // ~3 heartbeats' worth
    let (root_pub, root_priv) = crypto::mldsa87_generate();
    let alpha = Node::start(config(&root_priv, &root_pub, "alpha"), 0).unwrap();
    let beta = Node::start(config(&root_priv, &root_pub, "beta"), 0).unwrap();
    let got = beta.add_listener();
    alpha.connect("127.0.0.1", beta.port()).unwrap();

    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if alpha.rekey_epoch("beta") >= 1 && beta.rekey_epoch("alpha") >= 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(alpha.rekey_epoch("beta") >= 1, "initiator never rekeyed");
    assert!(beta.rekey_epoch("alpha") >= 1, "responder never completed a rekey");

    // Delivery must still work on the post-rekey keys.
    while Instant::now() < deadline {
        if alpha.send("beta", json!({"m": "after-rekey"})) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let p = got.recv_timeout(Duration::from_secs(5)).expect("delivery broke across the rekey");
    assert_eq!(p["m"], "after-rekey");

    std::env::remove_var("BONEMESH_REKEY_FRAMES");
    alpha.kill();
    beta.kill();
}
