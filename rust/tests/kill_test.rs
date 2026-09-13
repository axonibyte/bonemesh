//! kill() teardown (protocol.md §8).
//!
//! This port's kill() was a single flag store and nothing else, so a "killed" node
//! stayed bound to its port and kept serving every open link until the process
//! exited -- where the other six closed both. Nothing tested it, which is how that
//! survived. These assert the two observable consequences rather than the flag.
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bonemesh::node::{Config, Node};
use bonemesh::{cert, crypto};

const MESH: &str = "acme-prod";

// Derived rather than hardcoded, for the reason node_relay_test.rs records (D10).
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
fn kill_releases_the_listening_port() {
    let (root_pub, root_priv) = crypto::mldsa87_generate();
    let alpha = Node::start(config(&root_priv, &root_pub, "alpha"), 0).unwrap();
    let port = alpha.port();

    // Before: the port accepts connections.
    assert!(
        TcpStream::connect(("127.0.0.1", port)).is_ok(),
        "the node was not accepting connections before kill"
    );

    // Let the accept loop consume that connection and block in incoming() again.
    //
    // Without this the test cannot see the defect it exists for: a connection still
    // queued when kill() sets the stop flag makes incoming() return immediately, so
    // the loop notices the flag and releases the port on its own. The test would then
    // have supplied the very wake-up the code is supposed to provide, and passed with
    // kill()'s unblock deleted -- which is exactly what mutation showed.
    std::thread::sleep(Duration::from_millis(500));

    alpha.kill();

    // After: re-binding the same port must succeed, which it cannot while the old
    // listener holds it. Binding is the oracle rather than a failed connect, because
    // a connect can succeed against a socket already in a dying listener's backlog.
    //
    // 0.0.0.0, not 127.0.0.1. The node binds the wildcard address, and binding
    // 127.0.0.1:port succeeds even while 0.0.0.0:port is held -- they are different
    // addresses. Mutation caught that: with the test bound to loopback, deleting the
    // release logic entirely still passed.
    let mut bound = false;
    for _ in 0..50 {
        if std::net::TcpListener::bind(("0.0.0.0", port)).is_ok() {
            bound = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(bound, "kill() did not release port {port}");
}

#[test]
fn kill_closes_established_links() {
    let (root_pub, root_priv) = crypto::mldsa87_generate();
    let alpha = Node::start(config(&root_priv, &root_pub, "alpha"), 0).unwrap();
    let beta = Node::start(config(&root_priv, &root_pub, "beta"), 0).unwrap();
    alpha.connect("127.0.0.1", beta.port()).unwrap();

    assert!(
        alpha.session_info().as_object().is_some_and(|o| !o.is_empty()),
        "no session was established"
    );
    alpha.kill();

    // Asserted IMMEDIATELY, with no polling, and that is the whole point. Mutation
    // caught the polling version: alpha's links also empty because beta reacts to the
    // shutdown bye by closing, which makes alpha's reader deregister -- so a test that
    // waited could not tell the local drain from the peer's reaction. The drain is
    // synchronous and the peer's reaction is not, so "empty the instant kill()
    // returns" is the one assertion only the drain can satisfy.
    assert!(
        alpha.session_info().as_object().map_or(true, |o| o.is_empty()),
        "kill() returned with sessions still registered: {:?}",
        alpha.session_info()
    );

    beta.kill();
}
