// In-memory BMX handshake and transport tests: a full mutually-authenticated
// exchange plus the rejections that keep an outsider or a tamperer out, and a
// round-trip over the resulting transport session. Cross-language interop is
// proven separately by the live matrix.

use bonemesh::{cert, crypto};
use bonemesh::handshake::Handshake;
use bonemesh::transport::Transport;
use serde_json::json;

const MESH: &str = "acme-prod";
const NOW: i64 = 1_788_600_000;

struct Ids {
    root_pub: Vec<u8>,
    root_priv: [u8; 32],
}

fn root() -> Ids {
    let (root_pub, root_priv) = crypto::mldsa87_generate();
    Ids { root_pub, root_priv }
}

fn identity(ids: &Ids, label: &str) -> (serde_json::Value, [u8; 32]) {
    let (pk, sk) = crypto::mldsa65_generate();
    let c = cert::sign(cert::build(MESH, label, &pk, NOW - 100, NOW + 100), &ids.root_priv);
    (c, sk)
}

fn run(a: &mut Handshake, b: &mut Handshake) {
    let m1 = a.write_message1();
    let m2 = b.read_message1_write_message2(&m1).unwrap();
    let m3 = a.read_message2_write_message3(&m2).unwrap();
    b.read_message3(&m3).unwrap();
}

#[test]
fn full_handshake_agrees_on_keys_and_identities() {
    let ids = root();
    let (ac, ask) = identity(&ids, "alpha");
    let (bc, bsk) = identity(&ids, "beta");
    let mut a = Handshake::initiator(MESH, &ids.root_pub, NOW, ac, ask);
    let mut b = Handshake::responder(MESH, &ids.root_pub, NOW, bc, bsk);
    run(&mut a, &mut b);

    assert_eq!(a.session().send_key, b.session().receive_key);
    assert_eq!(a.session().receive_key, b.session().send_key);
    assert_ne!(a.session().send_key, a.session().receive_key);
    assert_eq!(a.session().peer_cert["label"], "beta");
    assert_eq!(b.session().peer_cert["label"], "alpha");
}

#[test]
fn transport_round_trips_over_the_session() {
    let ids = root();
    let (ac, ask) = identity(&ids, "alpha");
    let (bc, bsk) = identity(&ids, "beta");
    let mut a = Handshake::initiator(MESH, &ids.root_pub, NOW, ac, ask);
    let mut b = Handshake::responder(MESH, &ids.root_pub, NOW, bc, bsk);
    run(&mut a, &mut b);

    let mut ta = Transport::new(a.session());
    let mut tb = Transport::new(b.session());
    let frame = ta.seal(&json!({"m":"hello"}));
    assert_eq!(tb.open(&frame).unwrap()["m"], "hello");
    // Out-of-order rejected.
    let f0 = ta.seal(&json!({"n":0}));
    let f1 = ta.seal(&json!({"n":1}));
    assert!(tb.open(&f1).is_err());
    assert_eq!(tb.open(&f0).unwrap()["n"], 0);
}

#[test]
fn responder_rejects_foreign_mesh() {
    let ids = root();
    let (ac, ask) = identity(&ids, "alpha");
    let (bc, bsk) = identity(&ids, "beta");
    let mut a = Handshake::initiator(MESH, &ids.root_pub, NOW, ac, ask);
    let mut b = Handshake::responder("other-mesh", &ids.root_pub, NOW, bc, bsk);
    let m1 = a.write_message1();
    assert!(b.read_message1_write_message2(&m1).is_err());
}

#[test]
fn party_presenting_a_cert_it_does_not_own_is_rejected() {
    let ids = root();
    let (ac, ask) = identity(&ids, "alpha");
    let (bc, _bsk) = identity(&ids, "beta");
    let (_wrong_pub, wrong_sk) = crypto::mldsa65_generate();
    let mut a = Handshake::initiator(MESH, &ids.root_pub, NOW, ac, ask);
    // Responder holds beta's real cert but signs with the wrong identity key.
    let mut b = Handshake::responder(MESH, &ids.root_pub, NOW, bc, wrong_sk);
    let m1 = a.write_message1();
    let m2 = b.read_message1_write_message2(&m1).unwrap();
    let err = a.read_message2_write_message3(&m2).unwrap_err();
    assert!(err.contains("signature"), "expected signature rejection, got: {err}");
}
