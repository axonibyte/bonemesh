// Key-schedule correctness and composition. The exact shared vector is verified
// by interop/check-keyschedule-rust.sh (and by the Java/Go/Elixir runners); this
// suite proves the schedule is correct against the SHA-256 formula and that an
// initiator/responder pair stays in lockstep.

use bonemesh::crypto::sha256;
use bonemesh::keyschedule::{KeySchedule, PROTOCOL_NAME};

fn ramp(start: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    for (i, x) in b.iter_mut().enumerate() {
        *x = start.wrapping_add(i as u8);
    }
    b
}

fn driven() -> KeySchedule {
    let mut s = KeySchedule::new();
    s.mix_hash(b"acme-prod");
    s.mix_key(&ramp(1));
    s.mix_key(&ramp(0x21));
    s
}

#[test]
fn init_seeds_from_protocol_name() {
    assert_eq!(KeySchedule::new().h, sha256(PROTOCOL_NAME.as_bytes()));
}

#[test]
fn mix_hash_follows_the_formula() {
    let mut s = KeySchedule::new();
    let h0 = s.h;
    s.mix_hash(b"transcript-bytes");
    let mut expect = h0.to_vec();
    expect.extend_from_slice(b"transcript-bytes");
    assert_eq!(s.h, sha256(&expect));
}

#[test]
fn initiator_and_responder_stay_in_lockstep() {
    let mut initiator = driven();
    let mut responder = driven();

    let ct1 = initiator.encrypt_and_hash(b"responder sees this");
    assert_eq!(responder.decrypt_and_hash(&ct1).unwrap(), b"responder sees this");

    let ct2 = initiator.encrypt_and_hash(b"and this second one");
    assert_eq!(responder.decrypt_and_hash(&ct2).unwrap(), b"and this second one");

    assert_eq!(initiator.h, responder.h);
    assert_eq!(initiator.split(), responder.split());
}

#[test]
fn mix_key_resets_the_nonce_counter() {
    let mut s = KeySchedule::new();
    s.mix_key(&ramp(1));
    let _ = s.encrypt_and_hash(b"first");
    assert_eq!(s.nonce_counter(), 1);
    s.mix_key(&ramp(0x21));
    assert_eq!(s.nonce_counter(), 0);
}

#[test]
fn tampered_ciphertext_fails_to_decrypt() {
    let mut ct = driven().encrypt_and_hash(b"payload");
    ct[0] ^= 0x01;
    assert!(driven().decrypt_and_hash(&ct).is_none());
}
