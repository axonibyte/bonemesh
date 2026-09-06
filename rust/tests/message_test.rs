// Message schema tests. A representative subset of the shared corpus
// (spec/corpus/messages.json); the full set is checked cross-language by
// interop/check-messages-rust.sh.

use bonemesh::message::{self, validate};
use serde_json::json;

const MID: &str = "0123456789abcdef0123456789abcdef";

#[test]
fn bmx1_valid() {
    assert_eq!(validate("bmx1", &json!({"t":"bmx1","v":3,"mesh":"acme","e":"AAAA","k":"BBBB","n":"CCCC"})), None);
}
#[test]
fn bmx1_wrong_version() {
    assert_eq!(validate("bmx1", &json!({"t":"bmx1","v":2,"mesh":"acme","e":"AAAA","k":"BBBB","n":"CCCC"})), Some("version"));
}
#[test]
fn bmx1_non_base64() {
    assert_eq!(validate("bmx1", &json!({"t":"bmx1","v":3,"mesh":"acme","e":"not base64!","k":"BBBB","n":"CCCC"})), Some("not-base64"));
}
#[test]
fn envelope_valid() {
    assert_eq!(validate("envelope", &json!({"seq":0,"ct":"3q2+7w=="})), None);
}
#[test]
fn envelope_negative_seq() {
    assert_eq!(validate("envelope", &json!({"seq":-1,"ct":"3q2+7w=="})), Some("seq-range"));
}
#[test]
fn data_valid() {
    assert_eq!(validate("data", &json!({"type":"data","mid":MID,"to":"g","from":"a","ttl":16,"payload":{}})), None);
}
#[test]
fn data_ttl_out_of_range() {
    assert_eq!(validate("data", &json!({"type":"data","mid":MID,"to":"g","from":"a","ttl":256,"payload":{}})), Some("ttl-range"));
}
#[test]
fn data_malformed_mid() {
    assert_eq!(validate("data", &json!({"type":"data","mid":"0123","to":"g","from":"a","ttl":16,"payload":{}})), Some("mid-format"));
    assert_eq!(validate("data", &json!({"type":"data","mid":MID.to_uppercase(),"to":"g","from":"a","ttl":16,"payload":{}})), Some("mid-format"));
}
#[test]
fn ack_valid() {
    assert_eq!(validate("ack", &json!({"type":"ack","mid":MID})), None);
}
#[test]
fn ack_wrong_type() {
    assert_eq!(validate("ack", &json!({"type":"data","mid":MID})), Some("type"));
}

// nak: routed like data, plus hop + reason. The reason value is not enum-checked.
#[test]
fn nak_valid() {
    assert_eq!(validate("nak", &json!({"type":"nak","mid":MID,"hop":"beta","reason":"ttl","to":"alpha","from":"beta","ttl":16})), None);
}
#[test]
fn nak_unknown_reason_valid() {
    assert_eq!(validate("nak", &json!({"type":"nak","mid":MID,"hop":"beta","reason":"some-future-reason","to":"alpha","from":"beta","ttl":16})), None);
}
#[test]
fn nak_wrong_type() {
    assert_eq!(validate("nak", &json!({"type":"data","mid":MID,"hop":"beta","reason":"ttl","to":"alpha","from":"beta","ttl":16})), Some("type"));
}
#[test]
fn nak_bad_mid() {
    assert_eq!(validate("nak", &json!({"type":"nak","mid":"0123","hop":"beta","reason":"ttl","to":"alpha","from":"beta","ttl":16})), Some("mid-format"));
}
#[test]
fn nak_missing_hop() {
    assert_eq!(validate("nak", &json!({"type":"nak","mid":MID,"reason":"ttl","to":"alpha","from":"beta","ttl":16})), Some("missing-field"));
}
#[test]
fn nak_missing_reason() {
    assert_eq!(validate("nak", &json!({"type":"nak","mid":MID,"hop":"beta","to":"alpha","from":"beta","ttl":16})), Some("missing-field"));
}
#[test]
fn nak_ttl_range() {
    assert_eq!(validate("nak", &json!({"type":"nak","mid":MID,"hop":"beta","reason":"ttl","to":"alpha","from":"beta","ttl":0})), Some("ttl-range"));
}

// bye: link-local; reason optional and free-form.
#[test]
fn bye_valid_with_reason() {
    assert_eq!(validate("bye", &json!({"type":"bye","reason":"idle"})), None);
}
#[test]
fn bye_valid_no_reason() {
    assert_eq!(validate("bye", &json!({"type":"bye"})), None);
}
#[test]
fn bye_unknown_reason_valid() {
    assert_eq!(validate("bye", &json!({"type":"bye","reason":"some-future-reason"})), None);
}
#[test]
fn bye_wrong_type() {
    assert_eq!(validate("bye", &json!({"type":"data"})), Some("type"));
}

// Builders round-trip through their own validators.
#[test]
fn builders_produce_valid_messages() {
    assert_eq!(validate("nak", &message::nak(MID, "alpha", "beta", "beta", "ttl", 16)), None);
    assert_eq!(validate("bye", &message::bye(Some("idle"))), None);
    assert_eq!(validate("bye", &message::bye(None)), None);
}
