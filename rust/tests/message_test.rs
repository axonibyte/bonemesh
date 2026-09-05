// Message schema tests. A representative subset of the shared corpus
// (spec/corpus/messages.json); the full set is checked cross-language by
// interop/check-messages-rust.sh.

use bonemesh::message::validate;
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
