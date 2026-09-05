// JCS canonicalization tests. Vectors mirror the shared corpus
// (spec/corpus/canon.json) and security.md §11.1; byte-for-byte agreement with
// the Java, Go, and Elixir canonicalizers over that corpus is checked by
// interop/check-canon-rust.sh.

use bonemesh::canon::canonicalize;
use serde_json::json;

#[test]
fn basic_sorted_keys() {
    let cert = json!({"v":3,"mesh":"acme-prod","label":"alpha","idk":"YWJj","nbf":1_788_500_000_u64,"exp":1_790_000_000_u64});
    assert_eq!(
        canonicalize(&cert).unwrap(),
        r#"{"exp":1790000000,"idk":"YWJj","label":"alpha","mesh":"acme-prod","nbf":1788500000,"v":3}"#
    );
}

#[test]
fn sig_field_is_stripped() {
    let cert = json!({"v":3,"mesh":"m","label":"alpha","idk":"AA==","nbf":0,"exp":1,"sig":"IGNORED"});
    assert_eq!(
        canonicalize(&cert).unwrap(),
        r#"{"exp":1,"idk":"AA==","label":"alpha","mesh":"m","nbf":0,"v":3}"#
    );
}

#[test]
fn non_ascii_emitted_raw_utf8() {
    let cert = json!({"v":3,"mesh":"m","label":"café","idk":"AA==","nbf":0,"exp":1});
    assert_eq!(
        canonicalize(&cert).unwrap(),
        "{\"exp\":1,\"idk\":\"AA==\",\"label\":\"café\",\"mesh\":\"m\",\"nbf\":0,\"v\":3}"
    );
}

#[test]
fn string_escaping_quote_backslash() {
    let cert = json!({"v":3,"mesh":"m","label":"a\"b\\c","idk":"AA==","nbf":0,"exp":1});
    assert_eq!(
        canonicalize(&cert).unwrap(),
        r#"{"exp":1,"idk":"AA==","label":"a\"b\\c","mesh":"m","nbf":0,"v":3}"#
    );
}

#[test]
fn control_chars_short_and_u_forms() {
    // Label bytes: 'a', U+0001, TAB, 'b'. Expected escapes built from bytes so
    // no source escape sequence is relied on.
    let label = String::from_utf8(vec![b'a', 0x01, 0x09, b'b']).unwrap();
    let cert = json!({"v":3,"mesh":"m","label":label,"idk":"AA==","nbf":0,"exp":1});
    let u0001 = String::from_utf8(vec![0x5c, 0x75, 0x30, 0x30, 0x30, 0x31]).unwrap();
    let tab = String::from_utf8(vec![0x5c, 0x74]).unwrap();
    let want = format!(
        r#"{{"exp":1,"idk":"AA==","label":"a{u0001}{tab}b","mesh":"m","nbf":0,"v":3}}"#
    );
    assert_eq!(canonicalize(&cert).unwrap(), want);
}

#[test]
fn negative_integer_is_rejected() {
    let cert = json!({"v":3,"nbf":-1});
    assert!(canonicalize(&cert).is_err());
}
