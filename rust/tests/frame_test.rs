// Frame classification tests. Cases mirror the shared corpus
// (spec/corpus/framing.json); byte-for-byte agreement with the Java, Go, and
// Elixir classifiers over that corpus is checked by interop/check-framing-rust.sh.

use bonemesh::frame::{classify, Verdict, TRANSPORT_CAP};

fn reason(raw: &[u8]) -> Option<&'static str> {
    match classify(raw, TRANSPORT_CAP) {
        Verdict::Accept(_) => None,
        Verdict::Reject(r) => Some(r),
    }
}

#[test]
fn simple_object_accepts() {
    assert_eq!(reason(b"{\"a\":1}\n"), None);
}
#[test]
fn missing_trailing_newline() {
    assert_eq!(reason(b"{\"a\":1}"), Some("no-newline"));
}
#[test]
fn empty_line() {
    assert_eq!(reason(b"\n"), Some("empty"));
}
#[test]
fn not_json() {
    assert_eq!(reason(b"not json\n"), Some("invalid-json"));
}
#[test]
fn json_array_is_not_an_object() {
    assert_eq!(reason(b"[1,2,3]\n"), Some("not-an-object"));
}
#[test]
fn interior_newline_splits_frame() {
    assert_eq!(reason(b"{\"a\":\n1}\n"), Some("invalid-json"));
}
#[test]
fn invalid_utf8() {
    assert_eq!(reason(&[b'{', b'"', b'a', b'"', b':', b'"', 0xff, b'"', b'}', b'\n']), Some("invalid-utf8"));
}
#[test]
fn trailing_garbage_after_object() {
    assert_eq!(reason(b"{\"a\":1} X\n"), Some("trailing-data"));
}
#[test]
fn frame_exactly_at_cap_accepts() {
    assert_eq!(reason(&line_of_length(TRANSPORT_CAP)), None);
}
#[test]
fn frame_one_byte_over_cap_is_oversize() {
    let raw = line_of_length(TRANSPORT_CAP + 1);
    assert_eq!(classify_reason_at_cap(&raw), Some("oversize"));
}

fn classify_reason_at_cap(raw: &[u8]) -> Option<&'static str> {
    match classify(raw, TRANSPORT_CAP) {
        Verdict::Accept(_) => None,
        Verdict::Reject(r) => Some(r),
    }
}

fn line_of_length(n: usize) -> Vec<u8> {
    let overhead = "{\"p\":\"\"}".len() + 1;
    let fill = n - overhead;
    let mut s = String::from("{\"p\":\"");
    s.push_str(&"A".repeat(fill));
    s.push_str("\"}\n");
    s.into_bytes()
}
