//! Splitting and reassembly tests (protocol.md §6.1).
//!
//! Two groups. The first pins the format: a small payload travels whole, a large
//! one splits and rebuilds byte-identically, segments are text rather than
//! Base64, and cuts land on character boundaries even when every character is
//! multi-byte.
//!
//! The second pins the bounds, which is the half that had no coverage anywhere
//! before 3.3.0 and where the defect was. Each asserts that a hostile message is
//! refused AND that refusing it released whatever it claimed: a reassembler that
//! rejects a segment but keeps its partial forever is still a leak, and the
//! refusal alone cannot show that.

use bonemesh::chunk::{
    self, Reassembler, MAX_CHUNKS, MAX_CONCURRENT_REASSEMBLIES, MAX_REASSEMBLY_BUFFER,
    MAX_SEGMENT_BYTES, REASSEMBLY_TIMEOUT_MILLIS,
};
use bonemesh::message;
use serde_json::{json, Value};

const MID: &str = "0123456789abcdef0123456789abcdef";

fn blob(n: usize) -> String {
    (0..n).map(|i| (b'a' + (i % 26) as u8) as char).collect()
}

fn seg(mid: &str, i: i64, n: i64, s: &str) -> Value {
    message::data_segment(mid, "a", "b", 16, i, n, s)
}

// ---- format ----

#[test]
fn small_payload_travels_whole() {
    let payload = json!({ "line": "hello" });
    let msgs = chunk::split(MID, "a", "b", 16, payload.clone()).unwrap();
    assert_eq!(msgs.len(), 1);
    assert!(msgs[0].get("chunk").is_none(), "a whole message must not carry chunk");
    assert!(msgs[0].get("seg").is_none(), "a whole message must not carry seg");
    assert_eq!(msgs[0]["payload"], payload);
}

#[test]
fn large_payload_splits_and_reassembles() {
    let payload = json!({ "blob": blob(120_000) });
    let msgs = chunk::split(MID, "a", "b", 16, payload.clone()).unwrap();
    assert!(msgs.len() > 1, "large payload was not split");

    for (i, m) in msgs.iter().enumerate() {
        assert_eq!(message::validate("data", m), None, "segment {i} failed the data schema");
        assert!(m.get("payload").is_none(), "segment {i} carries a payload");
        let s = m["seg"].as_str().expect("segment is not a string");
        assert!(s.len() <= MAX_SEGMENT_BYTES, "segment {i} is over the pinned maximum");
    }

    let mut r = Reassembler::new();
    for m in &msgs[..msgs.len() - 1] {
        assert!(r.offer(m, 0).is_none(), "completed early");
    }
    let got = r.offer(&msgs[msgs.len() - 1], 0).expect("never completed");
    assert_eq!(got, payload);
    assert_eq!(r.in_flight(), 0, "a completed message stayed buffered");
    assert_eq!(r.buffered(), 0, "a completed message stayed counted");
}

#[test]
fn segments_are_text_not_base64() {
    // decision #25: a segment is a slice of the payload's JSON text, so it stays
    // readable through the key-log inspector. Concatenation must reproduce the
    // serialized payload with no decode step.
    let payload = json!({ "blob": blob(60_000) });
    let msgs = chunk::split(MID, "a", "b", 16, payload.clone()).unwrap();
    let joined: String = msgs.iter().map(|m| m["seg"].as_str().unwrap()).collect();
    assert_eq!(joined, payload.to_string());
    assert!(
        msgs[0]["seg"].as_str().unwrap().starts_with('{'),
        "the first segment should open the payload's JSON, not a Base64 blob"
    );
}

#[test]
fn cuts_land_on_character_boundaries() {
    // Every character is 3 UTF-8 bytes, so 24000 divides unevenly and a naive
    // byte cut would split one. Rust would panic on a non-boundary slice, so
    // reaching the assertions at all is itself part of the oracle.
    let payload = json!({ "cjk": "日".repeat(40_000) });
    let msgs = chunk::split(MID, "a", "b", 16, payload.clone()).unwrap();
    assert!(msgs.len() > 1);
    for (i, m) in msgs.iter().enumerate() {
        let s = m["seg"].as_str().unwrap();
        assert!(s.len() <= MAX_SEGMENT_BYTES, "segment {i} is over the pinned maximum");
        assert_eq!(s, String::from_utf8(s.as_bytes().to_vec()).unwrap());
    }
    let mut r = Reassembler::new();
    let mut got = None;
    for m in &msgs {
        got = r.offer(m, 0);
    }
    assert_eq!(got.expect("never completed"), payload);
}

#[test]
fn out_of_order_segments_still_reassemble() {
    let payload = json!({ "blob": blob(120_000) });
    let msgs = chunk::split(MID, "a", "b", 16, payload.clone()).unwrap();
    let mut r = Reassembler::new();
    let mut got = None;
    for m in msgs.iter().rev() {
        got = r.offer(m, 0);
    }
    assert_eq!(got.expect("reverse order never completed"), payload);
}

// ---- bounds ----

#[test]
fn absurd_chunk_count_is_refused_before_allocating() {
    // The Java reference sized its buffer on the peer's n before validating it, so
    // one frame claiming two billion segments exhausted the heap. Both oracles
    // matter: the offer is refused, AND nothing was retained, which is what shows
    // no allocation happened.
    let mut r = Reassembler::new();
    for n in [i64::MAX, 2_000_000_000, 1_000_000, MAX_CHUNKS + 1] {
        assert!(r.offer(&seg(MID, 0, n, "x"), 0).is_none(), "accepted n={n}");
        assert_eq!(r.in_flight(), 0, "n={n} was buffered anyway");
        assert_eq!(r.buffered(), 0, "n={n} was counted anyway");
    }
    // The boundary itself is legal, so this is a bound and not a blanket ban.
    r.offer(&seg(MID, 0, MAX_CHUNKS, "x"), 0);
    assert_eq!(r.in_flight(), 1, "the maximum legal chunk count was refused");
}

#[test]
fn malformed_chunk_metadata_is_refused() {
    let mut r = Reassembler::new();
    let mut bad = vec![];
    let mut m = seg(MID, 0, 3, "x");
    m["chunk"] = json!("not-an-object");
    bad.push(m);
    let mut m = seg(MID, 0, 3, "x");
    m["chunk"] = json!({ "i": "zero", "n": 3 });
    bad.push(m);
    let mut m = seg(MID, 0, 3, "x");
    m["chunk"] = json!({ "i": 0 }); // no n
    bad.push(m);
    let mut m = seg(MID, 0, 3, "x");
    m["chunk"] = json!({ "i": 0.5, "n": 3 }); // fractional index
    bad.push(m);
    bad.push(seg(MID, 3, 3, "x")); // i == n
    bad.push(seg(MID, -1, 3, "x")); // i < 0
    bad.push(seg(MID, 0, 0, "x")); // n == 0
    for (k, msg) in bad.iter().enumerate() {
        assert!(r.offer(msg, 0).is_none(), "case {k}: accepted malformed chunk");
        assert_eq!(r.in_flight(), 0, "case {k}: malformed chunk was buffered");
    }
}

#[test]
fn segment_without_its_slice_is_refused() {
    let mut r = Reassembler::new();
    let mut m = seg(MID, 0, 3, "x");
    m.as_object_mut().unwrap().remove("seg");
    assert!(r.offer(&m, 0).is_none());
    assert_eq!(r.in_flight(), 0);
}

#[test]
fn whole_message_claiming_to_be_a_segment_is_not_delivered() {
    // n == 1 with seg instead of payload is malformed, not a one-segment split.
    let mut r = Reassembler::new();
    let m = seg(MID, 0, 1, r#"{"a":1}"#);
    assert!(r.offer(&m, 0).is_none(), "delivered a fragment as a whole payload");
    assert_eq!(message::validate("data", &m), Some("payload-or-seg"));
}

#[test]
fn message_carrying_both_payload_and_segment_is_not_delivered() {
    // Found by mutation. The whole-message path returned the payload whenever one
    // was present, so a message contradicting itself -- payload AND seg -- was
    // delivered. The schema rejects it, but the schema is not on the wire path
    // (decision #27), so the reassembler has to refuse it too.
    let mut r = Reassembler::new();
    let mut both = message::data(MID, "a", "b", 16, json!({ "x": 1 }));
    both["seg"] = json!("{");
    assert!(r.offer(&both, 0).is_none(), "a self-contradicting message was delivered");
    let mut with_chunk = seg(MID, 0, 1, "{");
    with_chunk["payload"] = json!({ "x": 1 });
    assert!(
        r.offer(&with_chunk, 0).is_none(),
        "a self-contradicting n==1 message was delivered"
    );
}

#[test]
fn non_object_chunk_is_refused_even_with_a_payload() {
    // The distinguishing input: a garbage chunk on a message that DOES carry a
    // payload. Java conflated "chunk absent" with "chunk unparseable" and delivered
    // it; nothing tested the case, which is how that survived.
    let mut r = Reassembler::new();
    for garbage in [json!("1/3"), json!(7), json!([])] {
        let mut m = message::data(MID, "a", "b", 16, json!({ "x": 1 }));
        m["chunk"] = garbage.clone();
        assert!(r.offer(&m, 0).is_none(), "delivered a message whose chunk was {garbage}");
        assert!(message::validate("data", &m).is_some(), "the schema accepted chunk {garbage}");
    }
}

#[test]
fn concurrent_reassemblies_are_bounded() {
    let mut r = Reassembler::new();
    for k in 0..MAX_CONCURRENT_REASSEMBLIES {
        r.offer(&seg(&format!("{k:032x}"), 0, 4, "x"), 0);
    }
    assert_eq!(r.in_flight(), MAX_CONCURRENT_REASSEMBLIES);
    r.offer(&seg(&format!("{:032x}", 9999), 0, 4, "x"), 0);
    assert_eq!(r.in_flight(), MAX_CONCURRENT_REASSEMBLIES, "the bound was exceeded");
}

#[test]
fn buffered_bytes_are_bounded() {
    // The in-flight bound (256) is reached long before 16 MiB of segments can be
    // spread across separate message ids, so the byte budget is only reachable
    // inside one message: 1024 segments of 24000 bytes is 24.5 MB, over the
    // ceiling. That is the case to drive.
    let mut r = Reassembler::new();
    let full = "y".repeat(MAX_SEGMENT_BYTES);
    let mut accepted = 0usize;
    for i in 0..MAX_CHUNKS {
        r.offer(&seg(MID, i, MAX_CHUNKS, &full), 0);
        if r.in_flight() == 0 {
            break; // abandoned: the budget refused it
        }
        accepted += 1;
        assert!(r.buffered() <= MAX_REASSEMBLY_BUFFER, "the buffer maximum was exceeded");
    }
    assert_eq!(
        accepted,
        MAX_REASSEMBLY_BUFFER / MAX_SEGMENT_BYTES,
        "the message should be abandoned on the first segment that would not fit"
    );
    assert_eq!(r.in_flight(), 0, "the abandoned message was retained");
    assert_eq!(r.buffered(), 0, "abandoning did not return its bytes");
}

#[test]
fn stale_partials_are_swept() {
    let mut r = Reassembler::new();
    r.offer(&seg(MID, 0, 3, "x"), 1_000);
    assert_eq!(r.in_flight(), 1);
    // Just inside the timeout: still held.
    r.offer(&seg(MID, 1, 3, "y"), 1_000 + REASSEMBLY_TIMEOUT_MILLIS - 1);
    assert_eq!(r.in_flight(), 1, "swept too early");
    // At the timeout: gone, and its bytes back.
    r.offer(&seg(&"1".repeat(32), 0, 3, "z"), 1_000 + REASSEMBLY_TIMEOUT_MILLIS);
    assert_eq!(r.in_flight(), 1, "the stale partial was not swept");
    assert_eq!(r.buffered(), 1, "swept bytes were not returned to the budget");
}

#[test]
fn oversized_payload_fails_at_the_origin() {
    // §6.1: an origin whose payload no conforming destination would reassemble is
    // told locally rather than emitting it.
    let payload = json!({ "blob": blob(MAX_REASSEMBLY_BUFFER + 1) });
    assert!(chunk::split(MID, "a", "b", 16, payload).is_err());
}
