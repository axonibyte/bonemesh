//! Splitting and reassembly of oversized application payloads (protocol.md §6.1).
//!
//! A payload too large for one transport frame is serialized, its UTF-8 bytes cut
//! into segments of at most [`MAX_SEGMENT_BYTES`] on character boundaries, and
//! each segment sent as a data message sharing one message id, carrying
//! `chunk {i, n}` and a top-level `seg` string and **no** `payload`. A payload
//! that fits travels whole, with `payload` and no `seg`.
//!
//! Segments are text, not Base64: §0's Base64 rule covers binary fields, a slice
//! of JSON text is already UTF-8, and a JSON string carries it directly, so a
//! split message stays readable through the key-log inspector (decisions #3, #5,
//! #25). Cutting on a byte budget rather than a character count is what keeps the
//! split identical across the seven implementations, because UTF-8 has no
//! surrogates, so a code point is either wholly inside a segment or wholly
//! outside it.

use std::collections::HashMap;

use serde_json::Value;

use crate::message;

/// Maximum payload bytes carried by one segment (protocol.md §0).
pub const MAX_SEGMENT_BYTES: usize = 24000;
/// Maximum segments one application message may be split into (§0).
pub const MAX_CHUNKS: i64 = 1024;
/// Maximum segment bytes buffered at once, across every in-flight message (§0).
pub const MAX_REASSEMBLY_BUFFER: usize = 16777216;
/// Maximum messages that may be mid-reassembly at once (§0).
pub const MAX_CONCURRENT_REASSEMBLIES: usize = 256;
/// Milliseconds a partially-filled message may sit before being discarded (§0).
pub const REASSEMBLY_TIMEOUT_MILLIS: i64 = 30000;

/// Splits a payload into one whole data message or a series of segments.
///
/// `Err` means no conforming destination would reassemble it, so the caller is
/// told locally rather than the mesh carrying a message that cannot arrive
/// (§6.1, Bounds).
pub fn split(mid: &str, from: &str, to: &str, ttl: i64, payload: Value) -> Result<Vec<Value>, String> {
    let src = payload.to_string();
    let bytes = src.as_bytes();
    if bytes.len() <= MAX_SEGMENT_BYTES {
        return Ok(vec![message::data(mid, from, to, ttl, payload)]);
    }
    if bytes.len() > MAX_REASSEMBLY_BUFFER {
        return Err(format!(
            "payload of {} bytes exceeds the reassembly buffer maximum of {}",
            bytes.len(),
            MAX_REASSEMBLY_BUFFER
        ));
    }

    let mut segments: Vec<&str> = Vec::new();
    let mut pos = 0usize;
    while pos < bytes.len() {
        let end = char_boundary(bytes, pos, (pos + MAX_SEGMENT_BYTES).min(bytes.len()));
        // The cut is on a character boundary, so this slice is valid UTF-8.
        segments.push(std::str::from_utf8(&bytes[pos..end]).map_err(|e| e.to_string())?);
        pos = end;
    }
    if segments.len() as i64 > MAX_CHUNKS {
        return Err(format!(
            "payload needs {} segments, over the maximum of {}",
            segments.len(),
            MAX_CHUNKS
        ));
    }

    let n = segments.len();
    Ok(segments
        .into_iter()
        .enumerate()
        .map(|(i, seg)| message::data_segment(mid, from, to, ttl, i as i64, n as i64, seg))
        .collect())
}

/// Walks a proposed cut back to the nearest character boundary at or before it,
/// so a segment never ends mid-character and is itself valid UTF-8.
fn char_boundary(src: &[u8], start: usize, end: usize) -> usize {
    if end >= src.len() {
        return end; // the tail is always a boundary
    }
    let mut e = end;
    while e > start && src[e] & 0xC0 == 0x80 {
        // 10xxxxxx is a continuation byte
        e -= 1;
    }
    // A UTF-8 character is at most 4 bytes and a segment is 24000, so e cannot
    // reach start from well-formed input; falling back keeps a malformed
    // serializer from producing a zero-length segment and looping forever.
    if e > start {
        e
    } else {
        end
    }
}

struct Partial {
    segments: Vec<Option<String>>,
    received: usize,
    bytes: usize,
    started: i64,
}

/// Rebuilds split payloads at the destination, the counterpart to [`split`].
///
/// Every §0 bound is enforced **before** any allocation keyed on a number the
/// peer chose. That ordering is the point: the Java reference sized its buffer on
/// the peer's `n` and validated afterwards, so one frame claiming two billion
/// segments exhausted the heap — defect D7 reintroduced by the feature meant to
/// fix it.
///
/// Three bounds, none redundant. The byte budget caps one large message; the
/// in-flight count caps a flood of distinct ids each carrying an *empty* segment,
/// which costs nothing against a byte budget and still costs memory; the timeout
/// stops an abandoned message pinning memory for the session's life.
#[derive(Default)]
pub struct Reassembler {
    partials: HashMap<String, Partial>,
    order: Vec<String>,
    buffered: usize,
}

impl Reassembler {
    /// A new, empty reassembler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds one inbound data message, returning the payload when a message
    /// completes. `now_millis` is passed in rather than read so the timeout is
    /// testable without sleeping.
    pub fn offer(&mut self, msg: &Value, now_millis: i64) -> Option<Value> {
        self.sweep(now_millis);

        let chunk = msg.get("chunk");
        // chunk absent means a whole message; chunk present but not an object, or
        // with a non-integer n, is malformed and refused.
        let n: i64 = match chunk {
            None => 1,
            Some(raw) => raw.as_object().and_then(|o| o.get("n")).and_then(Value::as_i64)?,
        };
        if chunk.is_none() || n == 1 {
            // A whole message carries payload and no seg. One claiming n == 1
            // while carrying seg instead is malformed, not a one-segment split.
            return match msg.get("payload") {
                Some(p) if msg.get("seg").is_none() => Some(p.clone()),
                _ => None,
            };
        }

        // Bounds first, allocation second.
        let i = chunk.and_then(|c| c.get("i")).and_then(Value::as_i64)?;
        if !(1..=MAX_CHUNKS).contains(&n) || i < 0 || i >= n {
            return None;
        }
        // A segment without its slice is refused.
        let seg = msg.get("seg").and_then(|v| v.as_str())?.to_string();
        let mid = msg.get("mid").and_then(|v| v.as_str())?.to_string();

        let n_usize = n as usize;
        if !self.partials.contains_key(&mid) {
            if self.partials.len() >= MAX_CONCURRENT_REASSEMBLIES {
                return None;
            }
            self.partials.insert(
                mid.clone(),
                Partial { segments: vec![None; n_usize], received: 0, bytes: 0, started: now_millis },
            );
            self.order.push(mid.clone());
        } else if self.partials[&mid].segments.len() != n_usize {
            self.discard(&mid); // the peer changed n mid-message
            return None;
        }

        let idx = i as usize;
        let fresh = self.partials[&mid].segments[idx].is_none();
        if fresh {
            if self.buffered + seg.len() > MAX_REASSEMBLY_BUFFER {
                self.discard(&mid);
                return None;
            }
            self.buffered += seg.len();
            let p = self.partials.get_mut(&mid).unwrap();
            p.bytes += seg.len();
            p.received += 1;
            p.segments[idx] = Some(seg);
        }
        if self.partials[&mid].received != n_usize {
            return None;
        }

        let joined: String = self.partials[&mid]
            .segments
            .iter()
            .map(|s| s.as_deref().unwrap_or(""))
            .collect();
        self.discard(&mid);
        serde_json::from_str(&joined).ok()
    }

    /// Messages currently mid-reassembly. Exposed for the tests that assert the
    /// bounds release memory rather than merely refusing to add to it -- a
    /// reassembler that rejects a segment but keeps its partial forever is still a
    /// leak, and the refusal alone cannot show that.
    pub fn in_flight(&self) -> usize {
        self.partials.len()
    }

    /// Segment bytes held across every in-flight message.
    pub fn buffered(&self) -> usize {
        self.buffered
    }

    fn discard(&mut self, mid: &str) {
        if let Some(p) = self.partials.remove(mid) {
            self.buffered -= p.bytes;
        }
        self.order.retain(|m| m != mid);
    }

    fn sweep(&mut self, now_millis: i64) {
        while let Some(mid) = self.order.first().cloned() {
            match self.partials.get(&mid) {
                None => {
                    self.order.remove(0);
                }
                Some(p) if now_millis - p.started >= REASSEMBLY_TIMEOUT_MILLIS => {
                    self.discard(&mid);
                }
                Some(_) => break, // insertion-ordered: the rest are younger
            }
        }
    }
}

