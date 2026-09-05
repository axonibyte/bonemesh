//! The BoneMesh v3 frame reader/writer (protocol.md §2): one newline-terminated
//! UTF-8 JSON object per frame, within a hard size cap — the enforcement point
//! for defect D7. Classification verdicts match the shared corpus
//! (spec/corpus/framing.json), so a node in any language agrees on which frames
//! are well formed.

use serde::Deserialize;
use serde_json::Value;

/// Maximum handshake frame size in bytes (including the newline).
pub const HANDSHAKE_CAP: usize = 32768;
/// Maximum transport frame size in bytes (including the newline).
pub const TRANSPORT_CAP: usize = 65536;

/// The outcome of classifying a frame.
#[derive(Debug)]
pub enum Verdict {
    /// Accepted: the decoded object.
    Accept(Value),
    /// Rejected, with a reason tag matching the corpus.
    Reject(&'static str),
}

/// Classifies the first frame in `raw` against `cap`, reading only up to the
/// first newline.
pub fn classify(raw: &[u8], cap: usize) -> Verdict {
    let Some(nl) = raw.iter().position(|&b| b == b'\n') else {
        return Verdict::Reject("no-newline");
    };
    if nl + 1 > cap {
        return Verdict::Reject("oversize");
    }
    let content = &raw[..nl];
    if content.is_empty() {
        return Verdict::Reject("empty");
    }
    let Ok(text) = std::str::from_utf8(content) else {
        return Verdict::Reject("invalid-utf8");
    };
    match text.as_bytes()[0] {
        b'[' => return Verdict::Reject("not-an-object"),
        b'{' => {}
        _ => return Verdict::Reject("invalid-json"),
    }

    let mut de = serde_json::Deserializer::from_str(text);
    let value = match Value::deserialize(&mut de) {
        Ok(v) => v,
        Err(_) => return Verdict::Reject("invalid-json"),
    };
    if de.end().is_err() {
        return Verdict::Reject("trailing-data");
    }
    if !value.is_object() {
        return Verdict::Reject("not-an-object");
    }
    Verdict::Accept(value)
}

/// Encodes an object as a frame body followed by a single newline.
pub fn encode(object: &Value) -> Vec<u8> {
    let mut out = serde_json::to_vec(object).expect("serialize frame");
    out.push(b'\n');
    out
}
