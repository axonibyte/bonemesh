//! BoneMesh v3 message schema validation (protocol.md §4, security.md §4) and
//! inner-message builders. The validator mirrors the Java, Go, and Elixir
//! validators reason-for-reason (shared corpus: spec/corpus/messages.json).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

/// The default hop limit for application data.
pub const DEFAULT_TTL: i64 = 16;

/// Validates a message against a named schema. Returns `None` if valid, else a
/// reason tag. Schemas: `bmx1`, `envelope`, `data`, `ack`, `nak`, `bye`.
pub fn validate(schema: &str, f: &Value) -> Option<&'static str> {
    match schema {
        "bmx1" => validate_bmx1(f),
        "envelope" => validate_envelope(f),
        "data" => validate_data(f),
        "ack" => validate_ack(f),
        "nak" => validate_nak(f),
        "bye" => validate_bye(f),
        _ => Some("unknown-schema"),
    }
}

fn validate_bmx1(f: &Value) -> Option<&'static str> {
    if f["t"].as_str() != Some("bmx1") {
        return Some("type");
    }
    if f["v"].as_i64() != Some(3) {
        return Some("version");
    }
    match f["mesh"].as_str() {
        Some(m) if !m.is_empty() => {}
        _ => return Some("empty-mesh"),
    }
    for k in ["e", "k", "n"] {
        if f.get(k).is_none() {
            return Some("missing-field");
        }
        if let Some(r) = base64_reason(&f[k]) {
            return Some(r);
        }
    }
    None
}

fn validate_envelope(f: &Value) -> Option<&'static str> {
    match f["seq"].as_i64() {
        None => return Some("missing-field"),
        Some(s) if s < 0 => return Some("seq-range"),
        _ => {}
    }
    if f.get("ct").is_none() {
        return Some("missing-field");
    }
    base64_reason(&f["ct"])
}

fn validate_data(f: &Value) -> Option<&'static str> {
    if f["type"].as_str() != Some("data") {
        return Some("type");
    }
    if let Some(r) = mid_reason(&f["mid"]) {
        return Some(r);
    }
    if !f["to"].is_string() || !f["from"].is_string() {
        return Some("missing-field");
    }
    match f["ttl"].as_i64() {
        None => return Some("missing-field"),
        Some(t) if !(1..=255).contains(&t) => return Some("ttl-range"),
        _ => {}
    }
    if f.get("payload").is_none() {
        return Some("missing-field");
    }
    None
}

fn validate_ack(f: &Value) -> Option<&'static str> {
    if f["type"].as_str() != Some("ack") {
        return Some("type");
    }
    mid_reason(&f["mid"])
}

/// A NAK is routed back toward the origin like data (to/from/ttl) and names the
/// failing hop and a reason. The reason string is required but its value is not
/// enum-checked, so an unrecognized reason is accepted (forward-compatible).
fn validate_nak(f: &Value) -> Option<&'static str> {
    if f["type"].as_str() != Some("nak") {
        return Some("type");
    }
    if let Some(r) = mid_reason(&f["mid"]) {
        return Some(r);
    }
    match f["hop"].as_str() {
        Some(h) if !h.is_empty() => {}
        _ => return Some("missing-field"),
    }
    match f["reason"].as_str() {
        Some(r) if !r.is_empty() => {}
        _ => return Some("missing-field"),
    }
    if !f["to"].is_string() || !f["from"].is_string() {
        return Some("missing-field");
    }
    match f["ttl"].as_i64() {
        None => return Some("missing-field"),
        Some(t) if !(1..=255).contains(&t) => return Some("ttl-range"),
        _ => {}
    }
    None
}

/// A graceful session-close control. Link-local (not routed), so only its type
/// is required; an optional reason string is not validated further.
fn validate_bye(f: &Value) -> Option<&'static str> {
    if f["type"].as_str() != Some("bye") {
        return Some("type");
    }
    None
}

fn base64_reason(v: &Value) -> Option<&'static str> {
    match v.as_str() {
        Some(s) if B64.decode(s).is_ok() => None,
        _ => Some("not-base64"),
    }
}

fn mid_reason(v: &Value) -> Option<&'static str> {
    match v.as_str() {
        Some(s) if s.len() == 32 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) => None,
        _ => Some("mid-format"),
    }
}

/// A fresh 128-bit message id as 32 lowercase-hex characters.
pub fn new_mid() -> String {
    use rand_core::RngCore;
    let mut id = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut id);
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// An application data message.
pub fn data(mid: &str, from: &str, to: &str, ttl: i64, payload: Value) -> Value {
    json!({"type":"data","mid":mid,"from":from,"to":to,"ttl":ttl,"payload":payload})
}

/// An acknowledgement for a message id.
pub fn ack(mid: &str) -> Value {
    json!({"type":"ack","mid":mid})
}

/// A negative acknowledgement naming the hop that failed and why, routed back
/// toward the origin (protocol.md §7).
pub fn nak(mid: &str, from: &str, to: &str, hop: &str, reason: &str, ttl: i64) -> Value {
    json!({"type":"nak","mid":mid,"hop":hop,"reason":reason,"from":from,"to":to,"ttl":ttl})
}

/// A graceful session-close control. A reason is optional; `None` omits it,
/// defaulting to a plain shutdown.
pub fn bye(reason: Option<&str>) -> Value {
    match reason {
        Some(r) => json!({"type":"bye","reason":r}),
        None => json!({"type":"bye"}),
    }
}

/// A latency probe with an opaque token.
pub fn probe(token: i64) -> Value {
    json!({"type":"probe","token":token})
}

/// The echo response to a probe.
pub fn echo(token: i64) -> Value {
    json!({"type":"echo","token":token})
}

/// A discovery advertisement (label -> path cost).
pub fn disco(routes: Value) -> Value {
    json!({"type":"disco","routes":routes})
}
