//! The BoneMesh restricted-JCS certificate canonicalization (security.md
//! §11.1): the exact byte string the mesh root signs. Byte-for-byte identical
//! to the Java, Go, and Elixir implementations over the shared corpus
//! (spec/corpus/canon.json) — cross-language signature verification depends on
//! it.
//!
//! A certificate contains only JSON strings and non-negative integers, so this
//! is a small subset of RFC 8785: keys sorted by UTF-16 code unit, minimal
//! string escaping, integers in shortest form.

use serde_json::{Map, Value};

/// Canonicalizes a certificate object, dropping any `sig` member. Returns the
/// canonical UTF-8 string, or an error if the object contains a value a
/// certificate may not (float, negative, bool, null, array).
pub fn canonicalize(cert: &Value) -> Result<String, String> {
    let obj = cert.as_object().ok_or("certificate is not an object")?;
    encode_object(obj)
}

fn encode_object(obj: &Map<String, Value>) -> Result<String, String> {
    let mut keys: Vec<&String> = obj.keys().filter(|k| k.as_str() != "sig").collect();
    keys.sort_by(|a, b| utf16(a).cmp(&utf16(b)));

    let mut out = String::from("{");
    for (i, k) in keys.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        encode_string(&mut out, k);
        out.push(':');
        encode_value(&mut out, &obj[k.as_str()])?;
    }
    out.push('}');
    Ok(out)
}

fn encode_value(out: &mut String, v: &Value) -> Result<(), String> {
    match v {
        Value::String(s) => {
            encode_string(out, s);
            Ok(())
        }
        Value::Number(n) => match n.as_u64() {
            Some(u) => {
                out.push_str(&u.to_string());
                Ok(())
            }
            None => Err(format!("certificate number {n} is not a non-negative integer")),
        },
        Value::Object(o) => {
            out.push_str(&encode_object(o)?);
            Ok(())
        }
        other => Err(format!("value {other} is not permitted in a certificate")),
    }
}

fn encode_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{0009}' => out.push_str("\\t"),
            '\u{000a}' => out.push_str("\\n"),
            '\u{000c}' => out.push_str("\\f"),
            '\u{000d}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}
