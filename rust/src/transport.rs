//! The encrypted transport channel over a completed handshake (protocol.md §4):
//! each frame is a sequence-numbered AEAD carrier `{"seq":n,"ct":...}` whose
//! plaintext is the inner JSON message. The per-direction sequence is the
//! ChaCha20-Poly1305 nonce (4 zero bytes then the 64-bit little-endian counter),
//! never reused; reordered or replayed frames are rejected. Matches the shared
//! transport-frame vector.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

use crate::crypto;
use crate::handshake::Session;

/// A transport session.
pub struct Transport {
    send_key: Vec<u8>,
    receive_key: Vec<u8>,
    send_seq: u64,
    receive_seq: u64,
}

impl Transport {
    /// Builds a transport session from a completed handshake session.
    pub fn new(session: &Session) -> Self {
        Transport {
            send_key: session.send_key.clone(),
            receive_key: session.receive_key.clone(),
            send_seq: 0,
            receive_seq: 0,
        }
    }

    /// Seals an inner message into a `{seq, ct}` carrier.
    pub fn seal(&mut self, inner: &Value) -> Value {
        let seq = self.send_seq;
        let ct = seal_ciphertext(&self.send_key, seq, serde_json::to_string(inner).unwrap().as_bytes());
        self.send_seq += 1;
        json!({"seq":seq,"ct":B64.encode(ct)})
    }

    /// Opens a carrier, enforcing in-order delivery. Returns the inner message.
    pub fn open(&mut self, carrier: &Value) -> Result<Value, String> {
        let seq = carrier["seq"].as_u64().ok_or("missing seq")?;
        if seq != self.receive_seq {
            return Err(format!("out-of-order frame: expected {}, got {}", self.receive_seq, seq));
        }
        let ct = B64.decode(carrier["ct"].as_str().ok_or("missing ct")?).map_err(|_| "bad ct")?;
        let pt = crypto::aead_open(&self.receive_key, &nonce(seq), &[], &ct)
            .ok_or("frame authentication failed")?;
        self.receive_seq += 1;
        serde_json::from_slice(&pt).map_err(|_| "bad inner json".into())
    }
}

/// Seals a transport-frame ciphertext (the single AEAD implementation).
pub fn seal_ciphertext(key: &[u8], seq: u64, plaintext: &[u8]) -> Vec<u8> {
    crypto::aead_seal(key, &nonce(seq), &[], plaintext)
}

fn nonce(seq: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..12].copy_from_slice(&seq.to_le_bytes());
    n
}
