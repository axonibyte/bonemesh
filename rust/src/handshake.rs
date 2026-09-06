//! The BMX handshake (security.md §4): a three-message, mutually authenticated,
//! forward-secret exchange. Hybrid X25519 + ML-KEM-768 forward secrecy through
//! the key schedule; authentication by a root-signed certificate plus an ML-DSA
//! signature over the live transcript. Field-for-field identical to the Java,
//! Elixir, and Go implementations, so a Rust node completes a handshake with any
//! of them.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};

use crate::{cert, crypto, keyschedule::KeySchedule};

const VERSION: i64 = 3;

/// A completed session: the two directional transport keys and the peer's
/// verified certificate.
pub struct Session {
    pub send_key: Vec<u8>,
    pub receive_key: Vec<u8>,
    pub peer_cert: Value,
    /// Final transcript hash of the handshake — a per-session identifier (both
    /// ends agree on it) used to label key-log entries (security.md §8).
    pub h: [u8; 32],
}

/// A single-use handshake, threaded through the step methods. The role
/// (initiator or responder) is implicit in which step methods the caller
/// invokes, as in the other implementations.
pub struct Handshake {
    mesh: String,
    root_public: Vec<u8>,
    now: i64,
    cert: Value,
    id_private: [u8; 32],
    ks: KeySchedule,
    eph_dh_priv: [u8; 32],
    eph_dh_pub: [u8; 32],
    eph_kem_ek: Vec<u8>,
    eph_kem_dk: Vec<u8>,
    session: Option<Session>,
}

impl Handshake {
    /// Creates the initiating side.
    pub fn initiator(mesh: &str, root_public: &[u8], now: i64, cert: Value, id_private: [u8; 32]) -> Self {
        Self::new(mesh, root_public, now, cert, id_private)
    }

    /// Creates the responding side.
    pub fn responder(mesh: &str, root_public: &[u8], now: i64, cert: Value, id_private: [u8; 32]) -> Self {
        Self::new(mesh, root_public, now, cert, id_private)
    }

    fn new(mesh: &str, root_public: &[u8], now: i64, cert: Value, id_private: [u8; 32]) -> Self {
        let mut ks = KeySchedule::new();
        ks.mix_hash(mesh.as_bytes());
        Handshake {
            mesh: mesh.to_string(),
            root_public: root_public.to_vec(),
            now,
            cert,
            id_private,
            ks,
            eph_dh_priv: [0u8; 32],
            eph_dh_pub: [0u8; 32],
            eph_kem_ek: Vec::new(),
            eph_kem_dk: Vec::new(),
            session: None,
        }
    }

    /// Initiator: produces message 1.
    pub fn write_message1(&mut self) -> Vec<u8> {
        let (dh_pub, dh_priv) = crypto::x25519_generate();
        let (kem_ek, kem_dk) = crypto::mlkem_generate();
        let mut n = [0u8; 32];
        OsRng.fill_bytes(&mut n);

        self.ks.mix_hash(&dh_pub);
        self.ks.mix_hash(&kem_ek);
        self.ks.mix_hash(&n);

        self.eph_dh_pub = dh_pub;
        self.eph_dh_priv = dh_priv;
        self.eph_kem_ek = kem_ek.clone();
        self.eph_kem_dk = kem_dk;

        line(&json!({
            "t":"bmx1","v":VERSION,"mesh":self.mesh,
            "e":B64.encode(dh_pub),"k":B64.encode(&kem_ek),"n":B64.encode(n)
        }))
    }

    /// Responder: consumes message 1, produces message 2.
    pub fn read_message1_write_message2(&mut self, msg1: &[u8]) -> Result<Vec<u8>, String> {
        let m = decode(msg1)?;
        if m["t"].as_str() != Some("bmx1") {
            return Err("expected bmx1".into());
        }
        if m["v"].as_i64() != Some(VERSION) {
            return Err("unsupported version".into());
        }
        if m["mesh"].as_str() != Some(self.mesh.as_str()) {
            return Err("mesh mismatch".into());
        }
        let ei_pub = b64(&m["e"])?;
        let ki_ek = b64(&m["k"])?;
        let n = b64(&m["n"])?;
        self.ks.mix_hash(&ei_pub);
        self.ks.mix_hash(&ki_ek);
        self.ks.mix_hash(&n);

        let (er_pub, er_priv) = crypto::x25519_generate();
        self.ks.mix_hash(&er_pub);
        let ss_dh = crypto::x25519_agree(&er_priv, &arr32(&ei_pub)?);
        self.ks.mix_key(&ss_dh);

        let (ss_kem, ct) = crypto::mlkem_encapsulate(&ki_ek);
        self.ks.mix_hash(&ct);
        self.ks.mix_key(&ss_kem);

        let auth = self.seal_identity();
        Ok(line(&json!({
            "t":"bmx2","e":B64.encode(er_pub),"ct":B64.encode(&ct),"auth":B64.encode(&auth)
        })))
    }

    /// Initiator: consumes message 2 (verifying the responder), produces message 3.
    pub fn read_message2_write_message3(&mut self, msg2: &[u8]) -> Result<Vec<u8>, String> {
        let m = decode(msg2)?;
        let er_pub = b64(&m["e"])?;
        let ct = b64(&m["ct"])?;
        let auth = b64(&m["auth"])?;

        self.ks.mix_hash(&er_pub);
        let ss_dh = crypto::x25519_agree(&self.eph_dh_priv, &arr32(&er_pub)?);
        self.ks.mix_key(&ss_dh);
        self.ks.mix_hash(&ct);
        let ss_kem = crypto::mlkem_decapsulate(&self.eph_kem_dk, &ct);
        self.ks.mix_key(&ss_kem);

        let peer_cert = self.open_identity(&auth)?;
        let auth_i = self.seal_identity();
        let out = line(&json!({"t":"bmx3","auth":B64.encode(&auth_i)}));

        let (i2r, r2i) = self.ks.split();
        self.session = Some(Session { send_key: i2r.to_vec(), receive_key: r2i.to_vec(), peer_cert, h: self.ks.h });
        Ok(out)
    }

    /// Responder: consumes message 3, completing the handshake.
    pub fn read_message3(&mut self, msg3: &[u8]) -> Result<(), String> {
        let m = decode(msg3)?;
        let auth = b64(&m["auth"])?;
        let peer_cert = self.open_identity(&auth)?;
        let (i2r, r2i) = self.ks.split();
        self.session = Some(Session { send_key: r2i.to_vec(), receive_key: i2r.to_vec(), peer_cert, h: self.ks.h });
        Ok(())
    }

    /// The completed session.
    pub fn session(&self) -> &Session {
        self.session.as_ref().expect("handshake not complete")
    }

    fn seal_identity(&mut self) -> Vec<u8> {
        let sig = crypto::mldsa65_sign(&self.id_private, &self.ks.h);
        let payload = json!({"cert":self.cert,"sig":B64.encode(sig)});
        self.ks.encrypt_and_hash(serde_json::to_string(&payload).unwrap().as_bytes())
    }

    fn open_identity(&mut self, auth: &[u8]) -> Result<Value, String> {
        let h_pre = self.ks.h;
        let plaintext = self.ks.decrypt_and_hash(auth).ok_or("handshake authentication failed")?;
        let payload: Value = serde_json::from_slice(&plaintext).map_err(|_| "bad auth payload")?;
        let peer_cert = payload["cert"].clone();
        cert::verify(&peer_cert, &self.root_public, &self.mesh, self.now)
            .map_err(|e| format!("peer certificate invalid: {e}"))?;
        let sig = b64(&payload["sig"])?;
        let idk = cert::identity_key(&peer_cert)?;
        if crypto::mldsa65_verify(&idk, &h_pre, &sig) {
            Ok(peer_cert)
        } else {
            Err("peer transcript signature does not verify".into())
        }
    }
}

fn line(v: &Value) -> Vec<u8> {
    let mut out = serde_json::to_vec(v).unwrap();
    out.push(b'\n');
    out
}

fn decode(bytes: &[u8]) -> Result<Value, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "invalid utf8")?;
    serde_json::from_str(text.trim()).map_err(|_| "invalid json".into())
}

fn b64(v: &Value) -> Result<Vec<u8>, String> {
    B64.decode(v.as_str().ok_or("expected base64 string")?).map_err(|_| "bad base64".into())
}

fn arr32(v: &[u8]) -> Result<[u8; 32], String> {
    v.try_into().map_err(|_| "expected 32 bytes".into())
}
