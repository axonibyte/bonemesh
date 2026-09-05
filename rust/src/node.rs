//! A BoneMesh v3 mesh node (protocol.md §3) over std TCP: one authenticated,
//! encrypted session per neighbor, each owned by a reader thread, with
//! application payloads delivered to registered listeners. Wire-compatible with
//! the Java, Elixir, and Go implementations.
//!
//! This node does direct neighbor delivery (sufficient for two-party
//! interop and the matrix); distance-vector relay, discovery, and chunking are
//! shared with the other implementations and tracked as follow-up parity work.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::Value;

use crate::handshake::Handshake;
use crate::transport::Transport;
use crate::{frame, message};

/// A node configuration and identity.
#[derive(Clone)]
pub struct Config {
    pub label: String,
    pub mesh: String,
    pub root_public: Vec<u8>,
    pub cert: Value,
    pub id_private: [u8; 32],
}

struct Link {
    write: TcpStream,
    transport: Transport,
}

struct Inner {
    config: Config,
    links: Mutex<HashMap<String, Arc<Mutex<Link>>>>,
    listeners: Mutex<Vec<Sender<Value>>>,
}

/// A running node.
pub struct Node {
    inner: Arc<Inner>,
    port: u16,
}

impl Node {
    /// Starts a node listening on `port` (0 for an ephemeral port).
    pub fn start(config: Config, port: u16) -> std::io::Result<Node> {
        let listener = TcpListener::bind(("0.0.0.0", port))?;
        let port = listener.local_addr()?.port();
        let inner = Arc::new(Inner {
            config,
            links: Mutex::new(HashMap::new()),
            listeners: Mutex::new(Vec::new()),
        });

        let accept_inner = inner.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                if let Ok(stream) = stream {
                    let inner = accept_inner.clone();
                    thread::spawn(move || {
                        let _ = respond(&inner, stream);
                    });
                }
            }
        });

        Ok(Node { inner, port })
    }

    /// The port this node listens on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Registers a listener; delivered payloads are sent on the returned channel.
    pub fn add_listener(&self) -> std::sync::mpsc::Receiver<Value> {
        let (tx, rx) = channel();
        self.inner.listeners.lock().unwrap().push(tx);
        rx
    }

    /// Dials a peer and completes the handshake as initiator. Returns the peer label.
    pub fn connect(&self, host: &str, port: u16) -> Result<String, String> {
        let stream = TcpStream::connect((host, port)).map_err(|e| e.to_string())?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
        let mut write = stream;

        let c = &self.inner.config;
        let now = now_secs();
        let mut hs = Handshake::initiator(&c.mesh, &c.root_public, now, c.cert.clone(), c.id_private);
        write.write_all(&hs.write_message1()).map_err(|e| e.to_string())?;
        write.flush().ok();
        let m2 = read_line(&mut reader)?;
        let m3 = hs.read_message2_write_message3(&m2)?;
        write.write_all(&m3).map_err(|e| e.to_string())?;
        write.flush().ok();

        let peer = hs.session().peer_cert["label"].as_str().unwrap_or("").to_string();
        register(&self.inner, &peer, write, reader, Transport::new(hs.session()));
        Ok(peer)
    }

    /// Sends an application payload to a direct neighbor. Returns true if sent.
    pub fn send(&self, to: &str, payload: Value) -> bool {
        let mid = message::new_mid();
        let msg = message::data(&mid, &self.inner.config.label, to, message::DEFAULT_TTL, payload);
        send_to_link(&self.inner, to, &msg)
    }
}

fn respond(inner: &Arc<Inner>, stream: TcpStream) -> Result<(), String> {
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let mut write = stream;
    let c = &inner.config;
    let now = now_secs();
    let mut hs = Handshake::responder(&c.mesh, &c.root_public, now, c.cert.clone(), c.id_private);

    let m1 = read_line(&mut reader)?;
    let m2 = hs.read_message1_write_message2(&m1)?;
    write.write_all(&m2).map_err(|e| e.to_string())?;
    write.flush().ok();
    let m3 = read_line(&mut reader)?;
    hs.read_message3(&m3)?;

    let peer = hs.session().peer_cert["label"].as_str().unwrap_or("").to_string();
    register(inner, &peer, write, reader, Transport::new(hs.session()));
    Ok(())
}

// Registers a link and spawns its reader thread.
fn register(inner: &Arc<Inner>, peer: &str, write: TcpStream, reader: BufReader<TcpStream>, transport: Transport) {
    let link = Arc::new(Mutex::new(Link { write, transport }));
    inner.links.lock().unwrap().insert(peer.to_lowercase(), link.clone());

    let inner = inner.clone();
    let peer = peer.to_string();
    thread::spawn(move || read_loop(inner, peer, reader, link));
}

fn read_loop(inner: Arc<Inner>, peer: String, mut reader: BufReader<TcpStream>, link: Arc<Mutex<Link>>) {
    loop {
        let raw = match read_line(&mut reader) {
            Ok(r) => r,
            Err(_) => break,
        };
        let carrier: Value = match serde_json::from_slice(&raw) {
            Ok(v) => v,
            Err(_) => break,
        };
        let inner_msg = {
            let mut l = link.lock().unwrap();
            match l.transport.open(&carrier) {
                Ok(v) => v,
                Err(_) => continue,
            }
        };
        handle_inner(&inner, &peer, inner_msg);
    }
}

fn handle_inner(inner: &Arc<Inner>, peer: &str, msg: Value) {
    match msg["type"].as_str() {
        Some("data") => {
            let payload = msg["payload"].clone();
            for tx in inner.listeners.lock().unwrap().iter() {
                let _ = tx.send(payload.clone());
            }
        }
        Some("probe") => {
            if let Some(token) = msg["token"].as_i64() {
                send_to_link(inner, peer, &message::echo(token));
            }
        }
        _ => {}
    }
}

fn send_to_link(inner: &Arc<Inner>, label: &str, inner_msg: &Value) -> bool {
    let link = { inner.links.lock().unwrap().get(&label.to_lowercase()).cloned() };
    match link {
        None => false,
        Some(link) => {
            let mut l = link.lock().unwrap();
            let carrier = l.transport.seal(inner_msg);
            let bytes = frame::encode(&carrier);
            l.write.write_all(&bytes).and_then(|_| l.write.flush()).is_ok()
        }
    }
}

fn read_line(reader: &mut BufReader<TcpStream>) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let n = reader.read_until(b'\n', &mut buf).map_err(|e| e.to_string())?;
    if n == 0 {
        return Err("stream closed".into());
    }
    Ok(buf)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
