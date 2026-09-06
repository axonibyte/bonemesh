//! A BoneMesh v3 mesh node (protocol.md §3, §5) over std TCP: one
//! authenticated, encrypted session per neighbor, each owned by a reader
//! thread. It routes — distance-vector discovery over a 1 s heartbeat
//! (probe/echo for link latency, disco for route advertisement with poisoned
//! reverse), relays data toward a next hop with TTL, and delivers payloads
//! addressed to itself, deduping by message id. Wire-compatible with the
//! Java, Elixir, Go, JS, and PHP implementations.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};

use crate::handshake::Handshake;
use crate::routing;
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
    /// Whether this node dialed the connection this link runs over
    /// (protocol.md §3: the simultaneous-dial tiebreak needs to know who
    /// initiated each competing session).
    initiator: bool,
    /// When the handshake completed, in unix millis.
    established_at: i64,
    /// Unix-millis time of the last successfully opened inbound frame —
    /// any authenticated frame proves the peer is alive.
    last_inbound: i64,
    /// Unix-millis time of the last data frame sent over or received on this
    /// link (probe/echo/disco never count as activity).
    last_data: i64,
}

struct Inner {
    config: Config,
    tun: Tunables,
    links: Mutex<HashMap<String, Arc<Mutex<Link>>>>,
    listeners: Mutex<Vec<Sender<Value>>>,
    ack_listeners: Mutex<Vec<Sender<Value>>>,
    table: Mutex<routing::Table>,
    dedup: Mutex<routing::Dedup>,
    stop: AtomicBool,
}

/// Operational knobs (protocol.md §0): local behavior, never part of the wire
/// contract, read once from the environment at node start.
struct Tunables {
    probe_timeout_ms: i64,
    idle_ms: i64,
    retry_base_ms: i64,
    retry_cap_ms: i64,
    retry_max_ms: i64,
    rekey_ms: i64,
    rekey_frames: i64,
    rekey_timeout_ms: i64,
    keylog_path: String,
}

fn load_tunables() -> Tunables {
    Tunables {
        probe_timeout_ms: env_i64("BONEMESH_PROBE_TIMEOUT_MS", 15000),
        idle_ms: env_i64("BONEMESH_IDLE_MS", 0),
        retry_base_ms: env_i64("BONEMESH_RETRY_BASE_MS", 500),
        retry_cap_ms: env_i64("BONEMESH_RETRY_CAP_MS", 30000),
        retry_max_ms: env_i64("BONEMESH_RETRY_MAX_MS", 60000),
        rekey_ms: env_i64("BONEMESH_REKEY_MS", 3600000),
        rekey_frames: env_i64("BONEMESH_REKEY_FRAMES", 65536),
        rekey_timeout_ms: env_i64("BONEMESH_REKEY_TIMEOUT_MS", 10000),
        keylog_path: std::env::var("BONEMESH_KEYLOG").unwrap_or_default(),
    }
}

fn env_i64(name: &str, fallback: i64) -> i64 {
    match std::env::var(name) {
        Ok(v) => v.parse().unwrap_or(fallback),
        Err(_) => fallback,
    }
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
        let label = config.label.clone();
        let inner = Arc::new(Inner {
            config,
            tun: load_tunables(),
            links: Mutex::new(HashMap::new()),
            listeners: Mutex::new(Vec::new()),
            ack_listeners: Mutex::new(Vec::new()),
            table: Mutex::new(routing::Table::new(&label)),
            dedup: Mutex::new(routing::Dedup::new(4096)),
            stop: AtomicBool::new(false),
        });

        let hb_inner = inner.clone();
        thread::spawn(move || heartbeat(hb_inner));

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
        // Handshake done: drop the dial read-timeout so it cannot masquerade
        // as a liveness timer; liveness is the probe-timeout's job.
        write.set_read_timeout(None).ok();
        let _ = register(&self.inner, &peer, write, reader, Transport::new(hs.session()), true);
        Ok(peer)
    }

    /// Routes an application payload toward any reachable destination. Returns
    /// true if the message was handed to a next hop.
    pub fn send(&self, to: &str, payload: Value) -> bool {
        self.send_mid(to, payload).is_some()
    }

    /// Send that also returns the message id, so a caller can correlate the
    /// ack/nak delivered to `add_ack_listener` (protocol.md §7). Returns None if
    /// there is no route.
    pub fn send_mid(&self, to: &str, payload: Value) -> Option<String> {
        self.send_with_ttl(to, payload, message::DEFAULT_TTL)
    }

    /// Send with an explicit initial TTL — used by tests to force a relay to
    /// exhaust the hop limit and emit a NAK.
    pub fn send_with_ttl(&self, to: &str, payload: Value, ttl: i64) -> Option<String> {
        let mid = message::new_mid();
        let msg = message::data(&mid, &self.inner.config.label, to, ttl, payload);
        let nh = self.inner.table.lock().unwrap().next_hop(to)?;
        if send_to_link(&self.inner, &nh, &msg) {
            Some(mid)
        } else {
            None
        }
    }

    /// Registers an ack listener; ack and nak messages addressed to this node
    /// (the origin) are sent on the returned channel as the raw inner value.
    pub fn add_ack_listener(&self) -> std::sync::mpsc::Receiver<Value> {
        let (tx, rx) = channel();
        self.inner.ack_listeners.lock().unwrap().push(tx);
        rx
    }

    /// A snapshot of learned destinations to their next hop.
    pub fn route_table(&self) -> HashMap<String, String> {
        self.inner.table.lock().unwrap().route_table()
    }

    /// Stops the node's heartbeat.
    pub fn kill(&self) {
        self.inner.stop.store(true, Ordering::SeqCst);
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
    // Handshake done: drop the accept read-timeout so it cannot masquerade
    // as a liveness timer; liveness is the probe-timeout's job.
    write.set_read_timeout(None).ok();
    let _ = register(inner, &peer, write, reader, Transport::new(hs.session()), false);
    Ok(())
}

// Registers a new link for peer and starts its reader. Returns true if the new
// link was kept. On a collision it applies the simultaneous-dial tiebreak
// (protocol.md §3): same-initiator links are a reconnect (last writer wins);
// opposite-initiator links are a genuine dial collision, and both ends
// deterministically keep the session initiated by the lexicographically-lower
// label, so the pair converges on exactly one session. A displaced link is shut
// down; its deregister is identity-guarded, so its death cannot withdraw the
// surviving link's routes.
fn register(
    inner: &Arc<Inner>,
    peer: &str,
    write: TcpStream,
    reader: BufReader<TcpStream>,
    transport: Transport,
    initiator: bool,
) -> bool {
    let now = now_millis();
    let link = Arc::new(Mutex::new(Link {
        write,
        transport,
        initiator,
        established_at: now,
        last_inbound: now,
        last_data: now,
    }));

    let (keep_new, displaced) = {
        let mut links = inner.links.lock().unwrap();
        let prev = links.get(&peer.to_lowercase()).cloned();
        let keep_new = match &prev {
            Some(p) if p.lock().unwrap().initiator != initiator => {
                // Dial collision: keep the session the lower-labelled node
                // initiated. Both ends compute the same winner.
                let self_wins = inner.config.label.to_lowercase() < peer.to_lowercase();
                initiator == self_wins
            }
            _ => true, // no collision, or a same-initiator reconnect (last wins)
        };
        if keep_new {
            links.insert(peer.to_lowercase(), link.clone());
        }
        (keep_new, prev)
    };

    if !keep_new {
        // The new link lost the tiebreak; drop it and keep the existing one.
        link.lock().unwrap().write.shutdown(std::net::Shutdown::Both).ok();
        return false;
    }
    if let Some(old) = displaced {
        if !Arc::ptr_eq(&old, &link) {
            old.lock().unwrap().write.shutdown(std::net::Shutdown::Both).ok();
        }
    }
    inner.table.lock().unwrap().observe_neighbor(peer, 1); // optimistic seed

    let inner = inner.clone();
    let peer = peer.to_string();
    thread::spawn(move || read_loop(inner, peer, reader, link));
    true
}

fn read_loop(inner: Arc<Inner>, peer: String, mut reader: BufReader<TcpStream>, link: Arc<Mutex<Link>>) {
    loop {
        let raw = match read_line(&mut reader) {
            Ok(r) => r,
            Err(_) => {
                deregister(&inner, &peer, &link);
                break;
            }
        };
        let carrier: Value = match serde_json::from_slice(&raw) {
            Ok(v) => v,
            Err(_) => {
                deregister(&inner, &peer, &link);
                break;
            }
        };
        let inner_msg = {
            let mut l = link.lock().unwrap();
            match l.transport.open(&carrier) {
                Ok(v) => {
                    l.last_inbound = now_millis();
                    if v["type"] == "data" {
                        l.last_data = now_millis();
                    }
                    v
                }
                Err(_) => continue,
            }
        };
        if inner_msg["type"] == "bye" {
            // Peer is closing this session gracefully; tear it down and stop.
            deregister(&inner, &peer, &link);
            return;
        }
        handle_inner(&inner, &peer, inner_msg);
    }
}

fn handle_inner(inner: &Arc<Inner>, peer: &str, msg: Value) {
    match msg["type"].as_str() {
        Some("probe") => {
            if let Some(token) = msg["token"].as_i64() {
                send_to_link(inner, peer, &message::echo(token));
            }
        }
        Some("echo") => {
            if let Some(token) = msg["token"].as_i64() {
                let rtt = (now_millis() - token).max(0);
                inner.table.lock().unwrap().observe_neighbor(peer, rtt);
            }
        }
        Some("disco") => {
            if let Some(routes) = msg["routes"].as_object() {
                let mut table = inner.table.lock().unwrap();
                for (dest, cost) in routes {
                    if let Some(c) = cost.as_i64() {
                        table.learn_route(dest, peer, c);
                    }
                }
            }
        }
        Some("data") => handle_data(inner, msg),
        Some("ack") => handle_control(inner, msg, "a:"),
        Some("nak") => handle_control(inner, msg, "n:"),
        _ => {}
    }
}

fn handle_data(inner: &Arc<Inner>, msg: Value) {
    let mid = msg["mid"].as_str().unwrap_or("");
    let chunk_idx = msg["chunk"]["i"].as_i64().unwrap_or(-1);
    if inner.dedup.lock().unwrap().seen(&format!("d:{}:{}", mid, chunk_idx)) {
        return;
    }
    let to = msg["to"].as_str().unwrap_or("");
    let from = msg["from"].as_str().unwrap_or("");
    let self_label = inner.config.label.to_lowercase();
    if to.to_lowercase() == self_label {
        let payload = msg["payload"].clone();
        for tx in inner.listeners.lock().unwrap().iter() {
            let _ = tx.send(payload.clone());
        }
        // F6: acknowledge receipt back toward the origin.
        if !from.is_empty() && from.to_lowercase() != self_label {
            route_control(
                inner,
                &message::ack_to(mid, &inner.config.label, from, message::DEFAULT_TTL),
            );
        }
        return;
    }
    let ttl = msg["ttl"].as_i64().unwrap_or(0) - 1;
    if ttl <= 0 {
        // F6/D4: the relay that dropped it names itself as the failing hop.
        emit_nak(inner, mid, from, "ttl");
        return;
    }
    let nh = inner.table.lock().unwrap().next_hop(to);
    match nh {
        Some(nh) => {
            let mut fwd = msg.clone();
            fwd["ttl"] = json!(ttl);
            send_to_link(inner, &nh, &fwd);
        }
        None => emit_nak(inner, mid, from, "no-route"),
    }
}

// Relays or delivers an ack/nak (routed back toward the origin like data). A
// type-prefixed dedup key keeps a relayed ack from colliding with the data it
// answers (same mid). ack/nak are never themselves ack'd or nak'd.
fn handle_control(inner: &Arc<Inner>, msg: Value, prefix: &str) {
    let mid = msg["mid"].as_str().unwrap_or("");
    if inner.dedup.lock().unwrap().seen(&format!("{}{}", prefix, mid)) {
        return;
    }
    let to = msg["to"].as_str().unwrap_or("");
    if to.to_lowercase() == inner.config.label.to_lowercase() {
        deliver_ack(inner, msg);
        return;
    }
    let ttl = msg["ttl"].as_i64().unwrap_or(0) - 1;
    if ttl <= 0 {
        return; // drop silently; no nak-of-nak
    }
    let nh = inner.table.lock().unwrap().next_hop(to);
    if let Some(nh) = nh {
        let mut fwd = msg.clone();
        fwd["ttl"] = json!(ttl);
        send_to_link(inner, &nh, &fwd);
    }
}

// Sends a NAK back toward the origin naming this node as the failing hop.
// Best-effort: if the NAK itself cannot be routed it is dropped (no recursion).
fn emit_nak(inner: &Arc<Inner>, mid: &str, origin: &str, reason: &str) {
    if origin.is_empty() || origin.to_lowercase() == inner.config.label.to_lowercase() {
        return;
    }
    route_control(
        inner,
        &message::nak(mid, &inner.config.label, origin, &inner.config.label, reason, message::DEFAULT_TTL),
    );
}

// Sends a freshly-built ack/nak toward its destination, dropping silently if
// there is no route (never producing a control-of-control).
fn route_control(inner: &Arc<Inner>, msg: &Value) {
    let to = msg["to"].as_str().unwrap_or("");
    let nh = inner.table.lock().unwrap().next_hop(to);
    if let Some(nh) = nh {
        send_to_link(inner, &nh, msg);
    }
}

// Hands an ack/nak addressed to this node to the ack listeners.
fn deliver_ack(inner: &Arc<Inner>, msg: Value) {
    for tx in inner.ack_listeners.lock().unwrap().iter() {
        let _ = tx.send(msg.clone());
    }
}

// Withdraws a dropped link's routes, but only if it is still the current link —
// a reconnect may have replaced it, and the stale link's death must not
// withdraw the live link's routes.
fn deregister(inner: &Arc<Inner>, peer: &str, link: &Arc<Mutex<Link>>) {
    let key = peer.to_lowercase();
    let was_current = {
        let mut links = inner.links.lock().unwrap();
        match links.get(&key) {
            Some(cur) if Arc::ptr_eq(cur, link) => {
                links.remove(&key);
                true
            }
            _ => false,
        }
    };
    if was_current {
        inner.table.lock().unwrap().remove_neighbor(peer);
    }
}

fn heartbeat(inner: Arc<Inner>) {
    loop {
        thread::sleep(Duration::from_secs(1));
        if inner.stop.load(Ordering::SeqCst) {
            return;
        }
        let now = now_millis();
        let pairs: Vec<(String, Arc<Mutex<Link>>)> = {
            let links = inner.links.lock().unwrap();
            links.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };
        for (peer, link) in pairs {
            sweep_link(&inner, now, &peer, &link);
        }
    }
}

// Once-per-heartbeat maintenance for one link: tear it down if it is
// probe-timeout dead (F3) or data-idle past the idle timeout (F4, disabled at
// idle_ms==0), otherwise send it a probe and a route advertisement.
fn sweep_link(inner: &Arc<Inner>, now: i64, peer: &str, link: &Arc<Mutex<Link>>) {
    let (last_inbound, last_data) = {
        let l = link.lock().unwrap();
        (l.last_inbound, l.last_data)
    };
    if now - last_inbound > inner.tun.probe_timeout_ms {
        deregister(inner, peer, link);
        return;
    }
    if inner.tun.idle_ms > 0 && now - last_data > inner.tun.idle_ms {
        send_to_link(inner, peer, &message::bye(Some("idle")));
        deregister(inner, peer, link);
        return;
    }
    send_to_link(inner, peer, &message::probe(now));
    let adv = inner.table.lock().unwrap().advertise_to(peer);
    send_to_link(inner, peer, &message::disco(adv));
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn send_to_link(inner: &Arc<Inner>, label: &str, inner_msg: &Value) -> bool {
    let link = { inner.links.lock().unwrap().get(&label.to_lowercase()).cloned() };
    match link {
        None => false,
        Some(link) => {
            let mut l = link.lock().unwrap();
            if inner_msg["type"] == "data" {
                l.last_data = now_millis();
            }
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

// White-box tests for link registration lifecycle (protocol.md §3): a stale
// link's death must never withdraw the live link's routes, a displaced link
// must be closed, and per-link metadata must be recorded at register time.
#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpListener;

    fn bare_inner() -> Arc<Inner> {
        Arc::new(Inner {
            config: Config {
                label: "self".into(),
                mesh: "m".into(),
                root_public: vec![],
                cert: Value::Null,
                id_private: [0u8; 32],
            },
            tun: load_tunables(),
            links: Mutex::new(HashMap::new()),
            listeners: Mutex::new(Vec::new()),
            ack_listeners: Mutex::new(Vec::new()),
            table: Mutex::new(routing::Table::new("self")),
            dedup: Mutex::new(routing::Dedup::new(16)),
            stop: AtomicBool::new(false),
        })
    }

    // A bare Inner with a chosen probe timeout and idle timeout, for the
    // heartbeat-sweep feature tests (F3/F4).
    fn inner_with_tun(probe_timeout_ms: i64, idle_ms: i64) -> Arc<Inner> {
        Arc::new(Inner {
            config: Config {
                label: "self".into(),
                mesh: "m".into(),
                root_public: vec![],
                cert: Value::Null,
                id_private: [0u8; 32],
            },
            tun: Tunables {
                probe_timeout_ms,
                idle_ms,
                retry_base_ms: 500,
                retry_cap_ms: 30000,
                retry_max_ms: 60000,
                rekey_ms: 3600000,
                rekey_frames: 65536,
                rekey_timeout_ms: 10000,
                keylog_path: String::new(),
            },
            links: Mutex::new(HashMap::new()),
            listeners: Mutex::new(Vec::new()),
            ack_listeners: Mutex::new(Vec::new()),
            table: Mutex::new(routing::Table::new("self")),
            dedup: Mutex::new(routing::Dedup::new(16)),
            stop: AtomicBool::new(false),
        })
    }

    fn tcp_pair(listener: &TcpListener) -> (TcpStream, TcpStream) {
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    fn dummy_transport() -> Transport {
        Transport::new(&crate::handshake::Session {
            send_key: vec![0u8; 32],
            receive_key: vec![0u8; 32],
            peer_cert: json!({"label": "peer"}),
        })
    }

    #[test]
    fn stale_link_death_does_not_withdraw_live_neighbor() {
        let inner = bare_inner();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (c1, s1) = tcp_pair(&listener);
        let (c2, _s2) = tcp_pair(&listener);
        let r1 = BufReader::new(c1.try_clone().unwrap());
        let r2 = BufReader::new(c2.try_clone().unwrap());

        register(&inner, "peer", c1, r1, dummy_transport(), true);
        let first = inner.links.lock().unwrap().get("peer").cloned().unwrap();

        // Reconnect: displaces the first link.
        register(&inner, "peer", c2, r2, dummy_transport(), true);
        let cur = inner.links.lock().unwrap().get("peer").cloned().unwrap();
        assert!(!Arc::ptr_eq(&first, &cur), "reconnect did not replace the link");

        // The displaced socket must be shut down — its far end sees EOF.
        let mut s1 = s1;
        s1.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut buf = [0u8; 1];
        match s1.read(&mut buf) {
            Ok(0) => {}
            other => panic!("displaced link was not closed: {:?}", other),
        }

        // The stale link's death must not withdraw the live neighbor entry.
        deregister(&inner, "peer", &first);
        assert!(
            inner.table.lock().unwrap().next_hop("peer").is_some(),
            "stale link death withdrew the live link's neighbor entry"
        );
        assert!(inner.links.lock().unwrap().get("peer").is_some(), "live link lost");

        // Control: the CURRENT link's death does withdraw the neighbor.
        deregister(&inner, "peer", &cur);
        assert!(
            inner.table.lock().unwrap().next_hop("peer").is_none(),
            "current link death failed to withdraw the neighbor"
        );
    }

    #[test]
    fn register_records_initiator_and_timestamps() {
        let inner = bare_inner();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (c1, _s1) = tcp_pair(&listener);
        let r1 = BufReader::new(c1.try_clone().unwrap());
        let before = now_millis();
        register(&inner, "peer", c1, r1, dummy_transport(), true);
        let link = inner.links.lock().unwrap().get("peer").cloned().unwrap();
        let l = link.lock().unwrap();
        assert!(l.initiator, "initiator flag not recorded");
        assert!(
            l.established_at >= before && l.last_inbound >= before && l.last_data >= before,
            "timestamps not initialized at register"
        );
    }

    #[test]
    fn tunables_env_and_defaults() {
        std::env::set_var("BONEMESH_PROBE_TIMEOUT_MS", "1234");
        let t = load_tunables();
        assert_eq!(t.probe_timeout_ms, 1234, "env override ignored");
        std::env::set_var("BONEMESH_PROBE_TIMEOUT_MS", "garbage");
        assert_eq!(load_tunables().probe_timeout_ms, 15000, "unparseable env did not fall back");
        std::env::remove_var("BONEMESH_PROBE_TIMEOUT_MS");
        let d = load_tunables();
        assert_eq!(
            (d.idle_ms, d.retry_base_ms, d.retry_cap_ms, d.retry_max_ms),
            (0, 500, 30000, 60000)
        );
        assert_eq!((d.rekey_ms, d.rekey_frames, d.rekey_timeout_ms), (3600000, 65536, 10000));
    }

    // F1: on a dial collision both ends keep the session initiated by the
    // lower-labelled node, regardless of which link registered first. self="self":
    // against a higher peer ("zzz") self keeps its own-initiated link; against a
    // lower peer ("aaa") it keeps the one it accepted.
    #[test]
    fn tiebreak_keeps_lower_label_initiated_session() {
        for (peer, want_initiator) in [("zzz", true), ("aaa", false)] {
            for first_initiator in [true, false] {
                let inner = inner_with_tun(1_000_000, 0);
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                let (c1, _s1) = tcp_pair(&listener);
                let (c2, _s2) = tcp_pair(&listener);
                let r1 = BufReader::new(c1.try_clone().unwrap());
                let r2 = BufReader::new(c2.try_clone().unwrap());
                register(&inner, peer, c1, r1, dummy_transport(), first_initiator);
                register(&inner, peer, c2, r2, dummy_transport(), !first_initiator);
                let lk = inner.links.lock().unwrap().get(peer).cloned().unwrap();
                let got = lk.lock().unwrap().initiator;
                assert_eq!(
                    got, want_initiator,
                    "peer={peer} first_initiator={first_initiator}: wrong survivor"
                );
            }
        }
    }

    // F3: a link silent past the probe timeout is torn down and its routes
    // withdrawn; a fresh link is kept.
    #[test]
    fn probe_timeout_closes_silent_link() {
        let inner = inner_with_tun(100, 0);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (c1, _s1) = tcp_pair(&listener); // hold _s1 so the socket stays open
        let r1 = BufReader::new(c1.try_clone().unwrap());
        register(&inner, "peer", c1, r1, dummy_transport(), true);
        let lk = inner.links.lock().unwrap().get("peer").cloned().unwrap();

        sweep_link(&inner, now_millis(), "peer", &lk); // fresh: kept
        assert!(inner.links.lock().unwrap().contains_key("peer"), "fresh link wrongly torn down");

        lk.lock().unwrap().last_inbound = now_millis() - 5000; // now silent past the timeout
        sweep_link(&inner, now_millis(), "peer", &lk);
        assert!(!inner.links.lock().unwrap().contains_key("peer"), "probe-dead link not torn down");
        assert!(
            inner.table.lock().unwrap().next_hop("peer").is_none(),
            "neighbor not withdrawn after probe-timeout death"
        );
    }

    // F4: with idle teardown enabled, a link with no data past the idle timeout
    // is torn down; disabled (idle_ms==0), the same idle link stays up.
    #[test]
    fn idle_teardown_only_when_enabled() {
        let enabled = inner_with_tun(1_000_000, 100);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (c1, _s1) = tcp_pair(&listener);
        let r1 = BufReader::new(c1.try_clone().unwrap());
        register(&enabled, "peer", c1, r1, dummy_transport(), true);
        let lk = enabled.links.lock().unwrap().get("peer").cloned().unwrap();
        {
            let mut l = lk.lock().unwrap();
            l.last_inbound = now_millis(); // not probe-dead
            l.last_data = now_millis() - 5000; // idle
        }
        sweep_link(&enabled, now_millis(), "peer", &lk);
        assert!(
            !enabled.links.lock().unwrap().contains_key("peer"),
            "idle link not torn down when idle teardown is enabled"
        );

        let disabled = inner_with_tun(1_000_000, 0);
        let (c2, _s2) = tcp_pair(&listener);
        let r2 = BufReader::new(c2.try_clone().unwrap());
        register(&disabled, "peer", c2, r2, dummy_transport(), true);
        let lk2 = disabled.links.lock().unwrap().get("peer").cloned().unwrap();
        {
            let mut l = lk2.lock().unwrap();
            l.last_inbound = now_millis();
            l.last_data = now_millis() - 5000;
        }
        sweep_link(&disabled, now_millis(), "peer", &lk2);
        assert!(
            disabled.links.lock().unwrap().contains_key("peer"),
            "idle teardown fired even though it is disabled (idle_ms=0)"
        );
    }
}
