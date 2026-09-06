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

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
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
    /// Short hex prefix of the session's transcript hash — a session identifier
    /// both ends agree on, surfaced for the interop harness (--sessions).
    th: String,
    /// When the handshake completed, in unix millis.
    established_at: i64,
    /// Unix-millis time of the last successfully opened inbound frame —
    /// any authenticated frame proves the peer is alive.
    last_inbound: i64,
    /// Unix-millis time of the last data frame sent over or received on this
    /// link (probe/echo/disco never count as activity).
    last_data: i64,
    /// Rekey state (F5). rekey_hs is the in-flight handshake before any key
    /// swap has happened (abandonable, keeping the old keys); rekey_pending_recv
    /// holds the initiator's new (i2r, r2i, transcript-hash) between swapping
    /// its send key (after phase 2) and swapping its receive key (on phase 4).
    rekey_hs: Option<Handshake>,
    rekey_pending: Option<(Vec<u8>, Vec<u8>, [u8; 32])>,
    rekey_started_at: i64,
    rekey_epoch: i64,
}

struct Inner {
    config: Config,
    tun: Tunables,
    links: Mutex<HashMap<String, Arc<Mutex<Link>>>>,
    listeners: Mutex<Vec<Sender<Value>>>,
    ack_listeners: Mutex<Vec<Sender<Value>>>,
    pending: Mutex<HashMap<String, Vec<PendingSend>>>,
    table: Mutex<routing::Table>,
    dedup: Mutex<routing::Dedup>,
    keylog_mu: Mutex<()>,
    stop: AtomicBool,
}

/// An origin data message awaiting retry (F2): it could not be handed to a next
/// hop yet. Retried on each heartbeat with exponential backoff until it lands
/// or its lifetime is spent.
struct PendingSend {
    inner: Value,
    enqueued_at: i64,
    next_at: i64,
    delay: i64,
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
            pending: Mutex::new(HashMap::new()),
            table: Mutex::new(routing::Table::new(&label)),
            dedup: Mutex::new(routing::Dedup::new(4096)),
            keylog_mu: Mutex::new(()),
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
        let (sk, rk, h) = {
            let s = hs.session();
            (s.send_key.clone(), s.receive_key.clone(), s.h)
        };
        // Handshake done: drop the dial read-timeout so it cannot masquerade
        // as a liveness timer; liveness is the probe-timeout's job.
        write.set_read_timeout(None).ok();
        if register(&self.inner, &peer, write, reader, Transport::new(hs.session()), true, &th16(&h)) {
            // Initiator: send key is i2r, receive key is r2i.
            write_keylog(&self.inner, 0, &sk, &rk, &h);
        }
        Ok(peer)
    }

    /// Routes an application payload toward any reachable destination. Returns
    /// true if the message was handed to a next hop.
    pub fn send(&self, to: &str, payload: Value) -> bool {
        self.send_mid(to, payload).is_some()
    }

    /// Send that also returns the message id, so a caller can correlate the
    /// ack/nak delivered to `add_ack_listener` (protocol.md §7). Returns None if
    /// the destination is not routable now; the message is queued for bounded
    /// retry (F2) when retry is enabled, so it may still be delivered later.
    pub fn send_mid(&self, to: &str, payload: Value) -> Option<String> {
        let mid = message::new_mid();
        let msg = message::data(&mid, &self.inner.config.label, to, message::DEFAULT_TTL, payload);
        let nh = self.inner.table.lock().unwrap().next_hop(to);
        let delivered = match nh {
            Some(nh) => send_to_link(&self.inner, &nh, &msg),
            None => false,
        };
        if !delivered {
            enqueue_retry(&self.inner, &msg);
            return None;
        }
        Some(mid)
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

    /// Per-neighbor rekey epoch and transcript-hash label — the observability
    /// the interop harness dumps via --sessions.
    pub fn session_info(&self) -> Value {
        let links: Vec<(String, Arc<Mutex<Link>>)> = {
            let map = self.inner.links.lock().unwrap();
            map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };
        let mut obj = serde_json::Map::new();
        for (peer, link) in links {
            let l = link.lock().unwrap();
            obj.insert(peer, json!({"epoch": l.rekey_epoch, "th": l.th}));
        }
        Value::Object(obj)
    }

    /// The number of completed rekeys on the link to `peer`, or -1 if there is
    /// no such link (F5 observability).
    pub fn rekey_epoch(&self, peer: &str) -> i64 {
        match self.inner.links.lock().unwrap().get(&peer.to_lowercase()) {
            Some(l) => l.lock().unwrap().rekey_epoch,
            None => -1,
        }
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
    let (sk, rk, h) = {
        let s = hs.session();
        (s.send_key.clone(), s.receive_key.clone(), s.h)
    };
    // Handshake done: drop the accept read-timeout so it cannot masquerade
    // as a liveness timer; liveness is the probe-timeout's job.
    write.set_read_timeout(None).ok();
    if register(inner, &peer, write, reader, Transport::new(hs.session()), false, &th16(&h)) {
        // Responder: receive key is i2r, send key is r2i.
        write_keylog(inner, 0, &rk, &sk, &h);
    }
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
    th: &str,
) -> bool {
    let now = now_millis();
    let link = Arc::new(Mutex::new(Link {
        write,
        transport,
        initiator,
        th: th.to_string(),
        established_at: now,
        last_inbound: now,
        last_data: now,
        rekey_hs: None,
        rekey_pending: None,
        rekey_started_at: 0,
        rekey_epoch: 0,
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
        handle_inner(&inner, &peer, &link, inner_msg);
    }
}

fn handle_inner(inner: &Arc<Inner>, peer: &str, link: &Arc<Mutex<Link>>, msg: Value) {
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
        Some("rekey") => handle_rekey(inner, link, msg),
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
            if !send_to_link(inner, &nh, &fwd) {
                // The next-hop link died between routing and writing; name it as
                // the failing hop so the origin learns which hop broke (F2/D4).
                emit_nak_hop(inner, mid, from, &nh, "link-dead");
            }
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
    let hop = inner.config.label.clone();
    emit_nak_hop(inner, mid, origin, &hop, reason);
}

// Sends a NAK naming an explicit failing hop (this node for a local drop, the
// next-hop label for a dead onward link).
fn emit_nak_hop(inner: &Arc<Inner>, mid: &str, origin: &str, hop: &str, reason: &str) {
    if origin.is_empty() || origin.to_lowercase() == inner.config.label.to_lowercase() {
        return;
    }
    route_control(
        inner,
        &message::nak(mid, &inner.config.label, origin, hop, reason, message::DEFAULT_TTL),
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
            if sweep_link(&inner, now, &peer, &link) {
                maybe_rekey(&inner, now, &link);
            }
        }
        drain_retries(&inner, now);
    }
}

// Once-per-heartbeat maintenance for one link: tear it down if it is
// probe-timeout dead (F3) or data-idle past the idle timeout (F4, disabled at
// idle_ms==0), otherwise send it a probe and a route advertisement.
// Returns true if the link was kept.
fn sweep_link(inner: &Arc<Inner>, now: i64, peer: &str, link: &Arc<Mutex<Link>>) -> bool {
    let (last_inbound, last_data) = {
        let l = link.lock().unwrap();
        (l.last_inbound, l.last_data)
    };
    if now - last_inbound > inner.tun.probe_timeout_ms {
        deregister(inner, peer, link);
        return false;
    }
    if inner.tun.idle_ms > 0 && now - last_data > inner.tun.idle_ms {
        send_to_link(inner, peer, &message::bye(Some("idle")));
        deregister(inner, peer, link);
        return false;
    }
    send_to_link(inner, peer, &message::probe(now));
    let adv = inner.table.lock().unwrap().advertise_to(peer);
    send_to_link(inner, peer, &message::disco(adv));
    true
}

// Queues an origin data message for later retry, bounded to 64 per destination.
// A no-op when retry is disabled (retry_max_ms == 0) (F2).
fn enqueue_retry(inner: &Arc<Inner>, msg: &Value) {
    if inner.tun.retry_max_ms <= 0 {
        return;
    }
    let to = msg["to"].as_str().unwrap_or("").to_lowercase();
    let now = now_millis();
    let mut pending = inner.pending.lock().unwrap();
    let q = pending.entry(to).or_default();
    if q.len() >= 64 {
        return; // bounded: one unreachable destination cannot grow without limit
    }
    q.push(PendingSend {
        inner: msg.clone(),
        enqueued_at: now,
        next_at: now + inner.tun.retry_base_ms,
        delay: inner.tun.retry_base_ms,
    });
}

// Re-attempts due pending sends once per heartbeat: a landed message is dropped,
// a still-stuck one backs off (delay doubles to the cap), and one past its
// lifetime is dropped and reported to the origin's ack listener as a
// synthesized nak{reason:"expired"} (never on the wire) (F2).
fn drain_retries(inner: &Arc<Inner>, now: i64) {
    // Take the whole map so send_to_link (which locks links) never runs under
    // the pending lock; survivors and any concurrent enqueues merge back after.
    let taken: Vec<(String, Vec<PendingSend>)> = {
        let mut p = inner.pending.lock().unwrap();
        std::mem::take(&mut *p).into_iter().collect()
    };
    let mut survivors: HashMap<String, Vec<PendingSend>> = HashMap::new();
    for (dest, entries) in taken {
        for mut e in entries {
            if now < e.next_at {
                survivors.entry(dest.clone()).or_default().push(e);
                continue;
            }
            let to = e.inner["to"].as_str().unwrap_or("").to_string();
            let nh = inner.table.lock().unwrap().next_hop(&to);
            let delivered = matches!(nh, Some(ref h) if send_to_link(inner, h, &e.inner));
            if delivered {
                continue;
            }
            if now - e.enqueued_at > inner.tun.retry_max_ms {
                let mid = e.inner["mid"].as_str().unwrap_or("").to_string();
                let label = &inner.config.label;
                deliver_ack(
                    inner,
                    json!({"type":"nak","mid":mid,"hop":label,"reason":"expired","to":label,"from":label,"ttl":message::DEFAULT_TTL}),
                );
                continue;
            }
            e.delay = (e.delay * 2).min(inner.tun.retry_cap_ms);
            e.next_at = now + e.delay;
            survivors.entry(dest.clone()).or_default().push(e);
        }
    }
    let mut p = inner.pending.lock().unwrap();
    for (dest, mut entries) in survivors {
        p.entry(dest).or_default().append(&mut entries);
    }
}

// Seals and writes an inner message on a link the caller already holds locked —
// used inside the rekey machine so a seal-then-swap is atomic against other
// senders.
fn write_locked(l: &mut Link, inner_msg: &Value) {
    if inner_msg["type"] == "data" {
        l.last_data = now_millis();
    }
    let carrier = l.transport.seal(inner_msg);
    let bytes = frame::encode(&carrier);
    let _ = l.write.write_all(&bytes).and_then(|_| l.write.flush());
}

// Drives the initiator side of a periodic rekey (F5): abandon a stalled pre-swap
// handshake at the rekey timeout (keeping the old keys — the safe degrade
// against a peer that does not understand rekey), else, on the session
// initiator only, start a fresh BMX when the frame count or session age crosses
// the threshold. Runs under the link lock so phase 1 is sealed with the current
// keys without racing another sender.
fn maybe_rekey(inner: &Arc<Inner>, now_ms: i64, link: &Arc<Mutex<Link>>) {
    let mut l = link.lock().unwrap();
    if l.rekey_hs.is_some() {
        if now_ms - l.rekey_started_at > inner.tun.rekey_timeout_ms {
            l.rekey_hs = None; // no swap has happened yet; the old keys stand
        }
        return;
    }
    if l.rekey_pending.is_some() {
        return; // initiator has swapped its send key and is awaiting phase 4
    }
    if !l.initiator {
        return; // only the session's original initiator drives rekey
    }
    let due = l.transport.send_seq() >= inner.tun.rekey_frames as u64
        || l.transport.receive_seq() >= inner.tun.rekey_frames as u64
        || now_ms - l.established_at >= inner.tun.rekey_ms;
    if !due {
        return;
    }
    let c = &inner.config;
    let mut hs = Handshake::initiator(&c.mesh, &c.root_public, now_secs(), c.cert.clone(), c.id_private);
    let m1 = hs.write_message1();
    let mid = message::new_mid();
    write_locked(&mut l, &json!({"type":"rekey","mid":mid,"phase":1,"body":B64.encode(m1)}));
    l.rekey_hs = Some(hs);
    l.rekey_started_at = now_ms;
}

// Advances the tunneled-BMX rekey state machine for one link. The BMX messages
// ride inside transport frames, so they arrive through the normal reader with no
// raw-stream race; each side swaps its send key immediately after sealing its
// last old-key frame, and its receive key immediately after opening the peer's
// (protocol.md §5 / security.md §6).
fn handle_rekey(inner: &Arc<Inner>, link: &Arc<Mutex<Link>>, msg: Value) {
    let phase = msg["phase"].as_i64().unwrap_or(0);
    let mid = msg["mid"].as_str().unwrap_or("").to_string();
    let body = B64.decode(msg["body"].as_str().unwrap_or("")).unwrap_or_default();
    let c = &inner.config;
    let mut l = link.lock().unwrap();
    match phase {
        1 => {
            // Responder: accept the fresh bmx1 and reply bmx2.
            let mut hs = Handshake::responder(&c.mesh, &c.root_public, now_secs(), c.cert.clone(), c.id_private);
            let m2 = match hs.read_message1_write_message2(&body) {
                Ok(m) => m,
                Err(_) => return,
            };
            l.rekey_started_at = now_millis();
            write_locked(&mut l, &json!({"type":"rekey","mid":mid,"phase":2,"body":B64.encode(m2)}));
            l.rekey_hs = Some(hs);
        }
        2 => {
            // Initiator: finish with bmx3, then swap its send key.
            let (m3, send_key, recv_key, h) = {
                let hs = match l.rekey_hs.as_mut() {
                    Some(h) => h,
                    None => return,
                };
                let m3 = match hs.read_message2_write_message3(&body) {
                    Ok(m) => m,
                    Err(_) => {
                        l.rekey_hs = None;
                        return;
                    }
                };
                let s = hs.session();
                (m3, s.send_key.clone(), s.receive_key.clone(), s.h)
            };
            write_locked(&mut l, &json!({"type":"rekey","mid":mid,"phase":3,"body":B64.encode(m3)}));
            l.transport.swap_send(&send_key); // last old-key frame sent above; initiator send = i2r
            l.rekey_pending = Some((send_key, recv_key, h));
            l.rekey_hs = None;
        }
        3 => {
            // Responder: verify bmx3, swap receive, send phase 4, swap send.
            let (send_key, recv_key, h) = {
                let hs = match l.rekey_hs.as_mut() {
                    Some(h) => h,
                    None => return,
                };
                if hs.read_message3(&body).is_err() {
                    l.rekey_hs = None;
                    return;
                }
                let s = hs.session();
                (s.send_key.clone(), s.receive_key.clone(), s.h)
            };
            l.transport.swap_receive(&recv_key); // phase-3 frame was the last old-key inbound
            write_locked(&mut l, &json!({"type":"rekey","mid":mid,"phase":4}));
            l.transport.swap_send(&send_key);
            l.rekey_hs = None;
            l.rekey_epoch += 1;
            l.th = th16(&h);
            // Responder: receive key is i2r, send key is r2i.
            write_keylog(inner, l.rekey_epoch, &recv_key, &send_key, &h);
        }
        4 => {
            // Initiator: swap receive; rekey complete.
            if let Some((i2r, r2i, h)) = l.rekey_pending.take() {
                l.transport.swap_receive(&r2i);
                l.rekey_epoch += 1;
                l.th = th16(&h);
                write_keylog(inner, l.rekey_epoch, &i2r, &r2i, &h);
            }
        }
        _ => {}
    }
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

/// th16 is the first 16 hex chars of a transcript hash — a compact session
/// label for the harness's --sessions dump.
fn th16(h: &[u8]) -> String {
    let full = to_hex(h);
    full.chars().take(16).collect()
}

/// write_keylog appends a session's directional transport keys to the file
/// named by BONEMESH_KEYLOG in the pinned format (security.md §8), keyed by the
/// transcript hash. Callers pass the ABSOLUTE i2r/r2i keys (mapping their
/// role-relative send/receive onto direction), so one inspector reads either
/// end. A loud warning is printed once per session (epoch 0).
fn write_keylog(inner: &Arc<Inner>, epoch: i64, i2r: &[u8], r2i: &[u8], h: &[u8]) {
    if inner.tun.keylog_path.is_empty() {
        return;
    }
    let th = to_hex(h);
    let _g = inner.keylog_mu.lock().unwrap();
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&inner.tun.keylog_path)
    {
        let _ = write!(
            f,
            "BMX3_I2R_TRAFFIC_{} {} {}\nBMX3_R2I_TRAFFIC_{} {} {}\n",
            epoch,
            th,
            to_hex(i2r),
            epoch,
            th,
            to_hex(r2i)
        );
    }
    if epoch == 0 {
        eprintln!(
            "WARNING: BONEMESH_KEYLOG is on; transport keys written to {} — forward secrecy is defeated for anyone holding that file",
            inner.tun.keylog_path
        );
    }
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
            pending: Mutex::new(HashMap::new()),
            table: Mutex::new(routing::Table::new("self")),
            dedup: Mutex::new(routing::Dedup::new(16)),
            keylog_mu: Mutex::new(()),
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
            pending: Mutex::new(HashMap::new()),
            table: Mutex::new(routing::Table::new("self")),
            dedup: Mutex::new(routing::Dedup::new(16)),
            keylog_mu: Mutex::new(()),
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
            h: [0u8; 32],
        })
    }

    // A bare Inner with an explicit retry lifetime (others default), for F2.
    fn inner_retry(retry_max_ms: i64) -> Arc<Inner> {
        Arc::new(Inner {
            config: Config {
                label: "self".into(),
                mesh: "m".into(),
                root_public: vec![],
                cert: Value::Null,
                id_private: [0u8; 32],
            },
            tun: Tunables {
                probe_timeout_ms: 1_000_000,
                idle_ms: 0,
                retry_base_ms: 1,
                retry_cap_ms: 30000,
                retry_max_ms,
                rekey_ms: 3_600_000,
                rekey_frames: 65536,
                rekey_timeout_ms: 10000,
                keylog_path: String::new(),
            },
            links: Mutex::new(HashMap::new()),
            listeners: Mutex::new(Vec::new()),
            ack_listeners: Mutex::new(Vec::new()),
            pending: Mutex::new(HashMap::new()),
            table: Mutex::new(routing::Table::new("self")),
            dedup: Mutex::new(routing::Dedup::new(16)),
            keylog_mu: Mutex::new(()),
            stop: AtomicBool::new(false),
        })
    }

    // F2: a message enqueued while its destination is unroutable is delivered
    // once a route appears, on a later heartbeat drain.
    #[test]
    fn retry_delivers_after_route_appears() {
        let inner = inner_retry(100_000);
        let msg = message::data("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "self", "peer", message::DEFAULT_TTL, json!({"x":1}));
        enqueue_retry(&inner, &msg);
        assert_eq!(inner.pending.lock().unwrap().get("peer").map(|q| q.len()), Some(1));

        // A route to peer appears.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (c1, _s1) = tcp_pair(&listener);
        let r1 = BufReader::new(c1.try_clone().unwrap());
        register(&inner, "peer", c1, r1, dummy_transport(), true, "");

        drain_retries(&inner, now_millis() + 10_000); // well past next_at
        assert!(
            inner.pending.lock().unwrap().get("peer").map_or(true, |q| q.is_empty()),
            "a deliverable retry was not drained from the queue"
        );
    }

    // F2: a message that never becomes routable is dropped at its lifetime cap
    // and reported to the origin's ack listener as a nak{reason:"expired"}.
    #[test]
    fn retry_reports_expired_to_ack_listener() {
        let inner = inner_retry(100);
        let (tx, rx) = channel();
        inner.ack_listeners.lock().unwrap().push(tx);
        let mid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let msg = message::data(mid, "self", "peer", message::DEFAULT_TTL, json!({"x":1}));
        enqueue_retry(&inner, &msg);
        {
            let mut p = inner.pending.lock().unwrap();
            let e = &mut p.get_mut("peer").unwrap()[0];
            e.enqueued_at = now_millis() - 100_000; // past its lifetime
            e.next_at = 0; // due now
        }
        drain_retries(&inner, now_millis());
        assert!(
            inner.pending.lock().unwrap().get("peer").map_or(true, |q| q.is_empty()),
            "expired retry not dropped"
        );
        let a = rx.recv_timeout(Duration::from_secs(1)).expect("no expiry report");
        assert_eq!(a["type"], "nak");
        assert_eq!(a["reason"], "expired");
        assert_eq!(a["mid"], json!(mid));
    }

    // F2 disabled: with retry_max_ms==0 nothing is queued.
    #[test]
    fn retry_disabled_queues_nothing() {
        let inner = inner_retry(0);
        let msg = message::data("cccccccccccccccccccccccccccccccc", "self", "peer", message::DEFAULT_TTL, json!({}));
        enqueue_retry(&inner, &msg);
        assert!(inner.pending.lock().unwrap().is_empty(), "retry queued even though disabled");
    }

    #[test]
    fn stale_link_death_does_not_withdraw_live_neighbor() {
        let inner = bare_inner();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (c1, s1) = tcp_pair(&listener);
        let (c2, _s2) = tcp_pair(&listener);
        let r1 = BufReader::new(c1.try_clone().unwrap());
        let r2 = BufReader::new(c2.try_clone().unwrap());

        register(&inner, "peer", c1, r1, dummy_transport(), true, "");
        let first = inner.links.lock().unwrap().get("peer").cloned().unwrap();

        // Reconnect: displaces the first link.
        register(&inner, "peer", c2, r2, dummy_transport(), true, "");
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
        register(&inner, "peer", c1, r1, dummy_transport(), true, "");
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
                register(&inner, peer, c1, r1, dummy_transport(), first_initiator, "");
                register(&inner, peer, c2, r2, dummy_transport(), !first_initiator, "");
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
        register(&inner, "peer", c1, r1, dummy_transport(), true, "");
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
        register(&enabled, "peer", c1, r1, dummy_transport(), true, "");
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
        register(&disabled, "peer", c2, r2, dummy_transport(), true, "");
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
