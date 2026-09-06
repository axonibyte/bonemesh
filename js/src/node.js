// A BoneMesh v3 mesh node (protocol.md §3, §5) over TCP: one authenticated,
// encrypted session per neighbor, each served by an async frame reader. It
// routes — distance-vector discovery over a 1 s heartbeat (probe/echo for link
// latency, disco for route advertisement with poisoned reverse), relays data
// toward a next hop with TTL, and delivers payloads addressed to itself,
// deduping by message id. Wire-compatible with the Java, Elixir, Rust, Go, and
// PHP implementations.
//
// Node.js is single-threaded and event-driven, so there is no shared-state race
// to guard (contrast the Java node's synchronized routing tables): each link's
// seal/open runs to completion on the event loop.
import net from 'node:net';
import { once } from 'node:events';
import { Handshake } from './handshake.js';
import { Transport } from './transport.js';
import { classify, encode, HANDSHAKE_CAP, TRANSPORT_CAP } from './frame.js';
import * as message from './message.js';
import { Table, Dedup } from './routing.js';
import { loadTunables } from './tunables.js';

// A per-socket frame reader: buffers bytes, splits on newlines under a cap, and
// hands complete frames either to awaiting readFrame() calls or to a push
// callback once the connection enters transport mode.
class FrameChannel {
  constructor(socket) {
    this.socket = socket;
    this.buf = Buffer.alloc(0);
    this.cap = HANDSHAKE_CAP;
    this.queue = [];
    this.waiters = [];
    this.onFrameCb = null;
    this.closed = null;
    socket.on('data', (d) => this.#onData(d));
    socket.on('error', (e) => this.#fail(e));
    socket.on('close', () => this.#fail(new Error('connection closed')));
  }

  setCap(cap) { this.cap = cap; }

  #onData(d) {
    this.buf = Buffer.concat([this.buf, d]);
    let nl;
    while ((nl = this.buf.indexOf(0x0a)) >= 0) {
      const line = this.buf.subarray(0, nl + 1);
      this.buf = this.buf.subarray(nl + 1);
      const { obj, reason } = classify(line, this.cap);
      this.#emit(reason ? { error: new Error(reason) } : { obj });
    }
    if (this.buf.length > this.cap) this.#fail(new Error('oversize'));
  }

  #emit(item) {
    if (this.onFrameCb && !item.error) { this.onFrameCb(item.obj); return; }
    const w = this.waiters.shift();
    if (w) { item.error ? w.reject(item.error) : w.resolve(item.obj); }
    else this.queue.push(item);
  }

  #fail(err) {
    if (this.closed) return;
    this.closed = err;
    for (const w of this.waiters.splice(0)) w.reject(err);
  }

  readFrame() {
    const item = this.queue.shift();
    if (item) return item.error ? Promise.reject(item.error) : Promise.resolve(item.obj);
    if (this.closed) return Promise.reject(this.closed);
    return new Promise((resolve, reject) => this.waiters.push({ resolve, reject }));
  }

  onFrame(cb) {
    this.onFrameCb = cb;
    for (const item of this.queue.splice(0)) if (!item.error) cb(item.obj);
  }
}

export class Node {
  // config = { label, mesh, rootPublic, cert, idPrivate }
  constructor(config) {
    this.cfg = config;
    this.tun = loadTunables();
    this.links = new Map();
    this.listeners = [];
    this.server = null;
    this.table = new Table(config.label);
    this.dedup = new Dedup(4096);
    this.hb = null;
  }

  static async start(config, port) {
    const node = new Node(config);
    node.server = net.createServer((socket) => node.#respond(socket));
    node.server.on('error', () => {});
    node.server.listen(port);
    await once(node.server, 'listening');
    // 1 s heartbeat: probe + per-neighbor route advertisement to each link.
    node.hb = setInterval(() => {
      for (const label of node.links.keys()) {
        node.#sendToLink(label, message.probe(nowMs()));
        node.#sendToLink(label, message.disco(node.table.advertiseTo(label)));
      }
    }, 1000);
    return node;
  }

  port() { return this.server.address().port; }

  // A snapshot of learned destinations to their next hop.
  routeTable() { return this.table.routeTable(); }

  // Register a callback invoked with each delivered application payload.
  onMessage(cb) { this.listeners.push(cb); }

  async connect(host, port) {
    const socket = net.connect({ host, port });
    await once(socket, 'connect');
    const ch = new FrameChannel(socket);
    ch.setCap(HANDSHAKE_CAP);
    const hs = Handshake.initiator(this.cfg.mesh, this.cfg.rootPublic, now(), this.cfg.cert, this.cfg.idPrivate);
    socket.write(hs.writeMessage1());
    const m2 = await ch.readFrame();
    socket.write(hs.readMessage2WriteMessage3(m2));
    const peer = hs.session.peerCert.label;
    this.#register(peer, socket, ch, new Transport(hs.session), true);
    return peer;
  }

  send(to, payload) {
    const nh = this.table.nextHop(to);
    if (!nh) return false;
    const msg = message.data(message.newMid(), this.cfg.label, to, message.DEFAULT_TTL, payload);
    return this.#sendToLink(nh, msg);
  }

  #sendToLink(label, inner) {
    const link = this.links.get(label.toLowerCase());
    if (!link) return false;
    if (inner.type === 'data') link.lastData = nowMs();
    try {
      link.socket.write(encode(link.transport.seal(inner)));
      return true;
    } catch {
      return false;
    }
  }

  async #respond(socket) {
    const ch = new FrameChannel(socket);
    ch.setCap(HANDSHAKE_CAP);
    const hs = Handshake.responder(this.cfg.mesh, this.cfg.rootPublic, now(), this.cfg.cert, this.cfg.idPrivate);
    try {
      const m1 = await ch.readFrame();
      socket.write(hs.readMessage1WriteMessage2(m1));
      const m3 = await ch.readFrame();
      hs.readMessage3(m3);
    } catch {
      socket.destroy();
      return;
    }
    this.#register(hs.session.peerCert.label, socket, ch, new Transport(hs.session), false);
  }

  #register(peer, socket, ch, transport, initiator) {
    ch.setCap(TRANSPORT_CAP);
    const now = nowMs();
    // initiator: whether this node dialed the connection (protocol.md §3 —
    // the simultaneous-dial tiebreak needs to know who initiated each
    // competing session). lastInbound/lastData feed liveness and idle checks;
    // probe/echo/disco never count as data activity.
    const link = { socket, ch, transport, initiator, establishedAt: now, lastInbound: now, lastData: now };
    const displaced = this.links.get(peer.toLowerCase());
    this.links.set(peer.toLowerCase(), link);
    if (displaced && displaced !== link) {
      // A reconnect displaced an existing link: close it so its socket does
      // not linger. Its deregister is identity-guarded, so its death cannot
      // withdraw this new link's routes.
      displaced.socket.destroy();
    }
    this.table.observeNeighbor(peer, 1); // optimistic seed so it is routable
    socket.on('close', () => this.#deregister(peer, link));
    ch.onFrame((carrier) => {
      let inner;
      try {
        inner = transport.open(carrier);
      } catch {
        return;
      }
      link.lastInbound = nowMs();
      if (inner.type === 'data') link.lastData = nowMs();
      this.#handleInner(peer, inner);
    });
  }

  // Withdraws a dropped link's routes, but only if it is still the current
  // link — a reconnect may have replaced it, and the stale link's death must
  // not withdraw the live link's routes.
  #deregister(peer, link) {
    const k = peer.toLowerCase();
    if (this.links.get(k) === link) {
      this.links.delete(k);
      this.table.removeNeighbor(peer);
    }
  }

  #handleInner(peer, msg) {
    switch (msg.type) {
      case 'probe':
        this.#sendToLink(peer, message.echo(msg.token));
        break;
      case 'echo':
        this.table.observeNeighbor(peer, Math.max(0, nowMs() - msg.token));
        break;
      case 'disco':
        if (msg.routes) {
          for (const [dest, cost] of Object.entries(msg.routes)) this.table.learnRoute(dest, peer, cost);
        }
        break;
      case 'data':
        this.#handleData(msg);
        break;
    }
  }

  #handleData(msg) {
    const chunkIdx = msg.chunk && typeof msg.chunk.i === 'number' ? msg.chunk.i : -1;
    if (this.dedup.sawBefore(`${msg.mid}:${chunkIdx}`)) return;
    if (String(msg.to || '').toLowerCase() === this.cfg.label.toLowerCase()) {
      for (const cb of this.listeners) {
        try { cb(msg.payload); } catch { /* listener errors are its own */ }
      }
      return;
    }
    const ttl = (msg.ttl | 0) - 1;
    if (ttl <= 0) return; // DROP_TTL, silently
    const nh = this.table.nextHop(msg.to);
    if (!nh) return; // UNREACHABLE, silently
    this.#sendToLink(nh, { ...msg, ttl });
  }

  kill() {
    if (this.hb) clearInterval(this.hb);
    if (this.server) this.server.close();
    for (const link of this.links.values()) link.socket.destroy();
  }
}

function now() { return Math.floor(Date.now() / 1000); }
function nowMs() { return Date.now(); }
