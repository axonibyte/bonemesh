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
    this.ackListeners = [];
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
    // 1 s heartbeat: maintain each link (probe + route advertisement) or tear
    // it down if it is probe-timeout dead (F3) or idle (F4).
    node.hb = setInterval(() => {
      const now = nowMs();
      for (const [label, link] of [...node.links]) node.sweepLink(now, label, link);
    }, 1000);
    return node;
  }

  // Once-per-heartbeat maintenance for one link: tear it down if it is
  // probe-timeout dead (F3) or data-idle past the idle timeout (F4, disabled at
  // idleMs==0), otherwise send it a probe and a route advertisement.
  sweepLink(now, peer, link) {
    if (now - link.lastInbound > this.tun.probeTimeoutMs) {
      this.#deregister(peer, link);
      link.socket.destroy();
      return;
    }
    if (this.tun.idleMs > 0 && now - link.lastData > this.tun.idleMs) {
      this.#sendToLink(peer, message.bye('idle'));
      this.#deregister(peer, link);
      link.socket.destroy();
      return;
    }
    this.#sendToLink(peer, message.probe(now));
    this.#sendToLink(peer, message.disco(this.table.advertiseTo(peer)));
  }

  port() { return this.server.address().port; }

  // A snapshot of learned destinations to their next hop.
  routeTable() { return this.table.routeTable(); }

  // Register a callback invoked with each delivered application payload.
  onMessage(cb) { this.listeners.push(cb); }

  // Register a callback invoked with each ack/nak addressed to this node (the
  // origin), as the raw inner message.
  onAck(cb) { this.ackListeners.push(cb); }

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

  // Routes an application payload toward any reachable destination. Returns
  // true if the message was handed to a next hop.
  send(to, payload) {
    return this.sendMid(to, payload).ok;
  }

  // Send that also returns the message id, so a caller can correlate the
  // ack/nak delivered to onAck (protocol.md §7). Returns { mid, ok }.
  sendMid(to, payload) {
    return this.#sendWithTtl(to, payload, message.DEFAULT_TTL);
  }

  // sendMid with an explicit initial TTL, used by tests to force a relay to
  // exhaust the hop limit and emit a NAK.
  sendWithTtl(to, payload, ttl) {
    return this.#sendWithTtl(to, payload, ttl);
  }

  #sendWithTtl(to, payload, ttl) {
    const mid = message.newMid();
    const nh = this.table.nextHop(to);
    if (!nh) return { mid, ok: false };
    const ok = this.#sendToLink(nh, message.data(mid, this.cfg.label, to, ttl, payload));
    return { mid, ok };
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
    const k = peer.toLowerCase();
    const prev = this.links.get(k);
    // F1 simultaneous-dial tiebreak (protocol.md §3): if an existing link was
    // initiated by the opposite side, this is a genuine dial collision — both
    // ends deterministically keep the session initiated by the lower-labelled
    // node, so the pair converges on one session. Same-initiator = reconnect
    // (last writer wins).
    if (prev && prev.initiator !== initiator) {
      const selfWins = this.cfg.label.toLowerCase() < peer.toLowerCase();
      if (initiator !== selfWins) {
        // This new link lost the tiebreak; drop it and keep the existing one.
        socket.destroy();
        return false;
      }
    }
    this.links.set(k, link);
    if (prev && prev !== link) {
      // Displaced an existing link (reconnect, or collision the new link won):
      // close it. Its deregister is identity-guarded, so its death cannot
      // withdraw this new link's routes.
      prev.socket.destroy();
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
      if (inner.type === 'bye') {
        // Peer is closing this session gracefully; tear it down.
        this.#deregister(peer, link);
        link.socket.destroy();
        return;
      }
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
      case 'ack':
        this.#handleControl(msg, 'a:');
        break;
      case 'nak':
        this.#handleControl(msg, 'n:');
        break;
    }
  }

  #handleData(msg) {
    const chunkIdx = msg.chunk && typeof msg.chunk.i === 'number' ? msg.chunk.i : -1;
    if (this.dedup.sawBefore(`d:${msg.mid}:${chunkIdx}`)) return;
    const from = String(msg.from || '');
    if (String(msg.to || '').toLowerCase() === this.cfg.label.toLowerCase()) {
      for (const cb of this.listeners) {
        try { cb(msg.payload); } catch { /* listener errors are its own */ }
      }
      // F6: acknowledge receipt back toward the origin.
      if (from && from.toLowerCase() !== this.cfg.label.toLowerCase()) {
        this.#routeControl(message.ackTo(msg.mid, this.cfg.label, from, message.DEFAULT_TTL));
      }
      return;
    }
    const ttl = (msg.ttl | 0) - 1;
    if (ttl <= 0) {
      // F6/D4: the relay that dropped it names itself as the failing hop.
      this.#emitNak(msg.mid, from, 'ttl');
      return;
    }
    const nh = this.table.nextHop(msg.to);
    if (!nh) {
      this.#emitNak(msg.mid, from, 'no-route');
      return;
    }
    this.#sendToLink(nh, { ...msg, ttl });
  }

  // Relays or delivers an ack/nak (routed back toward the origin like data). A
  // type-prefixed dedup key keeps a relayed ack from colliding with the data it
  // answers (same mid). ack/nak are never themselves ack'd or nak'd.
  #handleControl(msg, prefix) {
    if (this.dedup.sawBefore(`${prefix}${msg.mid}`)) return;
    if (String(msg.to || '').toLowerCase() === this.cfg.label.toLowerCase()) {
      for (const cb of this.ackListeners) {
        try { cb(msg); } catch { /* listener errors are its own */ }
      }
      return;
    }
    const ttl = (msg.ttl | 0) - 1;
    if (ttl <= 0) return; // drop silently; no nak-of-nak
    const nh = this.table.nextHop(msg.to);
    if (!nh) return;
    this.#sendToLink(nh, { ...msg, ttl });
  }

  // Sends a NAK back toward the origin naming this node as the failing hop.
  // Best-effort: dropped if it cannot be routed (no recursion).
  #emitNak(mid, origin, reason) {
    if (!origin || origin.toLowerCase() === this.cfg.label.toLowerCase()) return;
    this.#routeControl(message.nak(mid, this.cfg.label, origin, this.cfg.label, reason, message.DEFAULT_TTL));
  }

  // Sends a freshly-built ack/nak toward its destination, dropping silently if
  // there is no route (never producing a control-of-control).
  #routeControl(msg) {
    const nh = this.table.nextHop(msg.to);
    if (!nh) return;
    this.#sendToLink(nh, msg);
  }

  kill() {
    if (this.hb) clearInterval(this.hb);
    if (this.server) this.server.close();
    for (const link of this.links.values()) link.socket.destroy();
  }
}

function now() { return Math.floor(Date.now() / 1000); }
function nowMs() { return Date.now(); }
