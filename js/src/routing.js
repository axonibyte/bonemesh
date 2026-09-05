// BoneMesh v3 distance-vector routing (protocol.md §5): a table of direct
// neighbors (EWMA-smoothed link latency) and learned routes (destination ->
// next hop, path cost in ms), plus a bounded dedup set for relayed messages.
// Wire-compatible with the Java, Elixir, Go, and Rust reference routers.
//
// Poison sentinel: a JS number cannot hold Java's Long.MAX_VALUE exactly (it
// exceeds 2^53), so this port advertises the 1e9 sentinel (Elixir's) and treats
// any advertised cost >= 1e9 as unreachable. Every tolerant receiver — Elixir,
// Go, Rust, PHP, and the corrected Java — honors it.

export const UNREACHABLE = 1_000_000_000;
export const POISON_THRESHOLD = 1_000_000_000;
const ALPHA = 0.2;

class Ewma {
  constructor() { this.value = 0; this.has = false; }
  observe(sample) {
    if (!this.has) { this.value = sample; this.has = true; }
    else { this.value = ALPHA * sample + (1 - ALPHA) * this.value; }
  }
  millis() { return this.has ? Math.round(this.value) : UNREACHABLE; }
}

export class Table {
  constructor(self) {
    this.self = self.toLowerCase();
    this.neighbors = new Map();      // label -> Ewma
    this.routes = new Map();         // dest -> { via, cost }
  }

  observeNeighbor(label, rttMillis) {
    const k = label.toLowerCase();
    let e = this.neighbors.get(k);
    if (!e) { e = new Ewma(); this.neighbors.set(k, e); }
    e.observe(rttMillis);
  }

  removeNeighbor(label) {
    const k = label.toLowerCase();
    this.neighbors.delete(k);
    for (const [dest, r] of this.routes) if (r.via === k) this.routes.delete(dest);
  }

  learnRoute(dest, via, advertisedCost) {
    const d = dest.toLowerCase();
    const v = via.toLowerCase();
    if (d === this.self || d === v) return;
    if (!this.neighbors.has(v)) return;
    if (advertisedCost >= POISON_THRESHOLD) {
      const r = this.routes.get(d);
      if (r && r.via === v) this.routes.delete(d);
      return;
    }
    const cost = satSum(advertisedCost, this.#neighborLatency(v));
    const r = this.routes.get(d);
    if (!r || r.via === v || cost < r.cost) this.routes.set(d, { via: v, cost });
  }

  nextHop(dest) {
    const d = dest.toLowerCase();
    if (this.neighbors.has(d)) return d; // a direct neighbor is its own next hop
    const r = this.routes.get(d);
    return r ? r.via : null;
  }

  advertiseTo(toNeighbor) {
    const to = toNeighbor.toLowerCase();
    const m = {};
    for (const [label, e] of this.neighbors) if (label !== to) m[label] = e.millis();
    for (const [dest, r] of this.routes) m[dest] = r.via === to ? UNREACHABLE : r.cost;
    delete m[this.self];
    return m;
  }

  routeTable() {
    const o = {};
    for (const [dest, r] of this.routes) o[dest] = r.via;
    return o;
  }

  #neighborLatency(k) {
    const e = this.neighbors.get(k);
    return e ? e.millis() : UNREACHABLE;
  }
}

function satSum(a, b) {
  if (a >= POISON_THRESHOLD || b >= POISON_THRESHOLD) return UNREACHABLE;
  const sum = a + b;
  return sum >= POISON_THRESHOLD ? UNREACHABLE : sum;
}

// A bounded set of recently seen keys (message id + chunk index) for dropping
// duplicate and looped relay traffic.
export class Dedup {
  constructor(cap) { this.cap = cap; this.set = new Set(); this.order = []; }
  sawBefore(key) {
    if (this.set.has(key)) return true;
    this.set.add(key);
    this.order.push(key);
    if (this.order.length > this.cap) this.set.delete(this.order.shift());
    return false;
  }
}
