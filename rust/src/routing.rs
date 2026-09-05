//! BoneMesh v3 distance-vector routing (protocol.md §5): a table of direct
//! neighbors (EWMA-smoothed link latency) and learned routes (destination ->
//! next hop, path cost in ms), plus a bounded dedup set for relayed messages.
//! Wire-compatible with the Java and Elixir reference routers.
//!
//! Poison sentinel: routes are advertised unreachable with `UNREACHABLE`
//! (i64::MAX, Java's Long.MAX_VALUE), and any advertised cost at or above
//! `POISON_THRESHOLD` (1e9, Elixir's sentinel) is treated as unreachable on
//! receipt — so a mixed mesh converges.

use std::collections::{HashMap, HashSet, VecDeque};

use serde_json::{json, Map, Value};

/// The poison cost this implementation advertises.
pub const UNREACHABLE: i64 = i64::MAX;
/// Any advertised cost at or above this is treated as unreachable.
pub const POISON_THRESHOLD: i64 = 1_000_000_000;
const ALPHA: f64 = 0.2;

struct Ewma {
    value: f64,
    has: bool,
}

impl Ewma {
    fn observe(&mut self, sample: i64) {
        let s = sample as f64;
        if !self.has {
            self.value = s;
            self.has = true;
        } else {
            self.value = ALPHA * s + (1.0 - ALPHA) * self.value;
        }
    }

    fn millis(&self) -> i64 {
        if !self.has {
            UNREACHABLE
        } else {
            self.value.round() as i64
        }
    }
}

/// A node's routing state (guard behind a Mutex for concurrent use).
pub struct Table {
    self_label: String,
    neighbors: HashMap<String, Ewma>,
    routes: HashMap<String, (String, i64)>, // dest -> (via, cost)
}

impl Table {
    pub fn new(self_label: &str) -> Table {
        Table {
            self_label: self_label.to_lowercase(),
            neighbors: HashMap::new(),
            routes: HashMap::new(),
        }
    }

    pub fn observe_neighbor(&mut self, label: &str, rtt_millis: i64) {
        self.neighbors
            .entry(label.to_lowercase())
            .or_insert(Ewma { value: 0.0, has: false })
            .observe(rtt_millis);
    }

    pub fn remove_neighbor(&mut self, label: &str) {
        let k = label.to_lowercase();
        self.neighbors.remove(&k);
        self.routes.retain(|_, (via, _)| *via != k);
    }

    pub fn learn_route(&mut self, dest: &str, via: &str, advertised_cost: i64) {
        let d = dest.to_lowercase();
        let v = via.to_lowercase();
        if d == self.self_label || d == v {
            return;
        }
        if !self.neighbors.contains_key(&v) {
            return;
        }
        if advertised_cost >= POISON_THRESHOLD {
            if let Some((rv, _)) = self.routes.get(&d) {
                if *rv == v {
                    self.routes.remove(&d);
                }
            }
            return;
        }
        let cost = saturating_sum(advertised_cost, self.neighbor_latency(&v));
        let install = match self.routes.get(&d) {
            None => true,
            Some((rv, rc)) => *rv == v || cost < *rc,
        };
        if install {
            self.routes.insert(d, (v, cost));
        }
    }

    pub fn next_hop(&self, dest: &str) -> Option<String> {
        let d = dest.to_lowercase();
        if self.neighbors.contains_key(&d) {
            return Some(d); // a direct neighbor is its own next hop
        }
        self.routes.get(&d).map(|(via, _)| via.clone())
    }

    /// The advertisement for one neighbor: direct-neighbor latencies plus learned
    /// routes, with split-horizon poisoned reverse.
    pub fn advertise_to(&self, to_neighbor: &str) -> Value {
        let to = to_neighbor.to_lowercase();
        let mut m = Map::new();
        for (label, e) in &self.neighbors {
            if *label != to {
                m.insert(label.clone(), json!(e.millis()));
            }
        }
        for (dest, (via, cost)) in &self.routes {
            let c = if *via == to { UNREACHABLE } else { *cost };
            m.insert(dest.clone(), json!(c));
        }
        m.remove(&self.self_label);
        Value::Object(m)
    }

    /// A snapshot of learned destinations to their next hop.
    pub fn route_table(&self) -> HashMap<String, String> {
        self.routes
            .iter()
            .map(|(dest, (via, _))| (dest.clone(), via.clone()))
            .collect()
    }

    fn neighbor_latency(&self, k: &str) -> i64 {
        self.neighbors.get(k).map(|e| e.millis()).unwrap_or(UNREACHABLE)
    }
}

fn saturating_sum(a: i64, b: i64) -> i64 {
    if a >= POISON_THRESHOLD || b >= POISON_THRESHOLD {
        return UNREACHABLE;
    }
    match a.checked_add(b) {
        Some(sum) if sum < POISON_THRESHOLD => sum,
        _ => UNREACHABLE,
    }
}

/// A bounded set of recently seen keys (message id + chunk index) for dropping
/// duplicate and looped relay traffic.
pub struct Dedup {
    cap: usize,
    seen: HashSet<String>,
    order: VecDeque<String>,
}

impl Dedup {
    pub fn new(cap: usize) -> Dedup {
        Dedup {
            cap,
            seen: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    /// Records `key` and reports whether it had been seen before.
    pub fn seen(&mut self, key: &str) -> bool {
        if self.seen.contains(key) {
            return true;
        }
        self.seen.insert(key.to_string());
        self.order.push_back(key.to_string());
        if self.order.len() > self.cap {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        false
    }
}
