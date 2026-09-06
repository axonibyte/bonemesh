// Package routing implements BoneMesh v3 distance-vector routing (protocol.md
// §5): a thread-safe table of direct neighbors (EWMA-smoothed link latency) and
// learned routes (destination -> next hop, path cost in ms), plus a bounded
// dedup set for relayed messages. Wire-compatible with the Java and Elixir
// reference routers.
//
// Poison sentinel: routes are poisoned (advertised as unreachable) with
// Unreachable = 2^63-1 (Java's Long.MAX_VALUE), and ANY advertised cost at or
// above PoisonThreshold (1e9, Elixir's sentinel) is treated as unreachable on
// receipt. Emitting the larger value and accepting either keeps a mixed mesh —
// Java, Elixir, and the ports — converging correctly.
package routing

import (
	"math"
	"sync"
)

const (
	// Unreachable is the poison cost this implementation advertises.
	Unreachable = int64(9223372036854775807)
	// PoisonThreshold: any advertised cost >= this is treated as unreachable.
	PoisonThreshold = int64(1000000000)
	alpha           = 0.2
)

type ewma struct {
	value float64
	has   bool
}

func (e *ewma) observe(sample int64) {
	s := float64(sample)
	if !e.has {
		e.value = s
		e.has = true
	} else {
		e.value = alpha*s + (1-alpha)*e.value
	}
}

func (e *ewma) millis() int64 {
	if !e.has {
		return Unreachable
	}
	return int64(math.Round(e.value))
}

type route struct {
	via  string // lowercased next-hop label
	cost int64
}

// Table is a node's routing state. Every method is safe for concurrent use.
type Table struct {
	mu        sync.Mutex
	self      string
	neighbors map[string]*ewma
	routes    map[string]route
}

// NewTable creates an empty table for a node with the given label.
func NewTable(self string) *Table {
	return &Table{self: lower(self), neighbors: map[string]*ewma{}, routes: map[string]route{}}
}

// ObserveNeighbor folds an RTT sample (ms) into a neighbor's latency, creating
// the neighbor if new.
func (t *Table) ObserveNeighbor(label string, rttMillis int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	k := lower(label)
	e := t.neighbors[k]
	if e == nil {
		e = &ewma{}
		t.neighbors[k] = e
	}
	e.observe(rttMillis)
}

// RemoveNeighbor drops a neighbor and every route that ran through it.
func (t *Table) RemoveNeighbor(label string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	k := lower(label)
	delete(t.neighbors, k)
	for dest, r := range t.routes {
		if r.via == k {
			delete(t.routes, dest)
		}
	}
}

// LearnRoute applies one advertised (dest, cost) entry heard from a neighbor.
func (t *Table) LearnRoute(dest, via string, advertisedCost int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	d := lower(dest)
	v := lower(via)
	if d == t.self || d == v {
		return
	}
	if _, ok := t.neighbors[v]; !ok {
		return // never heard of this neighbor
	}
	if _, ok := t.neighbors[d]; ok {
		return // dest is a direct neighbor; a routed path would only shadow it
	}
	if advertisedCost >= PoisonThreshold {
		if r, ok := t.routes[d]; ok && r.via == v {
			delete(t.routes, d) // poisoned by the neighbor we route through
		}
		return
	}
	cost := saturatingSum(advertisedCost, t.neighborLatency(v))
	if r, ok := t.routes[d]; !ok || r.via == v || cost < r.cost {
		t.routes[d] = route{via: v, cost: cost}
	}
}

// NextHop returns the (lowercased) next-hop label toward dest, or ("", false).
func (t *Table) NextHop(dest string) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	d := lower(dest)
	if _, ok := t.neighbors[d]; ok {
		return d, true // a direct neighbor is its own next hop
	}
	if r, ok := t.routes[d]; ok {
		return r.via, true
	}
	return "", false
}

// AdvertiseTo builds the route map to send a neighbor: direct-neighbor latencies
// and learned routes, with split-horizon poisoned reverse (a route learned via
// the target is advertised back as unreachable).
func (t *Table) AdvertiseTo(toNeighbor string) map[string]int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	to := lower(toNeighbor)
	adv := map[string]int64{}
	for label, e := range t.neighbors {
		if label != to {
			adv[label] = e.millis()
		}
	}
	for dest, r := range t.routes {
		if r.via == to {
			adv[dest] = Unreachable
		} else {
			adv[dest] = r.cost
		}
	}
	delete(adv, t.self)
	return adv
}

// RouteTable is a snapshot of learned destinations to their next hop, for the
// convergence tier and the driver's route dump.
func (t *Table) RouteTable() map[string]string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := map[string]string{}
	for dest, r := range t.routes {
		out[dest] = r.via
	}
	return out
}

func (t *Table) neighborLatency(k string) int64 {
	if e, ok := t.neighbors[k]; ok {
		return e.millis()
	}
	return Unreachable
}

func saturatingSum(a, b int64) int64 {
	if a >= PoisonThreshold || b >= PoisonThreshold {
		return Unreachable
	}
	sum := a + b
	if sum < a || sum >= PoisonThreshold {
		return Unreachable
	}
	return sum
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
}
