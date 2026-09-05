package routing

import "sync"

// Dedup is a bounded set of recently seen keys (message id + chunk index),
// used to drop duplicate and looped relay traffic. Thread-safe.
type Dedup struct {
	mu    sync.Mutex
	cap   int
	seen  map[string]struct{}
	order []string
}

// NewDedup creates a dedup set holding at most cap keys.
func NewDedup(cap int) *Dedup {
	return &Dedup{cap: cap, seen: make(map[string]struct{})}
}

// Seen records key and reports whether it had been seen before.
func (d *Dedup) Seen(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.seen[key]; ok {
		return true
	}
	d.seen[key] = struct{}{}
	d.order = append(d.order, key)
	if len(d.order) > d.cap {
		oldest := d.order[0]
		d.order = d.order[1:]
		delete(d.seen, oldest)
	}
	return false
}
