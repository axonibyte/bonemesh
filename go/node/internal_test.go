// White-box tests for link registration lifecycle (protocol.md §3): a stale
// link's death must never withdraw the live link's routes, a displaced link
// must be closed, and per-link metadata must be recorded at register time.
package node

import (
	"bufio"
	"io"
	"net"
	"testing"
	"time"

	"github.com/axonibyte/bonemesh/gonode/handshake"
	"github.com/axonibyte/bonemesh/gonode/routing"
	"github.com/axonibyte/bonemesh/gonode/transport"
)

func bareNode() *Node {
	return &Node{
		cfg:   Config{Label: "self", Mesh: "m"},
		tun:   loadTunables(),
		links: make(map[string]*link),
		table: routing.NewTable("self"),
		dedup: routing.NewDedup(16),
		done:  make(chan struct{}),
	}
}

func dummyTransport(peer string) *transport.Transport {
	return transport.New(&handshake.Session{
		SendKey:    make([]byte, 32),
		ReceiveKey: make([]byte, 32),
		PeerCert:   map[string]any{"label": peer},
	})
}

// A reconnect displaces an existing link; the stale link's death (deregister)
// must not withdraw the neighbor entry that now belongs to the live link, and
// the displaced socket must actually be closed rather than leaked.
func TestStaleLinkDeathDoesNotWithdrawLiveNeighbor(t *testing.T) {
	n := bareNode()
	c1a, c1b := net.Pipe()
	c2a, c2b := net.Pipe()
	defer c2b.Close()

	n.register("peer", c1a, bufio.NewReader(c1a), dummyTransport("peer"), true)
	n.mu.Lock()
	first := n.links["peer"]
	n.mu.Unlock()
	if first == nil {
		t.Fatal("first link not registered")
	}

	// Reconnect: displaces the first link.
	n.register("peer", c2a, bufio.NewReader(c2a), dummyTransport("peer"), true)

	// The displaced socket must be closed — its far end sees EOF promptly.
	c1b.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c1b.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("displaced link was not closed (read err = %v, want EOF)", err)
	}

	// The stale link's deregister (also racing in from its read loop) must not
	// withdraw the live link's neighbor entry.
	n.deregister("peer", first)
	if _, ok := n.table.NextHop("peer"); !ok {
		t.Fatal("stale link death withdrew the live link's neighbor entry")
	}
	n.mu.Lock()
	cur := n.links["peer"]
	n.mu.Unlock()
	if cur == nil || cur == first {
		t.Fatal("live link lost after stale deregister")
	}

	// Control: deregistering the CURRENT link does withdraw the neighbor —
	// proves the guard discriminates rather than never withdrawing.
	n.deregister("peer", cur)
	if _, ok := n.table.NextHop("peer"); ok {
		t.Fatal("current link death failed to withdraw the neighbor")
	}
}

// register must record who initiated and stamp the liveness clocks, so the
// tiebreak/liveness features have ground truth from the first instant.
func TestRegisterRecordsInitiatorAndTimestamps(t *testing.T) {
	n := bareNode()
	ca, cb := net.Pipe()
	defer cb.Close()
	before := nowMillis()
	n.register("peer", ca, bufio.NewReader(ca), dummyTransport("peer"), true)
	n.mu.Lock()
	lk := n.links["peer"]
	n.mu.Unlock()
	if !lk.initiator {
		t.Fatal("initiator flag not recorded")
	}
	if lk.establishedAt < before || lk.lastInbound.Load() < before || lk.lastData.Load() < before {
		t.Fatalf("timestamps not initialized at register: est=%d in=%d data=%d before=%d",
			lk.establishedAt, lk.lastInbound.Load(), lk.lastData.Load(), before)
	}
}

// Tunables come from the environment once at load, with pinned defaults.
func TestTunablesEnvAndDefaults(t *testing.T) {
	t.Setenv("BONEMESH_PROBE_TIMEOUT_MS", "1234")
	tun := loadTunables()
	if tun.probeTimeoutMS != 1234 {
		t.Fatalf("env override ignored: %d", tun.probeTimeoutMS)
	}
	if tun.idleMS != 0 || tun.retryBaseMS != 500 || tun.retryCapMS != 30000 ||
		tun.retryMaxMS != 60000 || tun.rekeyMS != 3600000 ||
		tun.rekeyFrames != 65536 || tun.rekeyTimeoutMS != 10000 {
		t.Fatalf("defaults wrong: %+v", tun)
	}
	t.Setenv("BONEMESH_PROBE_TIMEOUT_MS", "garbage")
	if loadTunables().probeTimeoutMS != 15000 {
		t.Fatal("unparseable env did not fall back to default")
	}
}
