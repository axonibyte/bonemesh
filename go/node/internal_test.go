// White-box tests for link registration lifecycle (protocol.md §3): a stale
// link's death must never withdraw the live link's routes, a displaced link
// must be closed, and per-link metadata must be recorded at register time.
package node

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"testing"
	"time"

	"github.com/axonibyte/bonemesh/gonode/canon"
	"github.com/axonibyte/bonemesh/gonode/cert"
	"github.com/axonibyte/bonemesh/gonode/crypto"
	"github.com/axonibyte/bonemesh/gonode/handshake"
	"github.com/axonibyte/bonemesh/gonode/routing"
	"github.com/axonibyte/bonemesh/gonode/transport"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
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

func drain(c net.Conn) { go func() { _, _ = io.Copy(io.Discard, c) }() }

// F1: on a dial collision both ends must keep the session initiated by the
// lower-labelled node, regardless of which link registered first. self="self":
// against a higher peer ("zzz") self keeps its own-initiated link; against a
// lower peer ("aaa") it keeps the one it accepted.
func TestTiebreakKeepsLowerLabelInitiatedSession(t *testing.T) {
	cases := []struct {
		peer          string
		wantInitiator bool
	}{
		{"zzz", true},  // self < peer  => keep self-initiated
		{"aaa", false}, // self > peer  => keep peer-initiated (the accepted link)
	}
	for _, tc := range cases {
		for _, firstInitiator := range []bool{true, false} {
			n := bareNode()
			a1, a2 := net.Pipe()
			b1, b2 := net.Pipe()
			defer a1.Close()
			defer a2.Close()
			defer b1.Close()
			defer b2.Close()
			n.register(tc.peer, a1, bufio.NewReader(a1), dummyTransport(tc.peer), firstInitiator)
			n.register(tc.peer, b1, bufio.NewReader(b1), dummyTransport(tc.peer), !firstInitiator)
			lk := n.links[lower(tc.peer)]
			if lk == nil {
				t.Fatalf("peer=%s first=%v: no surviving link", tc.peer, firstInitiator)
			}
			if lk.initiator != tc.wantInitiator {
				t.Fatalf("peer=%s first=%v: survivor initiator=%v want %v",
					tc.peer, firstInitiator, lk.initiator, tc.wantInitiator)
			}
			n.deregister(tc.peer, lk)
		}
	}
}

// F3: a link silent past the probe timeout is torn down and its routes
// withdrawn; a fresh link is kept.
func TestProbeTimeoutClosesSilentLink(t *testing.T) {
	n := bareNode()
	n.tun.probeTimeoutMS = 100
	n.tun.idleMS = 0
	c1, c2 := net.Pipe()
	drain(c2)
	defer c1.Close()
	defer c2.Close()
	n.register("peer", c1, bufio.NewReader(c1), dummyTransport("peer"), true)
	lk := n.links["peer"]

	n.sweepLink(nowMillis(), "peer", lk) // fresh: kept
	if _, ok := n.links["peer"]; !ok {
		t.Fatal("a fresh link was wrongly torn down")
	}
	lk.lastInbound.Store(nowMillis() - 5000) // now silent past the timeout
	n.sweepLink(nowMillis(), "peer", lk)
	if _, ok := n.links["peer"]; ok {
		t.Fatal("a probe-timed-out link was not torn down")
	}
	if _, ok := n.table.NextHop("peer"); ok {
		t.Fatal("neighbor not withdrawn after probe-timeout death")
	}
}

// F4: with idle teardown enabled, a link carrying no data past the idle timeout
// is torn down; with it disabled (idleMS==0) the same idle link stays up.
func TestIdleTeardownOnlyWhenEnabled(t *testing.T) {
	enabled := bareNode()
	enabled.tun.probeTimeoutMS = 1_000_000
	enabled.tun.idleMS = 100
	c1, c2 := net.Pipe()
	drain(c2)
	defer c1.Close()
	defer c2.Close()
	enabled.register("peer", c1, bufio.NewReader(c1), dummyTransport("peer"), true)
	lk := enabled.links["peer"]
	lk.lastInbound.Store(nowMillis()) // not probe-dead
	lk.lastData.Store(nowMillis() - 5000)
	enabled.sweepLink(nowMillis(), "peer", lk)
	if _, ok := enabled.links["peer"]; ok {
		t.Fatal("idle link not torn down when idle teardown is enabled")
	}

	disabled := bareNode()
	disabled.tun.probeTimeoutMS = 1_000_000
	disabled.tun.idleMS = 0
	d1, d2 := net.Pipe()
	drain(d2)
	defer d1.Close()
	defer d2.Close()
	disabled.register("peer", d1, bufio.NewReader(d1), dummyTransport("peer"), true)
	lk2 := disabled.links["peer"]
	lk2.lastInbound.Store(nowMillis())
	lk2.lastData.Store(nowMillis() - 5000)
	disabled.sweepLink(nowMillis(), "peer", lk2)
	if _, ok := disabled.links["peer"]; !ok {
		t.Fatal("idle teardown fired even though it is disabled (idleMS=0)")
	}
	disabled.deregister("peer", lk2)
}

func rootKeys(t *testing.T) ([]byte, *mldsa87.PrivateKey) {
	t.Helper()
	pub, priv, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pub.MarshalBinary()
	return b, priv
}

func cfgFor(t *testing.T, rootPub []byte, rootPriv *mldsa87.PrivateKey, label string) Config {
	t.Helper()
	idPub, idPriv := crypto.MLDSA65Generate()
	c := cert.Build("m", label, idPub, 1000, 1<<40)
	pre, err := canon.Canonicalize(c)
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, mldsa87.SignatureSize)
	if err := mldsa87.SignTo(rootPriv, []byte(pre), nil, false, sig); err != nil {
		t.Fatal(err)
	}
	c["sig"] = base64.StdEncoding.EncodeToString(sig)
	return Config{Label: label, Mesh: "m", RootPublic: rootPub, Cert: c, IDPrivate: idPriv}
}

// F6 / defect D4: when a relay drops a message because its TTL is exhausted, the
// NAK it returns to the origin must name the RELAY as the failing hop, never the
// final destination. Line alpha—beta—gamma; alpha sends toward gamma with ttl=1,
// so beta (the relay) exhausts it and is the one that must be named.
func TestNakNamesTheFailingRelayNotTheDestination(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	start := func(label string) *Node {
		n, err := Start(cfgFor(t, rootPub, rootPriv, label), 0)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	alpha := start("alpha")
	beta := start("beta")
	gamma := start("gamma")
	defer alpha.Kill()
	defer beta.Kill()
	defer gamma.Kill()

	if _, err := alpha.Connect("127.0.0.1", beta.Port()); err != nil {
		t.Fatal(err)
	}
	if _, err := gamma.Connect("127.0.0.1", beta.Port()); err != nil {
		t.Fatal(err)
	}

	// Wait until alpha has learned a route to gamma via beta.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if alpha.RouteTable()["gamma"] == "beta" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if alpha.RouteTable()["gamma"] != "beta" {
		t.Fatal("alpha never learned a route to gamma via beta")
	}

	acks := alpha.AckListener()
	mid, _ := alpha.sendWithTTL("gamma", map[string]any{"m": "doomed"}, 1)

	select {
	case a := <-acks:
		if a["type"] != "nak" {
			t.Fatalf("expected a nak, got %v", a["type"])
		}
		if a["hop"] != "beta" {
			t.Fatalf("nak must name the relay beta, named %q (the D4 bug names the destination)", a["hop"])
		}
		if a["reason"] != "ttl" {
			t.Fatalf("nak reason should be ttl, got %v", a["reason"])
		}
		if a["mid"] != mid {
			t.Fatalf("nak mid %v does not match sent mid %q", a["mid"], mid)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("origin never received a NAK for the TTL-dropped message")
	}
}
