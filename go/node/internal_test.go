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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/axonibyte/bonemesh/gonode/canon"
	"github.com/axonibyte/bonemesh/gonode/cert"
	"github.com/axonibyte/bonemesh/gonode/crypto"
	"github.com/axonibyte/bonemesh/gonode/handshake"
	"github.com/axonibyte/bonemesh/gonode/message"
	"github.com/axonibyte/bonemesh/gonode/routing"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

func bareNode() *Node {
	return &Node{
		cfg:     Config{Label: "self", Mesh: "m"},
		tun:     loadTunables(),
		links:   make(map[string]*link),
		pending: make(map[string][]*pendingSend),
		table:   routing.NewTable("self"),
		dedup:   routing.NewDedup(16),
		done:    make(chan struct{}),
	}
}

func dummySession(peer string) *handshake.Session {
	return &handshake.Session{
		SendKey:    make([]byte, 32),
		ReceiveKey: make([]byte, 32),
		PeerCert:   map[string]any{"label": peer},
		H:          make([]byte, 32),
	}
}

// A reconnect displaces an existing link; the stale link's death (deregister)
// must not withdraw the neighbor entry that now belongs to the live link, and
// the displaced socket must actually be closed rather than leaked.
func TestStaleLinkDeathDoesNotWithdrawLiveNeighbor(t *testing.T) {
	n := bareNode()
	c1a, c1b := net.Pipe()
	c2a, c2b := net.Pipe()
	defer c2b.Close()

	n.register("peer", c1a, bufio.NewReader(c1a), dummySession("peer"), true)
	n.mu.Lock()
	first := n.links["peer"]
	n.mu.Unlock()
	if first == nil {
		t.Fatal("first link not registered")
	}

	// Reconnect: displaces the first link.
	n.register("peer", c2a, bufio.NewReader(c2a), dummySession("peer"), true)

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
	n.register("peer", ca, bufio.NewReader(ca), dummySession("peer"), true)
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
			n.register(tc.peer, a1, bufio.NewReader(a1), dummySession(tc.peer), firstInitiator)
			n.register(tc.peer, b1, bufio.NewReader(b1), dummySession(tc.peer), !firstInitiator)
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
	n.register("peer", c1, bufio.NewReader(c1), dummySession("peer"), true)
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
	enabled.register("peer", c1, bufio.NewReader(c1), dummySession("peer"), true)
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
	disabled.register("peer", d1, bufio.NewReader(d1), dummySession("peer"), true)
	lk2 := disabled.links["peer"]
	lk2.lastInbound.Store(nowMillis())
	lk2.lastData.Store(nowMillis() - 5000)
	disabled.sweepLink(nowMillis(), "peer", lk2)
	if _, ok := disabled.links["peer"]; !ok {
		t.Fatal("idle teardown fired even though it is disabled (idleMS=0)")
	}
	disabled.deregister("peer", lk2)
}

// F2: a message enqueued while its destination is unroutable is delivered once
// a route appears, on a later heartbeat drain.
func TestRetryDeliversAfterRouteAppears(t *testing.T) {
	n := bareNode()
	n.tun.retryMaxMS = 100000
	msg := message.Data("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "self", "peer", message.DefaultTTL, map[string]any{"x": 1})
	n.enqueueRetry(msg)
	if len(n.pending["peer"]) != 1 {
		t.Fatalf("message not queued for retry: %d", len(n.pending["peer"]))
	}
	// A route to peer appears.
	c1, c2 := net.Pipe()
	drain(c2)
	defer c1.Close()
	defer c2.Close()
	n.register("peer", c1, bufio.NewReader(c1), dummySession("peer"), true)
	// Drain well past nextAt so the entry is due.
	n.drainRetries(nowMillis() + 10000)
	if len(n.pending["peer"]) != 0 {
		t.Fatal("a deliverable retry was not drained from the queue")
	}
}

// F2: a message that never becomes routable is dropped at its lifetime cap and
// the origin is told via a synthesized nak{reason:"expired"} on the ack listener.
func TestRetryReportsExpiredToAckListener(t *testing.T) {
	n := bareNode()
	n.tun.retryMaxMS = 100
	acks := n.AckListener()
	mid := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	msg := message.Data(mid, "self", "peer", message.DefaultTTL, map[string]any{"x": 1})
	n.enqueueRetry(msg)
	// Age the entry past its lifetime and make it due now.
	n.pending["peer"][0].enqueuedAt = nowMillis() - 100000
	n.pending["peer"][0].nextAt = 0
	n.drainRetries(nowMillis())
	if len(n.pending["peer"]) != 0 {
		t.Fatal("expired retry not dropped")
	}
	select {
	case a := <-acks:
		if a["type"] != "nak" || a["reason"] != "expired" || a["mid"] != mid {
			t.Fatalf("unexpected expiry report: %v", a)
		}
	case <-time.After(time.Second):
		t.Fatal("no expiry report delivered to the ack listener")
	}
}

// F2 disabled: with retryMaxMS==0 nothing is queued.
func TestRetryDisabledQueuesNothing(t *testing.T) {
	n := bareNode()
	n.tun.retryMaxMS = 0
	n.enqueueRetry(message.Data("cccccccccccccccccccccccccccccccc", "self", "peer", message.DefaultTTL, map[string]any{}))
	if len(n.pending) != 0 {
		t.Fatal("retry queued even though retry is disabled")
	}
}

// F5: under a low frame threshold the session initiator rekeys the live link;
// both ends advance their rekey epoch and application delivery continues across
// the key swap without interruption.
func TestRekeyUnderTrafficAdvancesEpochAndKeepsDelivering(t *testing.T) {
	t.Setenv("BONEMESH_REKEY_FRAMES", "6") // ~3 heartbeats' worth of frames
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
	defer alpha.Kill()
	defer beta.Kill()

	got := beta.AddListener()
	if _, err := alpha.Connect("127.0.0.1", beta.Port()); err != nil {
		t.Fatal(err)
	}

	epoch := func(n *Node, peer string) int {
		n.mu.Lock()
		defer n.mu.Unlock()
		lk := n.links[lower(peer)]
		if lk == nil {
			return -1
		}
		lk.mu.Lock()
		defer lk.mu.Unlock()
		return lk.rekeyEpoch
	}

	// Heartbeats alone cross the 6-frame threshold within a few seconds.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if epoch(alpha, "beta") >= 1 && epoch(beta, "alpha") >= 1 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if e := epoch(alpha, "beta"); e < 1 {
		t.Fatalf("initiator never rekeyed (epoch=%d)", e)
	}
	if e := epoch(beta, "alpha"); e < 1 {
		t.Fatalf("responder never completed a rekey (epoch=%d)", e)
	}

	// Delivery must still work on the post-rekey keys.
	for time.Now().Before(deadline) {
		if alpha.Send("beta", map[string]any{"m": "after-rekey"}) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	select {
	case p := <-got:
		if p["m"] != "after-rekey" {
			t.Fatalf("beta got unexpected payload after rekey: %v", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("delivery broke across the rekey")
	}
}

// keylog line: "BMX3_<DIR>_TRAFFIC_<epoch> <hex th> <hex key>". Returns
// dir -> {th, key} for epoch 0 entries.
func parseKeylogFile(t *testing.T, path string) map[string][2]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read keylog %s: %v", path, err)
	}
	out := map[string][2]string{}
	for _, ln := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		f := strings.Fields(ln)
		if len(f) != 3 || !strings.HasSuffix(f[0], "_TRAFFIC_0") {
			continue
		}
		dir := strings.TrimSuffix(strings.TrimPrefix(f[0], "BMX3_"), "_TRAFFIC_0")
		out[dir] = [2]string{f[1], f[2]}
	}
	return out
}

// M5: with BONEMESH_KEYLOG set, both ends of a session write the same
// directional keys and transcript hash — proof the emitted keys are the real
// shared session keys and the role→direction mapping is correct.
func TestKeylogEmitsAgreeingDirectionalKeys(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	alpha, err := Start(cfgFor(t, rootPub, rootPriv, "alpha"), 0)
	if err != nil {
		t.Fatal(err)
	}
	beta, err := Start(cfgFor(t, rootPub, rootPriv, "beta"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer alpha.Kill()
	defer beta.Kill()

	fa := filepath.Join(t.TempDir(), "a.keylog")
	fb := filepath.Join(t.TempDir(), "b.keylog")
	alpha.tun.keylogPath = fa
	beta.tun.keylogPath = fb

	if _, err := alpha.Connect("127.0.0.1", beta.Port()); err != nil {
		t.Fatal(err)
	}
	// Wait for both ends to write their epoch-0 entries.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if fi, e := os.Stat(fb); e == nil && fi.Size() > 0 {
			if fi2, e2 := os.Stat(fa); e2 == nil && fi2.Size() > 0 {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	a := parseKeylogFile(t, fa)
	b := parseKeylogFile(t, fb)
	for _, dir := range []string{"I2R", "R2I"} {
		if a[dir] == [2]string{} || b[dir] == [2]string{} {
			t.Fatalf("missing %s entry (a=%v b=%v)", dir, a, b)
		}
		if len(a[dir][1]) != 64 {
			t.Fatalf("%s key is not a 32-byte hex value: %q", dir, a[dir][1])
		}
		if a[dir][1] != b[dir][1] {
			t.Fatalf("%s key disagrees between ends: %s vs %s (role→direction mapping wrong)", dir, a[dir][1], b[dir][1])
		}
		if a[dir][0] != b[dir][0] {
			t.Fatalf("%s transcript-hash disagrees: %s vs %s", dir, a[dir][0], b[dir][0])
		}
	}
	// The two directions must use different keys.
	if a["I2R"][1] == a["R2I"][1] {
		t.Fatal("I2R and R2I keys are identical")
	}
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
