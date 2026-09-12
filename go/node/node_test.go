// Node integration test: a three-node line alpha—beta—gamma over loopback TCP.
// alpha and gamma are not direct neighbors, so a message from alpha to gamma
// must be relayed through beta once distance-vector discovery gives alpha a
// route. Exercises the routing/heartbeat/relay path end to end in one process.
package node_test

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/axonibyte/bonemesh/gonode/canon"
	"github.com/axonibyte/bonemesh/gonode/cert"
	"github.com/axonibyte/bonemesh/gonode/crypto"
	"github.com/axonibyte/bonemesh/gonode/node"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

const mesh = "acme-prod"

func newRoot(t *testing.T) ([]byte, *mldsa87.PrivateKey) {
	t.Helper()
	pub, priv, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pub.MarshalBinary()
	return b, priv
}

func config(t *testing.T, root []byte, rootPriv *mldsa87.PrivateKey, label string) node.Config {
	t.Helper()
	idPub, idPriv := crypto.MLDSA65Generate()
	c := cert.Build(mesh, label, idPub, 1000, 1<<40)
	pre, err := canon.Canonicalize(c)
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, mldsa87.SignatureSize)
	if err := mldsa87.SignTo(rootPriv, []byte(pre), nil, false, sig); err != nil {
		t.Fatal(err)
	}
	c["sig"] = base64.StdEncoding.EncodeToString(sig)
	return node.Config{Label: label, Mesh: mesh, RootPublic: root, Cert: c, IDPrivate: idPriv}
}

func TestThreeNodeLineRelay(t *testing.T) {
	root, rootPriv := newRoot(t)
	start := func(label string) *node.Node {
		n, err := node.Start(config(t, root, rootPriv, label), 0)
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

	got := gamma.AddListener()

	// Line topology: alpha <-> beta <-> gamma. alpha and gamma never connect.
	if _, err := alpha.Connect("127.0.0.1", beta.Port()); err != nil {
		t.Fatal(err)
	}
	if _, err := gamma.Connect("127.0.0.1", beta.Port()); err != nil {
		t.Fatal(err)
	}

	// Wait for discovery to give alpha a route to gamma (learned via beta), then
	// the relayed message to arrive.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if alpha.Send("gamma", map[string]any{"m": "relayed"}) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	select {
	case payload := <-got:
		if payload["m"] != "relayed" {
			t.Fatalf("gamma got unexpected payload: %v", payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("gamma never received the relayed message")
	}

	if nh := alpha.RouteTable()["gamma"]; nh != "beta" {
		t.Fatalf("alpha's route to gamma should be via beta, got %q", nh)
	}
}

// The destination of a delivered message returns an ack that reaches the
// origin's ack listener, correlated by the mid SendM returned (protocol.md §7).
func TestAckReachesOriginListener(t *testing.T) {
	root, rootPriv := newRoot(t)
	alpha, err := node.Start(config(t, root, rootPriv, "alpha"), 0)
	if err != nil {
		t.Fatal(err)
	}
	beta, err := node.Start(config(t, root, rootPriv, "beta"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer alpha.Kill()
	defer beta.Kill()

	acks := alpha.AckListener()
	if _, err := alpha.Connect("127.0.0.1", beta.Port()); err != nil {
		t.Fatal(err)
	}

	var mid string
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		var ok bool
		if mid, ok = alpha.SendM("beta", map[string]any{"m": "hi"}); ok {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	select {
	case a := <-acks:
		if a["type"] != "ack" {
			t.Fatalf("expected an ack, got %v", a["type"])
		}
		if a["mid"] != mid {
			t.Fatalf("ack mid %v does not match sent mid %q", a["mid"], mid)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("origin never received an ack for its delivered message")
	}
}

// Broadcast reaches every peer with a live session and never the sender
// (protocol.md §6). Both halves of the D5 fix are asserted: direct session peers
// ARE targeted, because the v2 implementation iterated indirect routes only, and
// the node's own label is NOT, because it could appear among its own routes.
func TestBroadcastReachesEveryPeerButNeverTheSender(t *testing.T) {
	root, rootPriv := newRoot(t)
	start := func(label string) *node.Node {
		n, err := node.Start(config(t, root, rootPriv, label), 0)
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

	betaGot := beta.AddListener()
	gammaGot := gamma.AddListener()
	alphaGot := alpha.AddListener()

	if _, err := alpha.Connect("127.0.0.1", beta.Port()); err != nil {
		t.Fatal(err)
	}
	if _, err := alpha.Connect("127.0.0.1", gamma.Port()); err != nil {
		t.Fatal(err)
	}

	if handed := alpha.Broadcast(map[string]any{"m": "all"}); handed != 2 {
		t.Fatalf("broadcast handed off to %d destinations, want 2", handed)
	}
	for name, ch := range map[string]<-chan map[string]any{"beta": betaGot, "gamma": gammaGot} {
		select {
		case p := <-ch:
			if p["m"] != "all" {
				t.Errorf("%s got unexpected payload: %v", name, p)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("%s never received the broadcast", name)
		}
	}

	// Assert the absence with time allowed to pass, and after the positives, so a
	// failure reads as "the sender got its own broadcast" rather than as a timeout.
	select {
	case p := <-alphaGot:
		t.Fatalf("the sender received its own broadcast: %v", p)
	case <-time.After(500 * time.Millisecond):
	}
}

// Each destination gets its own mid. Forced, not stylistic: dedup keys on
// (mid, chunk index), so a shared mid would have the first relay suppress every
// other copy, and an ack names only a mid.
func TestBroadcastGivesEachDestinationItsOwnMessageID(t *testing.T) {
	root, rootPriv := newRoot(t)
	start := func(label string) *node.Node {
		n, err := node.Start(config(t, root, rootPriv, label), 0)
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

	acks := alpha.AckListener()
	if _, err := alpha.Connect("127.0.0.1", beta.Port()); err != nil {
		t.Fatal(err)
	}
	if _, err := alpha.Connect("127.0.0.1", gamma.Port()); err != nil {
		t.Fatal(err)
	}
	if handed := alpha.Broadcast(map[string]any{"m": "all"}); handed != 2 {
		t.Fatalf("broadcast handed off to %d destinations, want 2", handed)
	}

	seen := map[string]bool{}
	deadline := time.After(10 * time.Second)
	for len(seen) < 2 {
		select {
		case a := <-acks:
			if mid, ok := a["mid"].(string); ok {
				seen[mid] = true
			}
		case <-deadline:
			t.Fatalf("expected one ack per destination with distinct mids, saw %d", len(seen))
		}
	}
}
