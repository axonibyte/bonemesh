// End-to-end BMX handshake tests (security.md §4). Runs the full three-message
// exchange between two in-process parties holding real root-signed certificates,
// asserts both sides derive matching directional transport keys and each other's
// certificate, exercises a transport round-trip over the result, and self-tests
// the authentication oracle by tampering with inputs and pinning a foreign root.
// The root is a throwaway ML-DSA-87 key generated in-test via CIRCL.
package handshake_test

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/axonibyte/bonemesh/gonode/canon"
	"github.com/axonibyte/bonemesh/gonode/cert"
	"github.com/axonibyte/bonemesh/gonode/crypto"
	"github.com/axonibyte/bonemesh/gonode/frame"
	"github.com/axonibyte/bonemesh/gonode/handshake"
	"github.com/axonibyte/bonemesh/gonode/transport"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

const (
	mesh = "acme-prod"
	now  = int64(1500)
)

func newRoot(t *testing.T) ([]byte, *mldsa87.PrivateKey) {
	t.Helper()
	pub, priv, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pub.MarshalBinary()
	return b, priv
}

// issue creates a root-signed certificate for label and returns (cert, idPriv).
func issue(t *testing.T, rootPriv *mldsa87.PrivateKey, label string) (map[string]any, []byte) {
	t.Helper()
	idPub, idPriv := crypto.MLDSA65Generate()
	c := cert.Build(mesh, label, idPub, 1000, 2000)
	pre, err := canon.Canonicalize(c)
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, mldsa87.SignatureSize)
	if err := mldsa87.SignTo(rootPriv, []byte(pre), nil, false, sig); err != nil {
		t.Fatal(err)
	}
	c["sig"] = base64.StdEncoding.EncodeToString(sig)
	return c, idPriv
}

func TestFullHandshake(t *testing.T) {
	root, rootPriv := newRoot(t)
	iCert, iPriv := issue(t, rootPriv, "initiator")
	rCert, rPriv := issue(t, rootPriv, "responder")

	init := handshake.Initiator(mesh, root, now, iCert, iPriv)
	resp := handshake.Responder(mesh, root, now, rCert, rPriv)

	m1 := init.WriteMessage1()
	m2, err := resp.ReadMessage1WriteMessage2(m1)
	if err != nil {
		t.Fatalf("responder rejected msg1: %v", err)
	}
	m3, err := init.ReadMessage2WriteMessage3(m2)
	if err != nil {
		t.Fatalf("initiator rejected msg2: %v", err)
	}
	if err := resp.ReadMessage3(m3); err != nil {
		t.Fatalf("responder rejected msg3: %v", err)
	}

	is, rs := init.SessionResult(), resp.SessionResult()
	if b64(is.SendKey) != b64(rs.ReceiveKey) || b64(is.ReceiveKey) != b64(rs.SendKey) {
		t.Fatal("directional transport keys do not match across the two sides")
	}
	if is.PeerCert["label"] != "responder" {
		t.Fatalf("initiator learned wrong peer: %v", is.PeerCert["label"])
	}
	if rs.PeerCert["label"] != "initiator" {
		t.Fatalf("responder learned wrong peer: %v", rs.PeerCert["label"])
	}

	// Transport round-trip over the negotiated session, both directions. Each
	// carrier crosses the frame wire (Encode -> ReadFrame) so seq arrives as a
	// json.Number, exactly as it does between two real nodes.
	it, rt := transport.New(is), transport.New(rs)
	carrier := it.Seal(map[string]any{"type": "data", "payload": map[string]any{"hi": "there"}})
	got, err := rt.Open(wire(t, carrier))
	if err != nil {
		t.Fatalf("responder could not open initiator frame: %v", err)
	}
	if p, _ := got["payload"].(map[string]any); p["hi"] != "there" {
		t.Fatalf("payload mismatch: %v", got)
	}
	back := rt.Seal(map[string]any{"type": "ack"})
	if _, err := it.Open(wire(t, back)); err != nil {
		t.Fatalf("initiator could not open responder frame: %v", err)
	}
}

// wire round-trips a carrier through the frame codec so integer fields arrive as
// json.Number, matching what a node reads off a socket.
func wire(t *testing.T, carrier map[string]any) map[string]any {
	t.Helper()
	m, reason := frame.Classify(frame.Encode(carrier), frame.TransportCap)
	if reason != "" {
		t.Fatalf("frame classify: %s", reason)
	}
	return m
}

// TestResponderPinsForeignRoot: the responder trusts a root that did not sign
// the initiator's certificate, so it must reject the initiator at msg3 even
// though every cryptographic step of the exchange itself succeeds.
func TestResponderPinsForeignRoot(t *testing.T) {
	realRoot, rootPriv := newRoot(t)
	foreignRoot, _ := newRoot(t)
	iCert, iPriv := issue(t, rootPriv, "initiator")
	rCert, rPriv := issue(t, rootPriv, "responder")

	init := handshake.Initiator(mesh, realRoot, now, iCert, iPriv)
	resp := handshake.Responder(mesh, foreignRoot, now, rCert, rPriv)

	m2, err := resp.ReadMessage1WriteMessage2(init.WriteMessage1())
	if err != nil {
		t.Fatalf("unexpected msg1 rejection: %v", err)
	}
	m3, err := init.ReadMessage2WriteMessage3(m2)
	if err != nil {
		t.Fatalf("initiator (correct root) unexpectedly rejected msg2: %v", err)
	}
	if err := resp.ReadMessage3(m3); err == nil {
		t.Fatal("responder accepted an initiator cert signed by an untrusted root")
	}
}

func TestForeignMeshRejected(t *testing.T) {
	root, rootPriv := newRoot(t)
	iCert, iPriv := issue(t, rootPriv, "initiator")
	rCert, rPriv := issue(t, rootPriv, "responder")

	resp := handshake.Responder(mesh, root, now, rCert, rPriv)
	bad := handshake.Initiator("other-mesh", root, now, iCert, iPriv).WriteMessage1()
	if _, err := resp.ReadMessage1WriteMessage2(bad); err == nil {
		t.Fatal("responder accepted msg1 from a foreign mesh")
	}
}

func TestTamperedAuthRejected(t *testing.T) {
	root, rootPriv := newRoot(t)
	iCert, iPriv := issue(t, rootPriv, "initiator")
	rCert, rPriv := issue(t, rootPriv, "responder")

	init := handshake.Initiator(mesh, root, now, iCert, iPriv)
	resp := handshake.Responder(mesh, root, now, rCert, rPriv)

	m2, err := resp.ReadMessage1WriteMessage2(init.WriteMessage1())
	if err != nil {
		t.Fatal(err)
	}
	m2[len(m2)/2] ^= 0x01 // corrupt the responder's sealed identity
	if _, err := init.ReadMessage2WriteMessage3(m2); err == nil {
		t.Fatal("initiator accepted a tampered responder auth")
	}
}

// Malformed peer input must be rejected as an error, never panic the node — the
// crypto primitives panic on bad-length keys, and an unrecovered goroutine panic
// crashes the process. Interop tier 7's seeded fuzzing surfaced this on the Go
// node. These mirror the Elixir port's graceful-rejection tests.
func TestReadMessage1RejectsMalformedKeys(t *testing.T) {
	root, rootPriv := newRoot(t)
	rCert, rPriv := issue(t, rootPriv, "responder")
	resp := handshake.Responder(mesh, root, now, rCert, rPriv)
	// Right shape and mesh, but "k" decodes to a too-short ML-KEM key — which
	// would panic MLKEM768Encapsulate without the handshake's recover.
	bad := frame.Encode(map[string]any{
		"t": "bmx1", "v": 3, "mesh": mesh,
		"e": b64(make([]byte, 32)), "k": b64([]byte("short")), "n": b64(make([]byte, 32)),
	})
	if _, err := resp.ReadMessage1WriteMessage2(bad); err == nil {
		t.Fatal("expected a malformed bmx1 to be rejected")
	}
}

func TestReadMessage3RejectsGarbage(t *testing.T) {
	root, rootPriv := newRoot(t)
	iCert, iPriv := issue(t, rootPriv, "initiator")
	rCert, rPriv := issue(t, rootPriv, "responder")
	init := handshake.Initiator(mesh, root, now, iCert, iPriv)
	resp := handshake.Responder(mesh, root, now, rCert, rPriv)
	if _, err := resp.ReadMessage1WriteMessage2(init.WriteMessage1()); err != nil {
		t.Fatal(err)
	}
	if err := resp.ReadMessage3([]byte("not-a-valid-bmx3\n")); err == nil {
		t.Fatal("expected a garbage bmx3 to be rejected")
	}
}

func TestReadMessage2RejectsGarbage(t *testing.T) {
	root, rootPriv := newRoot(t)
	iCert, iPriv := issue(t, rootPriv, "initiator")
	init := handshake.Initiator(mesh, root, now, iCert, iPriv)
	init.WriteMessage1()
	if _, err := init.ReadMessage2WriteMessage3([]byte("{bad json\n")); err == nil {
		t.Fatal("expected a garbage bmx2 to be rejected")
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
