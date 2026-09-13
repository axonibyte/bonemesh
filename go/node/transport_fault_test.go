// A transport-level fault tears the session down and names the reason
// (protocol.md §4 and §8, defect D20).
//
// The injection is a seq gap rather than a flipped ciphertext byte: it is
// deterministic and it exercises the ordering rule §4 actually states. Both take
// the same branch (Transport.Open returns an error either way).
//
// What these tests do NOT prove: that the node re-dials and recovers. That is
// tier 10's job over real sockets. The claim here is narrower — the link is torn
// down instead of being kept in a state where receiveSeq can never again match
// what the peer sends, and the peer is told why.
package node

import (
	"bufio"
	"net"
	"testing"
	"time"

	"github.com/axonibyte/bonemesh/gonode/frame"
	"github.com/axonibyte/bonemesh/gonode/handshake"
	"github.com/axonibyte/bonemesh/gonode/message"
	"github.com/axonibyte/bonemesh/gonode/transport"
)

// peerSide returns a transport that is the mirror of the one the node built, so
// the test can both craft frames the node will read and open the frames it writes.
func peerSide(sess *handshake.Session) *transport.Transport {
	return transport.New(&handshake.Session{
		SendKey:    sess.ReceiveKey,
		ReceiveKey: sess.SendKey,
		PeerCert:   sess.PeerCert,
		H:          sess.H,
	})
}

func TestOutOfOrderFrameTearsSessionDownNamingProtocolError(t *testing.T) {
	n := bareNode()
	ca, cb := net.Pipe()
	defer cb.Close()
	sess := dummySession("peer")
	n.register("peer", ca, bufio.NewReader(ca), sess, true)

	peer := peerSide(sess)
	peer.Seal(map[string]any{"type": "probe", "token": 1}) // burns seq 0, never written
	gap := peer.Seal(message.Data("m-gap", "peer", "self", 16, map[string]any{"x": 1}))

	done := make(chan map[string]any, 1)
	go func() {
		r := bufio.NewReader(cb)
		carrier, err := frame.ReadFrame(r, frame.TransportCap)
		if err != nil {
			close(done)
			return
		}
		inner, err := peer.Open(carrier)
		if err != nil {
			close(done)
			return
		}
		done <- inner
	}()

	if _, err := cb.Write(frame.Encode(gap)); err != nil {
		t.Fatalf("could not write the gap frame: %v", err)
	}

	// Oracle 1: the peer is told why, read off the wire rather than inferred.
	select {
	case inner, ok := <-done:
		if !ok {
			t.Fatal("the node closed the session without a readable bye")
		}
		if inner["type"] != "bye" {
			t.Fatalf("expected a bye, got %v", inner["type"])
		}
		if inner["reason"] != "protocol-error" {
			t.Fatalf("wrong close reason: %v", inner["reason"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the node never said why it was closing")
	}

	// Oracle 2: the session is gone, not merely silent.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		n.mu.Lock()
		_, present := n.links["peer"]
		n.mu.Unlock()
		if !present {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the node kept a session whose nonce stream it can never follow again")
}

// §8 requires ignoring inner types a node does not recognize, so an unknown type
// is NOT a protocol error. This is the guard on the test above: making every
// unparseable thing close the link would break forward compatibility.
func TestUnrecognizedInnerTypeDoesNotCloseTheSession(t *testing.T) {
	n := bareNode()
	ca, cb := net.Pipe()
	defer cb.Close()
	sess := dummySession("peer")
	n.register("peer", ca, bufio.NewReader(ca), sess, true)

	peer := peerSide(sess)
	carrier := peer.Seal(map[string]any{"type": "quux-from-the-future", "mid": "m1"})
	if _, err := cb.Write(frame.Encode(carrier)); err != nil {
		t.Fatalf("could not write the frame: %v", err)
	}

	// Assert the absence with time allowed to pass, then prove the link is still
	// usable rather than merely still listed.
	time.Sleep(500 * time.Millisecond)
	n.mu.Lock()
	_, present := n.links["peer"]
	n.mu.Unlock()
	if !present {
		t.Fatal("the node closed a session over an inner type it must ignore")
	}

	got := make(chan map[string]any, 1)
	go func() {
		r := bufio.NewReader(cb)
		c, err := frame.ReadFrame(r, frame.TransportCap)
		if err != nil {
			close(got)
			return
		}
		inner, err := peer.Open(c)
		if err != nil {
			close(got)
			return
		}
		got <- inner
	}()
	if !n.sendToLink("peer", message.Bye("idle")) {
		t.Fatal("the link survived the unknown type but could no longer be written to")
	}
	select {
	case inner, ok := <-got:
		if !ok || inner["type"] != "bye" {
			t.Fatalf("the link survived but its frames no longer open: %v", inner)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the link survived the unknown type but carried nothing afterwards")
	}
}

// The bye goes out on the link that faulted, not on whatever link is current for
// that peer. A reconnect can make a different link current between the fault and
// the announcement; sealing this link's fault with that link's keys would write a
// frame the peer cannot open, on a session that is fine.
//
// This is a white-box property about which socket is written, so it is staged
// directly: link2 is made current WITHOUT going through register, which would
// close the displaced link and destroy the state under test.
func TestProtocolErrorAnnouncesOnTheFaultingLinkNotTheCurrentOne(t *testing.T) {
	n := bareNode()
	a1, b1 := net.Pipe()
	a2, b2 := net.Pipe()
	defer b1.Close()
	defer b2.Close()

	sess1, sess2 := dummySession("peer"), dummySession("peer")
	n.register("peer", a1, bufio.NewReader(a1), sess1, true)
	faulting := n.links["peer"]
	lk2 := &link{conn: a2, transport: transport.New(sess2), initiator: true}
	n.mu.Lock()
	n.links["peer"] = lk2 // a reconnect won; the faulting link is now stale
	n.mu.Unlock()

	got := make(chan string, 2)
	read := func(c net.Conn, name string) {
		r := bufio.NewReader(c)
		if _, err := frame.ReadFrame(r, frame.TransportCap); err == nil {
			got <- name
		}
	}
	go read(b1, "faulting")
	go read(b2, "current")

	n.protocolError(faulting)

	select {
	case which := <-got:
		if which != "faulting" {
			t.Fatalf("the bye was written to the %s link", which)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the bye was written to neither link")
	}

	// And nothing reached the healthy link: assert the absence with time allowed
	// to pass, after the precondition above has already been established.
	select {
	case which := <-got:
		t.Fatalf("a second frame reached the %s link", which)
	case <-time.After(300 * time.Millisecond):
	}
}
