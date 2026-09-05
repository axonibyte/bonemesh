// Command faultpeer is the Tier 5 fake peer (methodology tier 5): it connects to
// a node under test (any implementation, running in listen mode) and executes
// one deterministic fault scenario — malformed frames, oversize input, aborted
// or tampered handshakes, or a corrupted transport frame — then exits. It is the
// initiator; the node under test is the responder.
//
// The peer is language-agnostic about who it talks to: it drives every
// implementation as a black box over TCP. It is itself implemented in Go,
// reusing the Go port's crypto/handshake/frame/transport stack to produce
// genuinely valid messages that it then corrupts at a chosen point — so a
// rejection reflects the node under test, not a broken peer.
//
// This binary only causes the fault. The oracle lives in interop/tier5.sh: for a
// fault scenario the listener's output file must stay empty (nothing delivered);
// a final "valid-send" must deliver, self-testing that the oracle can see a
// delivery at all and that the node survived the whole battery.
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/axonibyte/bonemesh/gonode/frame"
	"github.com/axonibyte/bonemesh/gonode/handshake"
	"github.com/axonibyte/bonemesh/gonode/message"
	"github.com/axonibyte/bonemesh/gonode/transport"
)

func main() {
	f := flags(os.Args[1:])
	scenario := f["scenario"]
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(f["host"], f["port"]), 5*time.Second)
	if err != nil {
		fail("dial: " + err.Error())
	}
	defer conn.Close()

	switch scenario {
	case "garbage":
		// Not JSON at all.
		conn.Write([]byte("this is definitely not json\n"))
	case "oversize":
		// A single line larger than the handshake cap.
		conn.Write(append(bytes.Repeat([]byte("a"), frame.HandshakeCap+1024), '\n'))
	case "truncated":
		// A frame body with no terminating newline, then close.
		conn.Write([]byte(`{"t":"bmx1","v":3`))
	case "wrong-mesh-bmx1":
		// Structurally valid bmx1, but for a mesh the node is not in.
		hs := initiator("wrong-mesh-entirely", f)
		conn.Write(hs.WriteMessage1())
	case "abort-after-bmx1":
		// Valid bmx1, then hang up before bmx3.
		hs := initiator(f["mesh"], f)
		conn.Write(hs.WriteMessage1())
	case "garbage-bmx3":
		// Valid bmx1, read bmx2, then send garbage where bmx3 belongs.
		hs := initiator(f["mesh"], f)
		conn.Write(hs.WriteMessage1())
		readFrame(conn)
		conn.Write([]byte("not-a-valid-bmx3\n"))
	case "tampered-bmx3":
		// Complete through bmx3, flip a byte in it, then send.
		hs := initiator(f["mesh"], f)
		conn.Write(hs.WriteMessage1())
		m2 := readFrame(conn)
		m3, err := hs.ReadMessage2WriteMessage3(frame.Encode(m2))
		if err != nil {
			fail("unexpected bmx2 rejection: " + err.Error())
		}
		m3[len(m3)/2] ^= 0x01
		conn.Write(m3)
	case "bad-transport":
		// Complete a real handshake, then send a transport frame with a
		// corrupted ciphertext. The node must drop it, not deliver it.
		t := completeHandshake(conn, f)
		carrier := t.Seal(dataMsg(f, "should-not-arrive"))
		carrier["ct"] = corruptB64(carrier["ct"].(string))
		conn.Write(frame.Encode(carrier))
		time.Sleep(500 * time.Millisecond)
	case "valid-send":
		// Positive control: a correct handshake and a real data frame.
		t := completeHandshake(conn, f)
		conn.Write(frame.Encode(t.Seal(dataMsg(f, f["marker"]))))
		time.Sleep(1 * time.Second)
	default:
		fail("unknown scenario: " + scenario)
	}
	fmt.Fprintf(os.Stderr, "faultpeer: scenario %q done\n", scenario)
}

func completeHandshake(conn net.Conn, f map[string]string) *transport.Transport {
	hs := initiator(f["mesh"], f)
	conn.Write(hs.WriteMessage1())
	m2 := readFrame(conn)
	m3, err := hs.ReadMessage2WriteMessage3(frame.Encode(m2))
	if err != nil {
		fail("handshake bmx2 rejected: " + err.Error())
	}
	conn.Write(m3)
	return transport.New(hs.SessionResult())
}

func initiator(mesh string, f map[string]string) *handshake.Handshake {
	root := decodeB64(read(f["root-pub"]))
	idPriv := decodeB64(read(f["id-priv"]))
	cert := loadCert(f["cert"])
	return handshake.Initiator(mesh, root, time.Now().Unix(), cert, idPriv)
}

func dataMsg(f map[string]string, marker string) map[string]any {
	label, _ := loadCert(f["cert"])["label"].(string)
	return message.Data(message.NewMID(), label, f["to"], message.DefaultTTL, map[string]any{"probe": marker})
}

func readFrame(conn net.Conn) map[string]any {
	r := bufio.NewReader(conn)
	m, err := frame.ReadFrame(r, frame.HandshakeCap)
	if err != nil {
		fail("reading frame: " + err.Error())
	}
	return m
}

func corruptB64(s string) string {
	b, _ := base64.StdEncoding.DecodeString(s)
	if len(b) > 0 {
		b[len(b)/2] ^= 0x01
	}
	return base64.StdEncoding.EncodeToString(b)
}

func loadCert(path string) map[string]any {
	dec := json.NewDecoder(bytes.NewReader([]byte(read(path))))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		fail("cert decode: " + err.Error())
	}
	return m
}

func read(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		fail(err.Error())
	}
	return string(b)
}

func decodeB64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		fail("base64: " + err.Error())
	}
	return b
}

func flags(args []string) map[string]string {
	m := map[string]string{}
	for i := 0; i+1 < len(args); i += 2 {
		if strings.HasPrefix(args[i], "--") {
			m[args[i][2:]] = args[i+1]
		}
	}
	return m
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "faultpeer: "+msg)
	os.Exit(1)
}
