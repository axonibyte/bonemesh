// Command fuzzer is the Tier 7 seeded fuzzer (methodology tier 7): from a single
// seed it drives a node under test (any implementation, in listen mode) through
// many randomized, replayable mutation strategies over frames, handshake
// messages, and transport payloads. The seed is printed and accepted back via
// --seed, so any failure reproduces exactly.
//
// It is the initiator; the node under test is the responder. Like the tier 5
// fault peer it reuses the Go port's stack to build genuinely valid messages,
// then corrupts them at a seeded point — so a rejection reflects the node, not a
// broken peer. Every strategy that reaches the transport phase corrupts the
// frame, so a correct node delivers nothing across the whole run.
//
// This binary only causes the faults. The oracle lives in interop/tier7.sh: the
// listener's output stays empty through the run, then a final valid send
// delivers — self-testing the oracle and proving the node survived every case.
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/axonibyte/bonemesh/gonode/frame"
	"github.com/axonibyte/bonemesh/gonode/handshake"
	"github.com/axonibyte/bonemesh/gonode/message"
	"github.com/axonibyte/bonemesh/gonode/transport"
)

func main() {
	f := flags(os.Args[1:])
	seed, _ := strconv.ParseInt(f["seed"], 10, 64)
	iterations := 200
	if n, err := strconv.Atoi(f["iterations"]); err == nil {
		iterations = n
	}
	fmt.Fprintf(os.Stderr, "fuzzer: seed=%d iterations=%d\n", seed, iterations)
	rng := rand.New(rand.NewSource(seed))

	const strategies = 8
	for i := 0; i < iterations; i++ {
		runOne(rng, rng.Intn(strategies), f)
	}
	fmt.Fprintf(os.Stderr, "fuzzer: %d iterations done\n", iterations)
}

func runOne(rng *rand.Rand, strategy int, f map[string]string) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(f["host"], f["port"]), 5*time.Second)
	if err != nil {
		return // listener busy/gone; the oracle catches a truly dead node via the control
	}
	defer conn.Close()
	_ = conn.SetDeadline(timeNow().Add(5 * time.Second))

	switch strategy {
	case 0: // random bytes, then newline
		conn.Write(append(randomBytes(rng, 1+rng.Intn(200)), '\n'))
	case 1: // a frame body with no terminating newline
		conn.Write(randomBytes(rng, 1+rng.Intn(64)))
	case 2: // oversize single line
		conn.Write(append(bytes.Repeat([]byte("A"), frame.HandshakeCap+1+rng.Intn(4096)), '\n'))
	case 3: // valid bmx1 with random bytes flipped
		m1 := initiator(f["mesh"], f).WriteMessage1()
		conn.Write(flip(rng, m1))
	case 4: // valid bmx1 with a field corrupted to invalid base64 / wrong type
		conn.Write(corruptBmx1(rng, f))
	case 5: // valid bmx1, then random garbage where bmx3 belongs
		hs := initiator(f["mesh"], f)
		conn.Write(hs.WriteMessage1())
		readFrame(conn)
		conn.Write(append(randomBytes(rng, 1+rng.Intn(120)), '\n'))
	case 6: // full handshake to bmx3, then bytes flipped in bmx3
		hs := initiator(f["mesh"], f)
		conn.Write(hs.WriteMessage1())
		m2 := readFrame(conn)
		if m2 == nil {
			return
		}
		m3, err := hs.ReadMessage2WriteMessage3(frame.Encode(m2))
		if err != nil {
			return
		}
		conn.Write(flip(rng, m3))
	case 7: // full handshake, then a corrupted transport frame
		t := completeHandshake(conn, f)
		if t == nil {
			return
		}
		carrier := t.Seal(message.Data(message.NewMID(), "fuzz", f["to"], message.DefaultTTL, map[string]any{"probe": "should-not-arrive"}))
		switch rng.Intn(3) {
		case 0: // corrupt ciphertext
			carrier["ct"] = corruptB64(rng, carrier["ct"].(string))
		case 1: // wrong sequence number
			carrier["seq"] = 1 + rng.Intn(1000)
		case 2: // replace ct with random base64
			carrier["ct"] = base64.StdEncoding.EncodeToString(randomBytes(rng, 32+rng.Intn(64)))
		}
		conn.Write(frame.Encode(carrier))
		time.Sleep(50 * time.Millisecond)
	}
}

func completeHandshake(conn net.Conn, f map[string]string) *transport.Transport {
	hs := initiator(f["mesh"], f)
	conn.Write(hs.WriteMessage1())
	m2 := readFrame(conn)
	if m2 == nil {
		return nil
	}
	m3, err := hs.ReadMessage2WriteMessage3(frame.Encode(m2))
	if err != nil {
		return nil
	}
	conn.Write(m3)
	return transport.New(hs.SessionResult())
}

func corruptBmx1(rng *rand.Rand, f map[string]string) []byte {
	m1 := initiator(f["mesh"], f).WriteMessage1()
	var obj map[string]any
	dec := json.NewDecoder(bytes.NewReader(m1))
	dec.UseNumber()
	if dec.Decode(&obj) != nil {
		return m1
	}
	switch rng.Intn(4) {
	case 0:
		obj["e"] = "!!!not-base64!!!"
	case 1:
		obj["k"] = rng.Intn(1000) // wrong type
	case 2:
		delete(obj, "n")
	case 3:
		obj["v"] = 99 // unsupported version
	}
	return frame.Encode(obj)
}

func initiator(mesh string, f map[string]string) *handshake.Handshake {
	return handshake.Initiator(mesh, decodeB64(read(f["root-pub"])), timeNow().Unix(), loadCert(f["cert"]), decodeB64(read(f["id-priv"])))
}

func readFrame(conn net.Conn) map[string]any {
	m, err := frame.ReadFrame(bufio.NewReader(conn), frame.HandshakeCap)
	if err != nil {
		return nil
	}
	return m
}

func flip(rng *rand.Rand, b []byte) []byte {
	out := append([]byte{}, b...)
	// Flip a handful of bytes, avoiding the trailing newline.
	n := len(out) - 1
	if n <= 0 {
		return out
	}
	for i := 0; i < 1+rng.Intn(4); i++ {
		out[rng.Intn(n)] ^= byte(1 + rng.Intn(255))
	}
	return out
}

func corruptB64(rng *rand.Rand, s string) string {
	b, _ := base64.StdEncoding.DecodeString(s)
	if len(b) > 0 {
		b[rng.Intn(len(b))] ^= byte(1 + rng.Intn(255))
	}
	return base64.StdEncoding.EncodeToString(b)
}

func randomBytes(rng *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.Intn(256))
	}
	// Keep an embedded newline out of it so it stays a single frame.
	for i := range b {
		if b[i] == '\n' {
			b[i] = ' '
		}
	}
	return b
}

func loadCert(path string) map[string]any {
	dec := json.NewDecoder(bytes.NewReader([]byte(read(path))))
	dec.UseNumber()
	var m map[string]any
	if dec.Decode(&m) != nil {
		return map[string]any{}
	}
	return m
}

func read(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fuzzer:", err)
		os.Exit(1)
	}
	return string(b)
}

func decodeB64(s string) []byte {
	b, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
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

func timeNow() time.Time { return time.Now() }
