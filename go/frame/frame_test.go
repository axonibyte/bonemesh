// Frame classification tests. Verdicts mirror the shared corpus
// (spec/corpus/framing.json, protocol.md §2): one newline-terminated JSON
// object per frame, within a hard size cap (defect D7).
package frame

import (
	"bufio"
	"bytes"
	"testing"
)

func TestClassifyValid(t *testing.T) {
	m, reason := Classify([]byte(`{"t":"bmx1","v":3}`+"\n"), HandshakeCap)
	if reason != "" {
		t.Fatalf("unexpected reason %q", reason)
	}
	if m["t"] != "bmx1" {
		t.Fatalf("bad decode: %v", m)
	}
}

func TestClassifyVerdicts(t *testing.T) {
	cases := []struct {
		name   string
		raw    string
		cap    int
		reason string
	}{
		{"no-newline", `{"a":1}`, HandshakeCap, "no-newline"},
		{"empty", "\n", HandshakeCap, "empty"},
		{"invalid-json", "{not json}\n", HandshakeCap, "invalid-json"},
		{"trailing-data", `{"a":1} {"b":2}` + "\n", HandshakeCap, "trailing-data"},
		{"not-an-object", "[1,2,3]\n", HandshakeCap, "not-an-object"},
		{"oversize", `{"a":1}` + "\n", 4, "oversize"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, reason := Classify([]byte(c.raw), c.cap)
			if reason != c.reason {
				t.Fatalf("got %q want %q", reason, c.reason)
			}
		})
	}
}

func TestClassifyInvalidUTF8(t *testing.T) {
	raw := append([]byte{'{', '"', 'a', '"', ':', '"', 0xff, 0xfe, '"', '}'}, '\n')
	if _, reason := Classify(raw, HandshakeCap); reason != "invalid-utf8" {
		t.Fatalf("got %q want invalid-utf8", reason)
	}
}

func TestEncodeReadRoundTrip(t *testing.T) {
	obj := map[string]any{"t": "bmx1", "mesh": "acme"}
	enc := Encode(obj)
	if enc[len(enc)-1] != '\n' {
		t.Fatal("Encode did not terminate with newline")
	}
	r := bufio.NewReader(bytes.NewReader(enc))
	got, err := ReadFrame(r, HandshakeCap)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if got["t"] != "bmx1" || got["mesh"] != "acme" {
		t.Fatalf("roundtrip mismatch: %v", got)
	}
}

func TestReadFrameEnforcesCap(t *testing.T) {
	big := append(bytes.Repeat([]byte("a"), 100), '\n')
	r := bufio.NewReader(bytes.NewReader(big))
	if _, err := ReadFrame(r, 10); err == nil {
		t.Fatal("expected oversize error")
	}
}
