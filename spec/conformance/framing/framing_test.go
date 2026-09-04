package framing

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/axonibyte/bonemesh/conformance/corpus"
)

type framingDoc struct {
	Cases []struct {
		Name     string `json:"name"`
		Kind     string `json:"kind"`
		BytesB64 string `json:"bytes_b64"`
		Expect   string `json:"expect"`
		Reason   string `json:"reason"`
	} `json:"cases"`
	SizeCases struct {
		HandshakeCap int `json:"handshake_cap"`
		TransportCap int `json:"transport_cap"`
	} `json:"size_cases"`
}

func capFor(kind string) int {
	if kind == "handshake" {
		return HandshakeCap
	}
	return TransportCap
}

func TestFramingCorpus(t *testing.T) {
	var doc framingDoc
	if err := corpus.LoadInto("framing.json", &doc); err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("corpus has no framing cases")
	}
	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			raw, err := base64.StdEncoding.DecodeString(c.BytesB64)
			if err != nil {
				t.Fatalf("bad bytes_b64: %v", err)
			}
			_, reason := Classify(raw, capFor(c.Kind))
			accepted := reason == ""
			if c.Expect == "accept" && !accepted {
				t.Errorf("expected accept, got reject(%q)", reason)
			}
			if c.Expect == "reject" {
				if accepted {
					t.Errorf("expected reject(%q), got accept", c.Reason)
				} else if reason != c.Reason {
					t.Errorf("reject reason mismatch: got %q want %q", reason, c.Reason)
				}
			}
		})
	}

	// Size boundary, generated from the pinned caps: a frame whose total length
	// (including the newline) is exactly the cap is accepted; one byte over is
	// rejected as oversize.
	if doc.SizeCases.TransportCap != TransportCap {
		t.Fatalf("corpus transport cap %d disagrees with code %d", doc.SizeCases.TransportCap, TransportCap)
	}
	for _, over := range []int{0, 1} {
		total := TransportCap + over
		line := lineOfLength(total) // includes trailing newline
		_, reason := Classify(line, TransportCap)
		if over == 0 && reason != "" {
			t.Errorf("frame at exactly the cap should accept, got %q", reason)
		}
		if over == 1 && reason != "oversize" {
			t.Errorf("frame one byte over the cap should be oversize, got %q", reason)
		}
	}
}

// lineOfLength builds a valid JSON object line {"p":"AAor..."} whose total
// length including the terminating newline equals n.
func lineOfLength(n int) []byte {
	const wrapper = `{"p":""}` // 8 bytes; +1 newline = 9 of overhead
	fill := n - len(wrapper) - 1
	if fill < 0 {
		panic(fmt.Sprintf("length %d too small", n))
	}
	return []byte(`{"p":"` + strings.Repeat("A", fill) + `"}` + "\n")
}
