// Package frame implements the BoneMesh v3 frame reader/writer (protocol.md §2):
// one newline-terminated UTF-8 JSON object per frame within a hard size cap
// (defect D7). Classification verdicts match the shared corpus
// (spec/corpus/framing.json).
package frame

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

const (
	// HandshakeCap is the maximum handshake frame size (bytes, incl. newline).
	HandshakeCap = 32768
	// TransportCap is the maximum transport frame size (bytes, incl. newline).
	TransportCap = 65536
)

// Classify returns the decoded object, or a non-empty reason tag, reading only
// up to the first newline.
func Classify(raw []byte, cap int) (map[string]any, string) {
	nl := bytes.IndexByte(raw, '\n')
	if nl < 0 {
		return nil, "no-newline"
	}
	if nl+1 > cap {
		return nil, "oversize"
	}
	content := raw[:nl]
	if len(content) == 0 {
		return nil, "empty"
	}
	if !utf8.Valid(content) {
		return nil, "invalid-utf8"
	}
	dec := json.NewDecoder(bytes.NewReader(content))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, "invalid-json"
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, "trailing-data"
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, "not-an-object"
	}
	return m, ""
}

// Encode writes an object as a frame body followed by a newline.
func Encode(object map[string]any) []byte {
	b, _ := json.Marshal(object)
	return append(b, '\n')
}

// ReadFrame reads one frame from r, bounded by cap.
func ReadFrame(r *bufio.Reader, cap int) (map[string]any, error) {
	line, err := readLine(r, cap)
	if err != nil {
		return nil, err
	}
	m, reason := Classify(line, cap)
	if reason != "" {
		return nil, errors.New(reason)
	}
	return m, nil
}

func readLine(r *bufio.Reader, cap int) ([]byte, error) {
	buf := make([]byte, 0, 512)
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if len(buf) >= cap {
			return nil, errors.New("oversize")
		}
		buf = append(buf, b)
		if b == '\n' {
			return buf, nil
		}
	}
}
