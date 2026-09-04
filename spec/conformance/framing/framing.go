// Package framing implements the BoneMesh v3 frame reader (protocol.md §2): one
// newline-terminated UTF-8 JSON object per frame, within a hard size cap. It is
// the enforcement point for defect D7 (unbounded input).
package framing

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"
)

// Cap constants (protocol.md §0).
const (
	HandshakeCap = 16384
	TransportCap = 65536
)

// Classify reads the first frame from raw and returns the decoded object, or a
// non-empty reason tag describing why the frame is rejected. It reads only up
// to the first newline: bytes after it belong to the next frame, exactly as a
// streaming reader would see them.
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
