// Verifies bonemesh-inspect against the shared key-log vector
// (spec/corpus/keylog.json): every captured frame, opened with its direction's
// key, must reproduce the expected inner message. This is the oracle the
// six-language key-log emitters are checked against in tier 10 — if this test
// and the vector agree, an emitter that produces a compatible log is decryptable
// by this one inspector.
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const corpusPath = "../../../spec/corpus/keylog.json"

type keylogVector struct {
	Keylog   []string         `json:"keylog"`
	Capture  []map[string]any `json:"capture"`
	Expected []map[string]any `json:"expected"`
}

func loadVector(t *testing.T) keylogVector {
	t.Helper()
	raw, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatalf("read %s: %v", corpusPath, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v keylogVector
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("parse %s: %v", corpusPath, err)
	}
	if len(v.Capture) == 0 || len(v.Capture) != len(v.Expected) {
		t.Fatalf("vector malformed: %d capture, %d expected", len(v.Capture), len(v.Expected))
	}
	return v
}

// keysFromVector writes the vector's key-log lines to a temp file and runs them
// back through the tool's own parseKeylog, so the label-parsing and hex-decoding
// paths are exercised, not reimplemented.
func keysFromVector(t *testing.T, v keylogVector) map[string][]keyEntry {
	t.Helper()
	klPath := filepath.Join(t.TempDir(), "keylog")
	if err := os.WriteFile(klPath, []byte(join(v.Keylog)), 0o644); err != nil {
		t.Fatal(err)
	}
	entries := parseKeylog(klPath)
	if len(entries) == 0 {
		t.Fatal("parseKeylog found no entries in the vector key-log")
	}
	return indexKeys(entries)
}

func join(lines []string) string {
	out := ""
	for _, l := range lines {
		out += l + "\n"
	}
	return out
}

func TestInspectReproducesCorpusVector(t *testing.T) {
	v := loadVector(t)
	byDir := keysFromVector(t, v)

	for i, frame := range v.Capture {
		line, _ := json.Marshal(frame)
		got, reason := openFrame(line, byDir)
		if reason != "" {
			t.Fatalf("frame %d: openFrame failed: %s", i, reason)
		}
		// Compare structurally: both sides decode integers as json.Number and
		// json.Marshal sorts map keys, so canonical JSON bytes must match.
		gotJSON, _ := json.Marshal(got)
		wantJSON, _ := json.Marshal(v.Expected[i])
		if !bytes.Equal(gotJSON, wantJSON) {
			t.Fatalf("frame %d mismatch:\n got  %s\n want %s", i, gotJSON, wantJSON)
		}
	}
}

// A frame that no key can open must be reported, not silently rendered — the
// self-test of the oracle: feed it a ciphertext a broken emitter would produce.
func TestInspectRejectsUnopenableFrame(t *testing.T) {
	v := loadVector(t)
	byDir := keysFromVector(t, v)
	// Valid-looking envelope, but ct is not something any key seals.
	line := []byte(`{"dir":"i2r","frame":{"seq":0,"ct":"AAAAAAAAAAAAAAAAAAAAAA=="}}`)
	if _, reason := openFrame(line, byDir); reason == "" {
		t.Fatal("openFrame accepted a frame no key could open")
	}
}

// A key-log line with an unknown label shape is ignored (forward-compatible),
// not fatal.
func TestParseLabelRejectsUnknownForms(t *testing.T) {
	for _, bad := range []string{"CLIENT_HANDSHAKE_0", "BMX3_X2Y_TRAFFIC_0", "BMX3_I2R_TRAFFIC_notanumber"} {
		if _, _, ok := parseLabel(bad); ok {
			t.Fatalf("parseLabel accepted unknown label %q", bad)
		}
	}
	if dir, epoch, ok := parseLabel("BMX3_R2I_TRAFFIC_2"); !ok || dir != "r2i" || epoch != 2 {
		t.Fatalf("parseLabel(BMX3_R2I_TRAFFIC_2) = %q,%d,%v", dir, epoch, ok)
	}
}
