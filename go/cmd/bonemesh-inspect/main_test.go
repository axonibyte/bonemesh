// Verifies bonemesh-inspect against the shared key-log vector: every captured
// frame, opened with its direction's key, must reproduce the expected inner
// message. This is the oracle the seven key-log emitters are checked against in
// tier 10 — if this test and the vector agree, an emitter that produces a
// compatible log is decryptable by this one inspector.
//
// The vector is MIRRORED below rather than read from spec/corpus/keylog.json.
// This test used to load that file, and it was the only test in the repository
// that did: inside the bonemesh-gonode reaper tenant only go/ is synced, so the
// path did not exist and the tenant had been failing. Every other in-tenant suite
// in every language mirrors its vectors for exactly this reason. The byte-exact
// comparison against the committed corpus lives where the whole tree is present,
// in interop/check-keylog-go.sh.
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// mirroredVector mirrors spec/corpus/keylog.json. Keep it in step with that file;
// interop/check-keylog-go.sh is what fails if it drifts.
const mirroredVector = `{
  "keylog": [
    "# BoneMesh key-log vector (security.md §8): BMX3_<DIR>_TRAFFIC_<epoch> <hex transcript-hash> <hex key>",
    "BMX3_I2R_TRAFFIC_0 0000000000000000000000000000000000000000000000000000000000000000 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    "BMX3_R2I_TRAFFIC_0 0000000000000000000000000000000000000000000000000000000000000000 6465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283"
  ],
  "capture": [
    {
      "dir": "i2r",
      "frame": {
        "ct": "GKixZAiviwO5Klog/7+PFNmx5p17/k48GJC1OPWOhOnztzXzT+r2Mspgu7uMvQMNqyXFU8Tk9I1bOY2YhZv4XiOxg0HEPqoXlNNo4t/xjc9V9jQqbmpQuqZGLMo1eBKc/Hgjk3QqZdD3L52qa9jF2Mc6AWA6W6M8/gav0zI/2YVlAQ3KcuZH",
        "seq": 0
      }
    },
    {
      "dir": "i2r",
      "frame": {
        "ct": "G/c0CnjhpyoOQUTiZ/+gYSPRgjwx9268tK7He1j33akVi5UqwZ58IgGD+0I2PzXlpr8LU3kd",
        "seq": 1
      }
    },
    {
      "dir": "r2i",
      "frame": {
        "ct": "Y3ENJRyFKXhMHofmTbr5R/XYD8FCinLvipXFtSJKMmX5fiq22OvDLXcLVXJRbFz+K2iTm9N6Ck/ag/auGychQRj3BMBN46c2xH0BdCjjy6ckpXT5XGN15e9Rgj05WC2d9DAp+QZjBwFeJ7I=",
        "seq": 0
      }
    }
  ],
  "expected": [
    {
      "dir": "i2r",
      "epoch": 0,
      "inner": {
        "from": "alpha",
        "mid": "0123456789abcdef0123456789abcdef",
        "payload": {
          "line": "hello"
        },
        "to": "beta",
        "ttl": 16,
        "type": "data"
      },
      "seq": 0
    },
    {
      "dir": "i2r",
      "epoch": 0,
      "inner": {
        "token": 1788000000000,
        "type": "probe"
      },
      "seq": 1
    },
    {
      "dir": "r2i",
      "epoch": 0,
      "inner": {
        "from": "beta",
        "mid": "0123456789abcdef0123456789abcdef",
        "to": "alpha",
        "ttl": 16,
        "type": "ack"
      },
      "seq": 0
    }
  ]
}`

type keylogVector struct {
	Keylog   []string         `json:"keylog"`
	Capture  []map[string]any `json:"capture"`
	Expected []map[string]any `json:"expected"`
}

func loadVector(t *testing.T) keylogVector {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader([]byte(mirroredVector)))
	dec.UseNumber()
	var v keylogVector
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("parse the mirrored key-log vector: %v", err)
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
