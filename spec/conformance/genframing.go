//go:build ignore

package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
)

type Case struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	BytesB64 string `json:"bytes_b64"`
	Expect   string `json:"expect"`
	Reason   string `json:"reason,omitempty"`
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func main() {
	cases := []Case{
		{"simple-object", "transport", b64([]byte("{\"a\":1}\n")), "accept", ""},
		{"missing-trailing-newline", "transport", b64([]byte("{\"a\":1}")), "reject", "no-newline"},
		{"empty-line", "transport", b64([]byte("\n")), "reject", "empty"},
		{"not-json", "transport", b64([]byte("not json\n")), "reject", "invalid-json"},
		{"json-array-not-object", "transport", b64([]byte("[1,2,3]\n")), "reject", "not-an-object"},
		{"interior-newline-splits-frame", "transport", b64([]byte("{\"a\":\n1}\n")), "reject", "invalid-json"},
		{"invalid-utf8", "transport", b64([]byte{'{', '"', 'a', '"', ':', '"', 0xff, '"', '}', '\n'}), "reject", "invalid-utf8"},
		{"trailing-garbage-after-object", "transport", b64([]byte("{\"a\":1} X\n")), "reject", "trailing-data"},
		{"lenient-unquoted-key", "transport", b64([]byte("{a:1}\n")), "reject", "invalid-json"},
		{"lenient-single-quoted-string", "transport", b64([]byte("{\"a\":'b'}\n")), "reject", "invalid-json"},
		{"lenient-trailing-comma", "transport", b64([]byte("{\"a\":1,}\n")), "reject", "invalid-json"},
		{"lenient-leading-zero", "transport", b64([]byte("{\"a\":01}\n")), "reject", "invalid-json"},
		{"lenient-nan-literal", "transport", b64([]byte("{\"a\":NaN}\n")), "reject", "invalid-json"},
	}
	doc := map[string]any{
		"description": "Frame acceptance/rejection (protocol.md section 2). Each case gives 'bytes_b64' (RFC 4648 base64 of the raw wire bytes), the frame 'kind' ('handshake' cap 32768, 'transport' cap 65536), and 'expect' ('accept'|'reject') with a 'reason' tag. A frame reader must reach the same verdict. 'accept' = exactly one newline-terminated JSON object within the cap. The object must be strict RFC 8259 JSON: the 'lenient-*' cases (unquoted keys, single-quoted strings, trailing commas, leading-zero numbers, NaN) are inputs a lenient parser accepts but a conforming reader must reject as invalid-json, so all implementations agree on exactly which frames are well formed.",
		"cases":       cases,
		"size_cases": map[string]any{
			"description":   "The runner also generates frames exactly at the cap (accept) and one byte over (reject, reason 'oversize') from these caps.",
			"handshake_cap": 32768,
			"transport_cap": 65536,
		},
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	os.WriteFile("../corpus/framing.json", append(b, '\n'), 0644)
}
