package canon

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/axonibyte/bonemesh/conformance/corpus"
)

type canonVectors struct {
	Vectors []struct {
		Name      string          `json:"name"`
		Cert      json.RawMessage `json:"cert"`
		Canonical string          `json:"canonical"`
	} `json:"vectors"`
}

func decodeCert(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("cert did not decode: %v", err)
	}
	return m
}

func TestCanonCorpus(t *testing.T) {
	var cv canonVectors
	if err := corpus.LoadInto("canon.json", &cv); err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	if len(cv.Vectors) == 0 {
		t.Fatal("corpus has no canon vectors")
	}
	for _, v := range cv.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			got, err := Canonicalize(decodeCert(t, v.Cert))
			if err != nil {
				t.Fatalf("Canonicalize: %v", err)
			}
			if string(got) != v.Canonical {
				t.Errorf("canonical mismatch\n got: %s\nwant: %s", got, v.Canonical)
			}
		})
	}
}

// Control-character escaping (security.md §11.1 step 4) cannot be expressed in
// JSON corpus source, so it is verified here. Both the input label and the
// expected escape bytes are built from explicit bytes so no source-level escape
// sequence is relied on: input label is 'a', U+0001, TAB, 'b'; U+0001 must
// escape to the six bytes  and TAB to the two bytes \t.
func TestCanonControlChars(t *testing.T) {
	label := string([]byte{'a', 0x01, 0x09, 'b'})
	cert := map[string]any{
		"v": json.Number("3"), "mesh": "m", "label": label,
		"idk": "AA==", "nbf": json.Number("0"), "exp": json.Number("1"),
	}
	esc := []byte{'a'}
	esc = append(esc, []byte{'\\', 'u', '0', '0', '0', '1'}...) // 
	esc = append(esc, []byte{'\\', 't'}...)                     // \t
	esc = append(esc, 'b')
	want := `{"exp":1,"idk":"AA==","label":"` + string(esc) + `","mesh":"m","nbf":0,"v":3}`

	got, err := Canonicalize(cert)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if string(got) != want {
		t.Errorf("canonical mismatch\n got: %s\nwant: %s", got, want)
	}
}

// A float, bool, null, or array must be refused rather than silently signed.
func TestCanonRejectsNonCertValues(t *testing.T) {
	for name, bad := range map[string]any{
		"float": json.Number("1.5"),
		"bool":  true,
		"null":  nil,
		"array": []any{1, 2},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Canonicalize(map[string]any{"v": json.Number("3"), "x": bad})
			if err == nil {
				t.Fatalf("expected rejection of %s value", name)
			}
		})
	}
}
