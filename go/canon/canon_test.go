// JCS canonicalization tests. Vectors mirror the shared corpus
// (spec/corpus/canon.json) and security.md §11.1; byte-for-byte agreement with
// the Java, Elixir, Rust, and conformance-runner canonicalizers over that
// corpus is what makes the root signature portable. Control-character escaping
// is covered by an in-code vector, since raw control bytes cannot appear in
// JSON source.
package canon

import (
	"bytes"
	"encoding/json"
	"testing"
)

// parse decodes JSON with UseNumber, so integers survive as json.Number exactly
// as the real certificate-loading path does.
func parse(t *testing.T, s string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return m
}

func TestCorpusVectors(t *testing.T) {
	cases := []struct {
		name  string
		cert  string
		canon string
	}{
		{
			"basic-sorted-keys",
			`{"v": 3, "mesh": "acme-prod", "label": "alpha", "idk": "YWJj", "nbf": 1788500000, "exp": 1790000000}`,
			`{"exp":1790000000,"idk":"YWJj","label":"alpha","mesh":"acme-prod","nbf":1788500000,"v":3}`,
		},
		{
			"sig-field-is-stripped",
			`{"v": 3, "mesh": "m", "label": "alpha", "idk": "AA==", "nbf": 0, "exp": 1, "sig": "SHOULD-BE-IGNORED"}`,
			`{"exp":1,"idk":"AA==","label":"alpha","mesh":"m","nbf":0,"v":3}`,
		},
		{
			"non-ascii-emitted-raw-utf8",
			`{"v": 3, "mesh": "m", "label": "café", "idk": "AA==", "nbf": 0, "exp": 1}`,
			`{"exp":1,"idk":"AA==","label":"café","mesh":"m","nbf":0,"v":3}`,
		},
		{
			"string-escaping-quote-backslash",
			`{"v": 3, "mesh": "m", "label": "a\"b\\c", "idk": "AA==", "nbf": 0, "exp": 1}`,
			`{"exp":1,"idk":"AA==","label":"a\"b\\c","mesh":"m","nbf":0,"v":3}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Canonicalize(parse(t, c.cert))
			if err != nil {
				t.Fatalf("Canonicalize: %v", err)
			}
			if got != c.canon {
				t.Fatalf("canonical mismatch\n got: %s\nwant: %s", got, c.canon)
			}
		})
	}
}

// TestControlCharEscaping covers the C0 escapes that cannot appear raw in JSON
// source: \b \t \n \f \r use their short forms, other control bytes use \u00XX.
func TestControlCharEscaping(t *testing.T) {
	label := "a" +
		string(rune(0x08)) + string(rune(0x09)) + string(rune(0x0a)) +
		string(rune(0x0c)) + string(rune(0x0d)) + string(rune(0x01)) + "b"
	cert := map[string]any{"label": label}
	// The u0001 escape is built from explicit bytes so the source cannot
	// smuggle a raw control byte in place of the escape sequence.
	u0001 := string([]byte{0x5c, 'u', '0', '0', '0', '1'})
	want := `{"label":"a\b\t\n\f\r` + u0001 + `b"}`
	got, err := Canonicalize(cert)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if got != want {
		t.Fatalf("escape mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestNegativeIntegerRejected(t *testing.T) {
	if _, err := Canonicalize(parse(t, `{"nbf": -1}`)); err == nil {
		t.Fatal("expected negative integer to be rejected")
	}
}

func TestNonIntegerNumberRejected(t *testing.T) {
	if _, err := Canonicalize(parse(t, `{"v": 3.5}`)); err == nil {
		t.Fatal("expected non-integer number to be rejected")
	}
}

func TestBooleanValueRejected(t *testing.T) {
	if _, err := Canonicalize(parse(t, `{"ok": true}`)); err == nil {
		t.Fatal("expected boolean value to be rejected")
	}
}

func TestNestedObjectSortedIndependently(t *testing.T) {
	got, err := Canonicalize(parse(t, `{"z": 1, "a": {"y": 2, "b": 3}}`))
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	want := `{"a":{"b":3,"y":2},"z":1}`
	if got != want {
		t.Fatalf("nested mismatch\n got: %s\nwant: %s", got, want)
	}
}
