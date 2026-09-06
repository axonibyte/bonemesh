// Message-schema validation tests. Reason tags mirror the shared corpus
// (spec/corpus/messages.json, protocol.md §4). Inputs are parsed with UseNumber
// so integers arrive as json.Number, exactly as on the wire.
package message

import (
	"bytes"
	"encoding/json"
	"testing"
)

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

func TestValidate(t *testing.T) {
	cases := []struct {
		schema string
		msg    string
		reason string
	}{
		// bmx1
		{"bmx1", `{"t":"bmx1","v":3,"mesh":"m","e":"AA==","k":"AA==","n":"AA=="}`, ""},
		{"bmx1", `{"t":"nope","v":3,"mesh":"m","e":"AA==","k":"AA==","n":"AA=="}`, "type"},
		{"bmx1", `{"t":"bmx1","v":2,"mesh":"m","e":"AA==","k":"AA==","n":"AA=="}`, "version"},
		{"bmx1", `{"t":"bmx1","v":3,"mesh":"","e":"AA==","k":"AA==","n":"AA=="}`, "empty-mesh"},
		{"bmx1", `{"t":"bmx1","v":3,"mesh":"m","k":"AA==","n":"AA=="}`, "missing-field"},
		{"bmx1", `{"t":"bmx1","v":3,"mesh":"m","e":"!!!","k":"AA==","n":"AA=="}`, "not-base64"},
		// envelope
		{"envelope", `{"seq":0,"ct":"AA=="}`, ""},
		{"envelope", `{"ct":"AA=="}`, "missing-field"},
		{"envelope", `{"seq":-1,"ct":"AA=="}`, "seq-range"},
		{"envelope", `{"seq":0,"ct":"!!!"}`, "not-base64"},
		// data
		{"data", `{"type":"data","mid":"0123456789abcdef0123456789abcdef","to":"b","from":"a","ttl":16,"payload":{}}`, ""},
		{"data", `{"type":"x","mid":"0123456789abcdef0123456789abcdef","to":"b","from":"a","ttl":16,"payload":{}}`, "type"},
		{"data", `{"type":"data","mid":"short","to":"b","from":"a","ttl":16,"payload":{}}`, "mid-format"},
		{"data", `{"type":"data","mid":"0123456789abcdef0123456789abcdef","from":"a","ttl":16,"payload":{}}`, "missing-field"},
		{"data", `{"type":"data","mid":"0123456789abcdef0123456789abcdef","to":"b","from":"a","ttl":0,"payload":{}}`, "ttl-range"},
		{"data", `{"type":"data","mid":"0123456789abcdef0123456789abcdef","to":"b","from":"a","ttl":256,"payload":{}}`, "ttl-range"},
		// ack
		{"ack", `{"type":"ack","mid":"0123456789abcdef0123456789abcdef"}`, ""},
		{"ack", `{"type":"nack","mid":"0123456789abcdef0123456789abcdef"}`, "type"},
		{"ack", `{"type":"ack","mid":"NOTHEX0000000000000000000000000x"}`, "mid-format"},
		// nak (routed like data; reason value is not enum-checked)
		{"nak", `{"type":"nak","mid":"0123456789abcdef0123456789abcdef","hop":"b","reason":"ttl","to":"a","from":"b","ttl":16}`, ""},
		{"nak", `{"type":"nak","mid":"0123456789abcdef0123456789abcdef","hop":"b","reason":"anything-new","to":"a","from":"b","ttl":16}`, ""},
		{"nak", `{"type":"data","mid":"0123456789abcdef0123456789abcdef","hop":"b","reason":"ttl","to":"a","from":"b","ttl":16}`, "type"},
		{"nak", `{"type":"nak","mid":"short","hop":"b","reason":"ttl","to":"a","from":"b","ttl":16}`, "mid-format"},
		{"nak", `{"type":"nak","mid":"0123456789abcdef0123456789abcdef","reason":"ttl","to":"a","from":"b","ttl":16}`, "missing-field"},
		{"nak", `{"type":"nak","mid":"0123456789abcdef0123456789abcdef","hop":"b","to":"a","from":"b","ttl":16}`, "missing-field"},
		{"nak", `{"type":"nak","mid":"0123456789abcdef0123456789abcdef","hop":"b","reason":"ttl","to":"a","from":"b","ttl":0}`, "ttl-range"},
		// bye (link-local; reason optional and free)
		{"bye", `{"type":"bye","reason":"idle"}`, ""},
		{"bye", `{"type":"bye"}`, ""},
		{"bye", `{"type":"bye","reason":"anything-new"}`, ""},
		{"bye", `{"type":"data"}`, "type"},
		// unknown
		{"mystery", `{}`, "unknown-schema"},
	}
	for _, c := range cases {
		got := Validate(c.schema, parse(t, c.msg))
		if got != c.reason {
			t.Fatalf("%s %s: got %q want %q", c.schema, c.msg, got, c.reason)
		}
	}
}

func TestBuildersProduceValidMessages(t *testing.T) {
	// Round-trip builders through JSON so ttl/int types match the wire form the
	// validator sees, rather than trusting the in-memory Go values.
	data := roundtrip(t, Data(NewMID(), "a", "b", DefaultTTL, map[string]any{"k": "v"}))
	if r := Validate("data", data); r != "" {
		t.Fatalf("Data() invalid: %q", r)
	}
	ack := roundtrip(t, Ack(NewMID()))
	if r := Validate("ack", ack); r != "" {
		t.Fatalf("Ack() invalid: %q", r)
	}
	nak := roundtrip(t, Nak(NewMID(), "a", "b", "beta", "ttl", DefaultTTL))
	if r := Validate("nak", nak); r != "" {
		t.Fatalf("Nak() invalid: %q", r)
	}
	if r := Validate("bye", roundtrip(t, Bye("idle"))); r != "" {
		t.Fatalf("Bye(reason) invalid: %q", r)
	}
	if r := Validate("bye", roundtrip(t, Bye(""))); r != "" {
		t.Fatalf("Bye() invalid: %q", r)
	}
}

func roundtrip(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestNewMIDFormatAndUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := NewMID()
		if midReason(id) != "" {
			t.Fatalf("NewMID produced malformed id %q", id)
		}
		if seen[id] {
			t.Fatalf("NewMID collision on %q", id)
		}
		seen[id] = true
	}
}
