package schema

import (
	"testing"

	"github.com/axonibyte/bonemesh/conformance/corpus"
)

type messagesDoc struct {
	Cases []struct {
		Name   string         `json:"name"`
		Schema string         `json:"schema"`
		Expect string         `json:"expect"`
		Reason string         `json:"reason"`
		Frame  map[string]any `json:"frame"`
	} `json:"cases"`
}

func TestSchemaCorpus(t *testing.T) {
	var doc messagesDoc
	if err := corpus.LoadInto("messages.json", &doc); err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("corpus has no message cases")
	}
	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			reason := Validate(c.Schema, c.Frame)
			valid := reason == ""
			if c.Expect == "valid" && !valid {
				t.Errorf("expected valid, got invalid(%q)", reason)
			}
			if c.Expect == "invalid" {
				if valid {
					t.Errorf("expected invalid(%q), got valid", c.Reason)
				} else if reason != c.Reason {
					t.Errorf("reason mismatch: got %q want %q", reason, c.Reason)
				}
			}
		})
	}
}
