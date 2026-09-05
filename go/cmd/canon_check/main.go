// Command canon_check reads the shared corpus (spec/corpus/canon.json) and
// confirms this Go canonicalizer reproduces each vector's expected bytes. The
// Java, Rust, and Elixir implementations validate the same file, so agreement
// means a certificate signed by any of them verifies under this one. Invoked by
// interop/check-canon-go.sh; exits non-zero on any mismatch.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/axonibyte/bonemesh/gonode/canon"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: canon_check <path-to-canon.json>")
		os.Exit(2)
	}
	doc := decode(os.Args[1])
	vectors, _ := doc["vectors"].([]any)
	failures := 0
	for _, raw := range vectors {
		v := raw.(map[string]any)
		name, _ := v["name"].(string)
		cert, _ := v["cert"].(map[string]any)
		want, _ := v["canonical"].(string)
		got, err := canon.Canonicalize(cert)
		if err != nil {
			fmt.Printf("FAIL %s\n  error: %v\n", name, err)
			failures++
			continue
		}
		if got == want {
			fmt.Printf("PASS %s\n", name)
		} else {
			fmt.Printf("FAIL %s\n  got:  %s\n  want: %s\n", name, got, want)
			failures++
		}
	}
	if failures > 0 {
		fmt.Fprintf(os.Stderr, "%d vector(s) mismatched\n", failures)
		os.Exit(1)
	}
	fmt.Printf("all %d canon vectors match\n", len(vectors))
}

func decode(path string) map[string]any {
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return m
}
