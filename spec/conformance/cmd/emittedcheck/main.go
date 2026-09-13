// Command emittedcheck reads the inner messages an implementation actually put on
// the wire and fails on any field the spec does not name for that type.
//
// This is the direction decision #24 is about and the one the repository did not
// have. message.validate() answers "is what I received well-formed?" — and it is
// called from no node's wire path in any of the seven, only from the corpus-check
// binaries, so the `messages` family has always validated a side-car. Nothing
// asked the other question: "is what I emitted named by the spec?" A port could
// add a field to a frame and every gate in the tree would stay green, which is
// the same blind spot that let a public broadcast() live in one implementation
// (decision #23).
//
// Input is the NDJSON bonemesh-inspect prints — {"dir","seq","epoch","inner"} per
// frame — so the messages checked are the ones that were actually sealed, decoded
// with the keys the node itself logged. A capture records both directions, so a Go
// node paired with another language yields that language's emissions too; one
// capturing implementation covers all seven, as decision #18 anticipated.
//
// What it does NOT prove: that a required field was present (messages.json and the
// seven validators pin presence and type), nor that the VALUE is meaningful. It
// proves only that nothing unnamed was emitted. Keeping it to that one question is
// deliberate: a check derived from the same schema it is checking would agree with
// itself no matter what the code did.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

type allowlist struct {
	Types map[string][]string `json:"types"`
}

func main() {
	spec := flag.String("allowlist", "", "path to spec/corpus/emitted.json")
	label := flag.String("label", "", "what produced this capture, for the report")
	// A capture records both ends, and the capturing node is the initiator, so
	// i2r frames are its own emissions and r2i are the peer's. Filtering by
	// direction is what lets a violation be attributed to the language that
	// actually emitted it rather than to the pair.
	dir := flag.String("dir", "any", `which side to check: "i2r", "r2i", or "any"`)
	flag.Parse()
	if *spec == "" {
		fmt.Fprintln(os.Stderr, "usage: emittedcheck --allowlist <emitted.json> [--label x] [--dir i2r|r2i|any] < inspect.ndjson")
		os.Exit(2)
	}

	raw, err := os.ReadFile(*spec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read allowlist: %v\n", err)
		os.Exit(2)
	}
	var a allowlist
	if err := json.Unmarshal(raw, &a); err != nil {
		fmt.Fprintf(os.Stderr, "cannot parse allowlist: %v\n", err)
		os.Exit(2)
	}
	allowed := map[string]map[string]bool{}
	for t, fields := range a.Types {
		set := map[string]bool{}
		for _, f := range fields {
			set[f] = true
		}
		allowed[t] = set
	}

	seen := map[string]int{}
	var problems []string
	frames := 0

	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 1<<20), 1<<24)
	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		var rec struct {
			Dir   string         `json:"dir"`
			Inner map[string]any `json:"inner"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil || rec.Inner == nil {
			continue // not an inspect record; the inspector reports its own skips
		}
		if *dir != "any" && rec.Dir != *dir {
			continue
		}
		frames++
		kind, _ := rec.Inner["type"].(string)
		if kind == "" {
			problems = append(problems, "a frame was emitted with no type")
			continue
		}
		fields, known := allowed[kind]
		if !known {
			problems = append(problems, fmt.Sprintf("emitted an inner type the spec does not define: %q", kind))
			continue
		}
		seen[kind]++
		for f := range rec.Inner {
			if !fields[f] {
				problems = append(problems, fmt.Sprintf("%s carries %q, which protocol.md does not name for it", kind, f))
			}
		}
	}
	if err := in.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "reading capture: %v\n", err)
		os.Exit(2)
	}

	// An empty capture must not read as a pass: it is the failure mode this whole
	// check exists to avoid one layer up (a gate reporting PASS for code it never
	// exercised -- D16, D19).
	if frames == 0 {
		fmt.Fprintf(os.Stderr, "FAIL %s: no frames were decoded for dir=%s, so nothing was checked\n", *label, *dir)
		os.Exit(1)
	}

	kinds := make([]string, 0, len(seen))
	for k := range seen {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	counts := make([]string, 0, len(kinds))
	for _, k := range kinds {
		counts = append(counts, fmt.Sprintf("%s=%d", k, seen[k]))
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		uniq := problems[:0]
		var last string
		for _, p := range problems {
			if p != last {
				uniq = append(uniq, p)
				last = p
			}
		}
		fmt.Fprintf(os.Stderr, "FAIL %s: %d frames (%s)\n", *label, frames, strings.Join(counts, " "))
		for _, p := range uniq {
			fmt.Fprintf(os.Stderr, "  %s\n", p)
		}
		os.Exit(1)
	}
	fmt.Printf("PASS %-7s %d frames, every field named by the spec (%s)\n",
		*label, frames, strings.Join(counts, " "))
}
