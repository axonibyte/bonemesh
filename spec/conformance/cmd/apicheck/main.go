// Command apicheck compares one implementation's public API surface against the
// surface every implementation is supposed to expose, and fails on a difference
// in either direction.
//
// This is the axis decision #23 was written for and the one that had no gate.
// "Reference implementations shall do nothing more than what the protocol
// expressly denotes" was enforced for BONEMESH_* tunables, message types and
// corpus schemas; nothing asked whether a port exposes a method the protocol
// never denoted. A public broadcast() lived in exactly one implementation through
// the entire 8x7 corpus grid run twice, specsrc, the 49-cell matrix and tiers
// 5-10, and was found by a human diffing two ports method-for-method.
//
// Both directions matter and they catch different things. A MISSING capability is
// a port that quietly does less than its siblings — the shape of the bug that
// made this necessary. An EXTRA one is surface the spec never denoted, which is
// what the rule forbids.
//
// What it does NOT prove: that a capability behaves the same way, or that its
// signature matches. Those are the interop matrix's and the tiers' job; this asks
// only "is the same set of things callable?". Keeping it to that is deliberate —
// a name table is maintainable, while a cross-language signature model is not, and
// would be turned off the first time it was wrong.
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

type surface struct {
	Capabilities map[string]map[string]string `json:"capabilities"`
	AllowedExtra map[string]map[string]string `json:"allowed_extra"`
}

func main() {
	specPath := flag.String("surface", "", "path to spec/corpus/api.json")
	impl := flag.String("impl", "", "implementation the names on stdin came from")
	flag.Parse()
	if *specPath == "" || *impl == "" {
		fmt.Fprintln(os.Stderr, "usage: apicheck --surface <api.json> --impl <name> < names")
		os.Exit(2)
	}

	raw, err := os.ReadFile(*specPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read surface: %v\n", err)
		os.Exit(2)
	}
	var s surface
	if err := json.Unmarshal(raw, &s); err != nil {
		fmt.Fprintf(os.Stderr, "cannot parse surface: %v\n", err)
		os.Exit(2)
	}
	if len(s.Capabilities) == 0 {
		fmt.Fprintln(os.Stderr, "surface declares no capabilities")
		os.Exit(2)
	}

	// expected name -> capability it satisfies, for this implementation.
	expect := map[string]string{}
	for cap, byLang := range s.Capabilities {
		name, ok := byLang[*impl]
		if !ok {
			fmt.Fprintf(os.Stderr, "surface has no %s name for capability %q\n", *impl, cap)
			os.Exit(2)
		}
		expect[name] = cap
	}
	allowed := s.AllowedExtra[*impl]

	found := map[string]bool{}
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		if n := strings.TrimSpace(in.Text()); n != "" {
			found[n] = true
		}
	}
	if err := in.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "reading names: %v\n", err)
		os.Exit(2)
	}
	// An empty extraction must not read as "nothing extra, therefore fine": that
	// is a gate passing for code it never looked at (D16, D19).
	if len(found) == 0 {
		fmt.Fprintf(os.Stderr, "FAIL %s: the extractor produced no names, so nothing was compared\n", *impl)
		os.Exit(1)
	}

	var missing, extra []string
	for name, cap := range expect {
		if !found[name] {
			missing = append(missing, fmt.Sprintf("%s (%s)", name, cap))
		}
	}
	for name := range found {
		if _, ok := expect[name]; ok {
			continue
		}
		if _, ok := allowed[name]; ok {
			continue
		}
		extra = append(extra, name)
	}
	sort.Strings(missing)
	sort.Strings(extra)

	if len(missing) > 0 || len(extra) > 0 {
		fmt.Fprintf(os.Stderr, "FAIL %s: public surface does not match the shared one\n", *impl)
		for _, m := range missing {
			fmt.Fprintf(os.Stderr, "  missing: %s — every other implementation exposes it\n", m)
		}
		for _, e := range extra {
			fmt.Fprintf(os.Stderr, "  extra:   %s — the protocol does not denote it (decision #23)\n", e)
		}
		os.Exit(1)
	}
	n := len(expect)
	if len(allowed) > 0 {
		names := make([]string, 0, len(allowed))
		for k := range allowed {
			names = append(names, k)
		}
		sort.Strings(names)
		fmt.Printf("PASS %-7s %d capabilities, plus the declared carve-out (%s)\n",
			*impl, n, strings.Join(names, " "))
		return
	}
	fmt.Printf("PASS %-7s %d capabilities, no surface the protocol does not denote\n", *impl, n)
}
