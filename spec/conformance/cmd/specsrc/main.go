// Command specsrc is methodology tier 3: source-as-data. It reads the normative
// specification as DATA and checks every implementation against it.
//
// docs/PLAN.md §5 and docs/architecture.md §5 both list tier 3 as a
// per-language obligation, but no implementation ever had one. This is it,
// written once and pointed at all of them, because the question it answers --
// "did a spec edit land in the code, and does the code contain constants the spec
// never mentions?" -- is the same question in every language.
//
// # Why it parses the markdown
//
// The expected values come from spec/protocol.md and spec/security.md directly,
// not from a generated JSON or a shared Go constant. Generating an intermediate
// artifact and checking implementations against THAT would be the
// "test against a re-export of the thing you are checking" trap the methodology
// names: the artifact and the code could drift from the prose together and agree
// perfectly. The spec tree is excluded from the searched corpus for the same
// reason -- otherwise the spec would satisfy its own checks.
//
// The per-language source roots below are deliberately duplicated here rather
// than discovered, so that the duplication is itself the check.
//
// # What it proves, and what it does not
//
// It proves that the constants, tunable names and message-type tokens the spec
// pins are PRESENT in each implementation, and that each implementation reads no
// BONEMESH_* tunable the spec does not document. It does NOT prove they are used
// correctly -- a cap that is parsed but never enforced still passes here. Correct
// use is what the corpus checks (interop/run-corpus-checks.sh) and the live tiers
// (interop/tier5..10.sh) are for. This tier catches the drift those cannot see:
// a constant renamed, removed, or changed in the spec and not in the code.
//
// Every extraction asserts that it actually extracted something. A parser that
// silently matches nothing would turn this whole tool into a vacuous pass, which
// is the most likely way for it to rot as the spec is reworded.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// implementation source roots (the deliberate duplication)
// ---------------------------------------------------------------------------

type impl struct {
	name  string
	roots []string // directories or files, relative to the repo root
	skip  []string // path fragments to exclude (tests, vendor, build output)
}

var impls = []impl{
	{"java", []string{"java/src/main/java/com/axonibyte/bonemesh/v3"}, nil},
	{"go", []string{"go/canon", "go/cert", "go/crypto", "go/frame", "go/handshake",
		"go/keyschedule", "go/message", "go/node", "go/routing", "go/transport"},
		[]string{"_test.go"}},
	{"rust", []string{"rust/src"}, nil},
	{"js", []string{"js/src"}, nil},
	{"php", []string{"php/src"}, nil},
	{"elixir", []string{"elixir/lib"}, nil},
	{"python", []string{"python/bonemesh"}, nil},
}

// Source extensions worth reading, so a stray binary or lockfile under a root
// cannot accidentally satisfy a check.
var sourceExt = map[string]bool{
	".java": true, ".go": true, ".rs": true, ".js": true,
	".php": true, ".ex": true, ".exs": true, ".py": true,
}

// ---------------------------------------------------------------------------

func main() {
	// -root lets the self-test (interop/check-spec.sh --self-test) point this at a
	// synthetic tree with a deliberately drifted constant, which is how the tool
	// is proven able to fail. Without it the tool could only ever be observed
	// passing, and an unfired check is an unmeasured one.
	rootFlag := flag.String("root", "", "repository root to check (default: search upward from the working directory)")
	flag.Parse()

	root := *rootFlag
	if root == "" {
		var err error
		if root, err = repoRoot(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	protocol := mustRead(filepath.Join(root, "spec", "protocol.md"))
	security := mustRead(filepath.Join(root, "spec", "security.md"))

	s := extractSpec(protocol, security)
	fmt.Printf("spec pins: %d literal constants, %d tunables, %d message types\n",
		len(s.literals), len(s.tunables), len(s.messageTypes))

	failures := 0
	fail := func(format string, a ...any) {
		fmt.Printf("FAIL  "+format+"\n", a...)
		failures++
	}

	// --- D. spec vs corpus, before any implementation is consulted -----------
	// Two independent artifacts that must agree, neither derived from the other.
	corpusTypes, err := corpusSchemas(filepath.Join(root, "spec", "corpus", "messages.json"))
	if err != nil {
		fail("corpus: %v", err)
	} else {
		for _, t := range corpusTypes {
			// "envelope" is the transport carrier, named in protocol.md §4 rather
			// than in the Appendix A type table.
			if t == "envelope" {
				continue
			}
			if !contains(s.messageTypes, t) {
				fail("corpus messages.json uses schema %q, which the spec's type table does not list", t)
			}
		}
		fmt.Printf("PASS  corpus schemas are all spec'd types (%d)\n", len(corpusTypes))
	}

	// --- per implementation --------------------------------------------------
	present := 0
	for _, im := range impls {
		src, n, err := loadSource(root, im)
		if err != nil || n == 0 {
			fmt.Printf("SKIP  %-7s — no source found (not present in this tree)\n", im.name)
			continue
		}
		present++
		norm := normalize(src)
		bad := 0

		// A. literal constants the spec pins.
		for _, lit := range s.literals {
			hay := src
			needle := lit.value
			if lit.normalized {
				hay, needle = norm, normalize(lit.value)
			}
			if !strings.Contains(hay, needle) {
				fail("%-7s missing %s (spec pins %q)", im.name, lit.what, lit.value)
				bad++
			}
		}

		// B. tunables, both directions.
		implTunables := tunableNames(src)
		for _, t := range s.tunables {
			if !contains(implTunables, t) {
				fail("%-7s does not read %s, which protocol.md §0 documents", im.name, t)
				bad++
			}
		}
		for _, t := range implTunables {
			if !contains(s.tunables, t) {
				fail("%-7s reads %s, which no spec document mentions", im.name, t)
				bad++
			}
		}

		// C. message types from the spec's type table.
		for _, t := range s.messageTypes {
			if !strings.Contains(src, `"`+t+`"`) && !strings.Contains(src, `'`+t+`'`) &&
				!strings.Contains(src, `:`+t) && !strings.Contains(src, `"`+t+`"`) {
				fail("%-7s never names message type %q", im.name, t)
				bad++
			}
		}

		if bad == 0 {
			fmt.Printf("PASS  %-7s agrees with the spec (%d files, %d tunables)\n",
				im.name, n, len(implTunables))
		}
	}

	if present == 0 {
		fmt.Fprintln(os.Stderr, "FAIL: no implementation source found at all — wrong working directory?")
		os.Exit(1)
	}

	fmt.Println()
	if failures > 0 {
		fmt.Fprintf(os.Stderr, "%d spec/source disagreement(s)\n", failures)
		os.Exit(1)
	}
	fmt.Printf("every implementation present (%d) agrees with the pinned spec\n", present)
}

// ---------------------------------------------------------------------------
// spec extraction
// ---------------------------------------------------------------------------

type literal struct {
	what       string
	value      string
	normalized bool // compare with separators stripped and lowercased
}

type specPins struct {
	literals     []literal
	tunables     []string
	messageTypes []string
}

// mustFind runs re against text and returns capture group 1, exiting non-zero if
// there is no match. Every extraction goes through this: a spec reword that
// breaks a pattern must fail loudly, never silently stop checking.
func mustFind(what, text string, re *regexp.Regexp) string {
	m := re.FindStringSubmatch(text)
	if m == nil {
		fmt.Fprintf(os.Stderr,
			"FAIL: cannot extract %s from the spec — the wording changed and this\n"+
				"      parser stopped checking it. Fix the pattern in specsrc, do not\n"+
				"      leave it silently matching nothing.\n", what)
		os.Exit(1)
	}
	return m[1]
}

func extractSpec(protocol, security string) specPins {
	var s specPins

	add := func(what, value string) {
		s.literals = append(s.literals, literal{what: what, value: value})
	}
	addNorm := func(what, value string) {
		s.literals = append(s.literals, literal{what: what, value: value, normalized: true})
	}

	// protocol.md §0 table.
	add("handshake frame cap",
		mustFind("handshake frame cap", protocol,
			regexp.MustCompile(`(?m)^\| Handshake frame max \| (\d+) bytes`)))
	add("transport frame cap",
		mustFind("transport frame cap", protocol,
			regexp.MustCompile(`(?m)^\| Transport frame max \(default\) \| (\d+) bytes`)))

	ttl := mustFind("ttl default/range", protocol,
		regexp.MustCompile(`(?m)^\| `+"`ttl`"+` default \| (\d+; range \d+–\d+)`))
	ttlParts := regexp.MustCompile(`(\d+); range (\d+)–(\d+)`).FindStringSubmatch(ttl)
	add("ttl default", ttlParts[1])
	add("ttl maximum", ttlParts[3])

	// protocol.md §0 operational-tunables prose.
	addNorm("latency EWMA alpha",
		mustFind("EWMA alpha", protocol,
			regexp.MustCompile(`latency EWMA \*\*α = ([0-9.]+)\*\*`)))
	add("dedup window",
		mustFind("dedup window", protocol,
			regexp.MustCompile(`dedup window \*\*(\d+)\*\*`)))

	// security.md §5 protocol name, and §8 key-log line prefixes.
	add("BMX protocol name",
		mustFind("protocol name", security,
			regexp.MustCompile(`SHA-256\("([A-Za-z0-9_]+)"\)`)))
	// Key-log line format, checked as COMPONENTS rather than as the concatenated
	// prefix. PHP and Elixir build the line from a template
	// (sprintf("BMX3_%s_TRAFFIC_%d", ...) / "BMX3_#{dir}_TRAFFIC_#{epoch}") and
	// pass the direction separately, so demanding the joined literal failed them
	// for writing correct code in a different shape -- and "passed" PHP's I2R half
	// only because the joined form appears in a comment there. A check that
	// dictates code shape is a check that will be worked around.
	klog := mustFind("key-log line format", security,
		regexp.MustCompile(`(BMX3_I2R_TRAFFIC_<epoch>[^\n]*)`))
	for _, part := range []struct{ what, value string }{
		{"key-log record prefix", "BMX3_"},
		{"key-log record infix", "_TRAFFIC_"},
		{"key-log initiator→responder direction", "I2R"},
		{"key-log responder→initiator direction", "R2I"},
	} {
		// Each component must genuinely come from the spec line, so a reworded
		// format cannot leave this loop asserting invented strings.
		if part.value != "R2I" && !strings.Contains(klog, part.value) {
			fmt.Fprintf(os.Stderr,
				"FAIL: key-log component %q is not in the spec's format line (%q)\n",
				part.value, klog)
			os.Exit(1)
		}
		add(part.what, part.value)
	}

	// security.md §11 primitive table. Normalized, because every language spells
	// these differently (MLDSA65PrivateKey / ml_dsa_65 / :mldsa65 / MLDSA65).
	prim := regexp.MustCompile(`(?m)^\| (?:Node identity signature|Root signature|Ephemeral KEM|Ephemeral DH|AEAD) \| \*{0,2}([A-Za-z0-9-]+)`)
	pm := prim.FindAllStringSubmatch(security, -1)
	if len(pm) < 5 {
		fmt.Fprintf(os.Stderr, "FAIL: extracted only %d of the 5 pinned primitives from security.md §11\n", len(pm))
		os.Exit(1)
	}
	for _, m := range pm {
		addNorm("primitive "+m[1], m[1])
	}

	// Tunables: every BONEMESH_* the spec documents.
	tun := regexp.MustCompile("BONEMESH_[A-Z0-9_]+")
	seen := map[string]bool{}
	for _, name := range append(tun.FindAllString(protocol, -1), tun.FindAllString(security, -1)...) {
		// protocol.md abbreviates the retry/rekey families as
		// BONEMESH_RETRY_BASE_MS/_CAP_MS/_MAX_MS; expand the suffix-only forms.
		if !seen[name] {
			seen[name] = true
			s.tunables = append(s.tunables, name)
		}
	}
	for _, fam := range []struct {
		prefix   string
		suffixes []string
	}{
		{"BONEMESH_RETRY", []string{"_BASE_MS", "_CAP_MS", "_MAX_MS"}},
		{"BONEMESH_REKEY", []string{"_MS", "_FRAMES", "_TIMEOUT_MS"}},
	} {
		for _, suf := range fam.suffixes {
			n := fam.prefix + suf
			if !seen[n] {
				seen[n] = true
				s.tunables = append(s.tunables, n)
			}
		}
	}
	sort.Strings(s.tunables)
	if len(s.tunables) < 9 {
		fmt.Fprintf(os.Stderr, "FAIL: extracted only %d tunables from the spec, expected at least 9\n", len(s.tunables))
		os.Exit(1)
	}

	// Appendix A message-type table. Cells can hold more than one token
	// ("`probe` / `echo`"), so every backticked token in the column counts.
	appendix := protocol[strings.Index(protocol, "## Appendix A"):]
	if i := strings.Index(appendix, "## Appendix B"); i > 0 {
		appendix = appendix[:i]
	}
	row := regexp.MustCompile("(?m)^\\| (?:handshake|transport) \\| ([^|]+) \\|")
	tok := regexp.MustCompile("`([a-z0-9]+)`")
	for _, m := range row.FindAllStringSubmatch(appendix, -1) {
		for _, t := range tok.FindAllStringSubmatch(m[1], -1) {
			if !contains(s.messageTypes, t[1]) {
				s.messageTypes = append(s.messageTypes, t[1])
			}
		}
	}
	sort.Strings(s.messageTypes)
	if len(s.messageTypes) < 10 {
		fmt.Fprintf(os.Stderr,
			"FAIL: extracted only %d message types from Appendix A (%v), expected at least 10\n",
			len(s.messageTypes), s.messageTypes)
		os.Exit(1)
	}
	return s
}

// corpusSchemas returns the distinct "schema" values in messages.json, read as
// text so this tool needs no JSON dependency and no shared struct with the
// conformance packages.
func corpusSchemas(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(`"schema"\s*:\s*"([a-z0-9]+)"`)
	var out []string
	for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
		if !contains(out, m[1]) {
			out = append(out, m[1])
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no schema names found in %s", path)
	}
	sort.Strings(out)
	return out, nil
}

// ---------------------------------------------------------------------------
// source loading
// ---------------------------------------------------------------------------

func loadSource(root string, im impl) (string, int, error) {
	var b strings.Builder
	files := 0
	for _, r := range im.roots {
		p := filepath.Join(root, r)
		err := filepath.Walk(p, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // a missing root just contributes nothing
			}
			if info.IsDir() {
				return nil
			}
			if !sourceExt[filepath.Ext(path)] {
				return nil
			}
			for _, s := range im.skip {
				if strings.Contains(path, s) {
					return nil
				}
			}
			// Never let a vendored or generated tree satisfy a check.
			if strings.Contains(path, "/vendor/") || strings.Contains(path, "/node_modules/") ||
				strings.Contains(path, "/target/") || strings.Contains(path, "/build/") ||
				strings.Contains(path, "/_build/") || strings.Contains(path, "__pycache__") {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			b.Write(raw)
			b.WriteByte('\n')
			files++
			return nil
		})
		if err != nil {
			return "", 0, err
		}
	}
	return b.String(), files, nil
}

func tunableNames(src string) []string {
	re := regexp.MustCompile("BONEMESH_[A-Z0-9_]+")
	var out []string
	for _, n := range re.FindAllString(src, -1) {
		if !contains(out, n) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// normalize lowercases and drops every non-alphanumeric character, so one spec
// spelling ("ML-DSA-65") matches every language's ("MLDSA65PrivateKey",
// "ml_dsa_65", ":mldsa65").
func normalize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func mustRead(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return string(raw)
}

// repoRoot walks up from the working directory looking for the tree that holds
// both spec/ and interop/, so the tool can be run from anywhere.
func repoRoot() (string, error) {
	d, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if st, err := os.Stat(filepath.Join(d, "spec", "protocol.md")); err == nil && !st.IsDir() {
			if _, err := os.Stat(filepath.Join(d, "interop")); err == nil {
				return d, nil
			}
		}
		parent := filepath.Dir(d)
		if parent == d {
			return "", fmt.Errorf("no repository root (a dir with spec/protocol.md and interop/) above the working directory")
		}
		d = parent
	}
}
