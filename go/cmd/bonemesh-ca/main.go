// Command bonemesh-ca is the BoneMesh mesh certificate authority: it creates a
// mesh root keypair, generates node identity keypairs, issues membership
// certificates, and verifies them (security.md §3). It is the canonical
// provisioning tool, replacing the earlier Java CLI flag-for-flag; keys and
// certificates it emits are implementation-neutral (base64 raw keys, JSON
// certs) and accepted by a node in any language.
//
// Usage mirrors the retired Java tool exactly:
//
//	bonemesh-ca init-root --out <dir>
//	bonemesh-ca keygen    --out <prefix>
//	bonemesh-ca issue     --root-priv <f> --root-pub <f> --mesh <id> --label <l> --key <node.pub> [--days 30] [--out <f>]
//	bonemesh-ca verify    --root-pub <f> --mesh <id> --cert <f>
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/axonibyte/bonemesh/gonode/canon"
	"github.com/axonibyte/bonemesh/gonode/cert"
	"github.com/axonibyte/bonemesh/gonode/crypto"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "init-root":
		initRoot(flags(os.Args[2:]))
	case "keygen":
		keygen(flags(os.Args[2:]))
	case "issue":
		issue(flags(os.Args[2:]))
	case "verify":
		verify(flags(os.Args[2:]))
	default:
		usage()
		os.Exit(2)
	}
}

func initRoot(f map[string]string) {
	dir := require(f, "out")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fail(err)
	}
	pub, priv := crypto.MLDSA87Generate()
	writeKey(filepath.Join(dir, "root.priv"), priv)
	writeKey(filepath.Join(dir, "root.pub"), pub)
	fmt.Printf("root keypair written to %s (guard root.priv; it never goes on a node)\n", dir)
}

func keygen(f map[string]string) {
	prefix := require(f, "out")
	pub, priv := crypto.MLDSA65Generate()
	writeKey(prefix+".priv", priv)
	writeKey(prefix+".pub", pub)
	fmt.Printf("identity keypair written to %s.{priv,pub}\n", prefix)
}

func issue(f map[string]string) {
	rootPub := readKey(require(f, "root-pub"))
	rootPriv := readKey(require(f, "root-priv"))
	nodePub := readKey(require(f, "key"))
	mesh := require(f, "mesh")
	label := require(f, "label")

	days := int64(30)
	if v, ok := f["days"]; ok {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			fail(fmt.Errorf("bad --days %q: %w", v, err))
		}
		days = n
	}
	out := f["out"]
	if out == "" {
		out = label + ".cert.json"
	}

	nbf := time.Now().Unix()
	exp := nbf + days*86400
	c := cert.Build(mesh, label, nodePub, nbf, exp)

	pre, err := canon.Canonicalize(c)
	if err != nil {
		fail(err)
	}
	c["sig"] = base64.StdEncoding.EncodeToString(crypto.MLDSA87Sign(rootPriv, []byte(pre)))
	// Sanity: the freshly-issued cert must verify under its own root — catches a
	// key/canonicalization mismatch at issue time rather than at a peer's node.
	if err := cert.Verify(c, rootPub, mesh, nbf); err != nil {
		fail(fmt.Errorf("issued certificate failed self-verification: %w", err))
	}

	blob, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		fail(err)
	}
	if err := os.WriteFile(out, blob, 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("certificate for %s written to %s\n", label, out)
}

func verify(f map[string]string) {
	rootPub := readKey(require(f, "root-pub"))
	c := readCert(require(f, "cert"))
	mesh := require(f, "mesh")

	if v, ok := c["v"]; !ok || fmt.Sprint(v) != "3" {
		fail(fmt.Errorf("unsupported certificate version %v", c["v"]))
	}
	if err := cert.Verify(c, rootPub, mesh, time.Now().Unix()); err != nil {
		fmt.Printf("INVALID: %s\n", err.Error())
		os.Exit(1)
	}
	label, _ := c["label"].(string)
	fmt.Printf("OK: certificate for %s verifies\n", label)
}

// --- helpers (base64 std, no trailing newline; matches every other tool) ---

func writeKey(path string, key []byte) {
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key)), 0o644); err != nil {
		fail(err)
	}
}

func readKey(path string) []byte {
	raw, err := os.ReadFile(path)
	if err != nil {
		fail(err)
	}
	key, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil {
		fail(fmt.Errorf("%s: not valid base64: %w", path, err))
	}
	return key
}

// readCert parses a certificate JSON with UseNumber so its integers stay
// json.Number — canon.Canonicalize rejects float64.
func readCert(path string) map[string]any {
	raw, err := os.ReadFile(path)
	if err != nil {
		fail(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var c map[string]any
	if err := dec.Decode(&c); err != nil {
		fail(fmt.Errorf("%s: not valid certificate JSON: %w", path, err))
	}
	return c
}

// flags walks argv as strict `--key value` pairs (matching the retired Java
// tool and the interop_node driver): pairs start at index 0 of the slice, a
// lone trailing --flag is ignored, unknown flags are accepted, last wins.
func flags(args []string) map[string]string {
	f := map[string]string{}
	for i := 0; i+1 < len(args); i += 2 {
		if len(args[i]) > 2 && args[i][:2] == "--" {
			f[args[i][2:]] = args[i+1]
		}
	}
	return f
}

func require(f map[string]string, key string) string {
	v, ok := f[key]
	if !ok || v == "" {
		fmt.Fprintf(os.Stderr, "missing required --%s\n", key)
		os.Exit(1)
	}
	return v
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err.Error())
	os.Exit(1)
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: bonemesh-ca <command> [--flag value ...]
  init-root --out <dir>
  keygen    --out <prefix>
  issue     --root-priv <f> --root-pub <f> --mesh <id> --label <l> --key <node.pub> [--days 30] [--out <f>]
  verify    --root-pub <f> --mesh <id> --cert <f>
`)
}
