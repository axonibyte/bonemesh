// Command bmconf is the BoneMesh conformance tool. It validates the static
// corpus in-process and points at the live cross-node conformance suite. Both
// subcommands are pointers to where the assertions actually run, rather than
// duplicating them here.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "corpus":
		// The corpus is validated by `go test ./...`, which drives the canon,
		// framing, and schema packages against it. This subcommand points there
		// rather than duplicating the assertions.
		fmt.Println("The corpus is exercised by `go test ./...` in this module.")
		fmt.Println("See canon/, framing/, and schema/ for the corpus-driven suites.")
	case "drive":
		// Live conformance — completing real handshakes and transport with a
		// running node in every language and checking the observed behavior — is
		// the job of the interop harness, which drives each implementation as a
		// black box through the neutral driver contract.
		fmt.Println("Live cross-node conformance runs in the interop harness, not here.")
		fmt.Println("See interop/README.md and interop/run-matrix.sh (the matrix), plus")
		fmt.Println("interop/tier5..tier10 for fault, degraded-network, fuzz, convergence,")
		fmt.Println("churn, and feature-behavior conformance. Run it via the interop reaper")
		fmt.Println("tenant (the root .reaper.toml).")
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: bmconf <corpus|drive>")
	fmt.Fprintln(os.Stderr, "  corpus  explain how the static corpus is validated")
	fmt.Fprintln(os.Stderr, "  drive   point to the live cross-node conformance suite (interop/)")
}
