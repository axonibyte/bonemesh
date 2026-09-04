// Command bmconf is the BoneMesh conformance tool. Today it validates the
// static corpus in-process; once a v3 node exists (M4) it will also drive a
// running node over TCP and check its behavior against the same corpus.
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
		fmt.Fprintln(os.Stderr, "drive: not implemented yet — needs a v3 node to speak to (M4).")
		os.Exit(1)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: bmconf <corpus|drive>")
	fmt.Fprintln(os.Stderr, "  corpus  explain how the static corpus is validated")
	fmt.Fprintln(os.Stderr, "  drive   (pending M4) drive a running node over TCP")
}
