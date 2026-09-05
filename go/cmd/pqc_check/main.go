// Command pqc_check verifies the Go port's post-quantum interop against the
// shared vector (spec/corpus/transcripts/pqc-interop.json), produced by the
// Java reference (BouncyCastle).
//
// It verifies the ML-DSA-65 signature over the vector's message using the
// vector's public key, exercising the node's real crypto.MLDSA65Verify (CIRCL).
// Success proves Go and Java agree on ML-DSA-65 at the byte level.
//
// It deliberately does NOT decapsulate the vector's ML-KEM ciphertext: the
// vector ships a 2400-byte FIPS *expanded* decapsulation key, while this port
// uses Go's stdlib crypto/mlkem, which is keyed by the 64-byte seed. That is a
// private-key *representation* difference, not an interop gap — a decapsulation
// key never crosses a node (only the encapsulation key, ciphertext, and public
// artifacts do, all standard FIPS encodings). Live ML-KEM-768 interop between
// Go and Java/Elixir/Rust is proven directly by the interop matrix, where every
// pairing completes a real hybrid handshake. This tool names that boundary
// rather than loading a key format the node never receives.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/axonibyte/bonemesh/gonode/crypto"
)

type vector struct {
	MLDSA65 struct {
		PublicHex    string `json:"public_hex"`
		MessageHex   string `json:"message_hex"`
		SignatureHex string `json:"signature_hex"`
	} `json:"mldsa65"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: pqc_check <pqc-interop.json>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	pub := unhex(v.MLDSA65.PublicHex)
	msg := unhex(v.MLDSA65.MessageHex)
	sig := unhex(v.MLDSA65.SignatureHex)

	if !crypto.MLDSA65Verify(pub, msg, sig) {
		fmt.Fprintln(os.Stderr, "FAIL: Go did not verify the Java ML-DSA-65 signature")
		os.Exit(1)
	}
	fmt.Println("PASS: Go verifies the Java ML-DSA-65 signature over the shared vector")
	fmt.Println("NOTE: ML-KEM-768 interop with Java is proven live by the interop matrix")
	fmt.Println("      (stdlib crypto/mlkem is seed-keyed; the vector's expanded dk is a")
	fmt.Println("      key-representation detail that never crosses a node).")
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad hex:", err)
		os.Exit(1)
	}
	return b
}
