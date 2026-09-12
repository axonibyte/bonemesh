// Command transport_check reads the shared transport-frame vector
// (spec/corpus/transcripts/transport-frame.json) and confirms this Go transport
// both reproduces the sealed ciphertext byte-for-byte and can open it again.
//
// The vector states both halves ("reproduces ct_hex and can open it"), so both
// are asserted: sealing alone would pass even if opening were broken, and
// opening alone would pass a transport that agreed with itself but not with the
// other implementations. Invoked by interop/check-transport-go.sh.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/axonibyte/bonemesh/gonode/transport"
)

type vector struct {
	Inputs struct {
		KeyHex            string `json:"key_hex"`
		Seq               uint64 `json:"seq"`
		InnerPlaintextHex string `json:"inner_plaintext_hex"`
	} `json:"inputs"`
	Outputs struct {
		CtHex string `json:"ct_hex"`
	} `json:"outputs"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: transport_check <path-to-transport-frame.json>")
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

	failures := 0
	check := func(name, want, got string) {
		if want == got {
			fmt.Println("PASS", name)
			return
		}
		fmt.Printf("FAIL %s\n  got:  %s\n  want: %s\n", name, got, want)
		failures++
	}

	key, err := hex.DecodeString(v.Inputs.KeyHex)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	inner, err := hex.DecodeString(v.Inputs.InnerPlaintextHex)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	wantCt, err := hex.DecodeString(v.Outputs.CtHex)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	check("ct_hex", v.Outputs.CtHex,
		hex.EncodeToString(transport.SealCiphertext(key, v.Inputs.Seq, inner)))

	if pt, ok := transport.OpenCiphertext(key, v.Inputs.Seq, wantCt); ok {
		check("inner_plaintext_hex", v.Inputs.InnerPlaintextHex, hex.EncodeToString(pt))
	} else {
		fmt.Println("FAIL inner_plaintext_hex\n  got:  <authentication failed>")
		failures++
	}

	if failures > 0 {
		fmt.Fprintf(os.Stderr, "%d output(s) mismatched\n", failures)
		os.Exit(1)
	}
	fmt.Println("transport frame seals and opens to the shared vector")
}
