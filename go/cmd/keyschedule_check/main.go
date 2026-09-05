// Command keyschedule_check reads the shared key-schedule vector
// (spec/corpus/transcripts/keyschedule.json) and confirms this Go symmetric
// state reproduces every output. Agreement with the Java, Rust, and Elixir
// implementations over this file means a handshake driven by any of them derives
// the same transport keys. Invoked by interop/check-keyschedule-go.sh.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/axonibyte/bonemesh/gonode/keyschedule"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: keyschedule_check <path-to-keyschedule.json>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var doc struct {
		Inputs  map[string]string `json:"inputs"`
		Outputs map[string]string `json:"outputs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	s := keyschedule.New()
	failures := 0
	check := func(name, want string, got []byte) {
		if hex.EncodeToString(got) == want {
			fmt.Printf("PASS %s\n", name)
		} else {
			fmt.Printf("FAIL %s\n  got:  %s\n  want: %s\n", name, hex.EncodeToString(got), want)
			failures++
		}
	}

	check("h_init", doc.Outputs["h_init"], s.H)
	s.MixHash(unhex(doc.Inputs["mesh_hex"]))
	check("h_after_mesh", doc.Outputs["h_after_mesh"], s.H)
	s.MixKey(unhex(doc.Inputs["ss_dh_hex"]))
	check("ck_after_dh", doc.Outputs["ck_after_dh"], s.Ck)
	s.MixKey(unhex(doc.Inputs["ss_kem_hex"]))
	check("ck_after_kem", doc.Outputs["ck_after_kem"], s.Ck)
	ct1 := s.EncryptAndHash(unhex(doc.Inputs["plaintext1_hex"]))
	check("ct1", doc.Outputs["ct1_hex"], ct1)
	check("h_after_ct1", doc.Outputs["h_after_ct1"], s.H)
	ct2 := s.EncryptAndHash(unhex(doc.Inputs["plaintext2_hex"]))
	check("ct2", doc.Outputs["ct2_hex"], ct2)
	check("h_after_ct2", doc.Outputs["h_after_ct2"], s.H)
	i2r, r2i := s.Split()
	check("transport_key_i2r", doc.Outputs["transport_key_i2r"], i2r)
	check("transport_key_r2i", doc.Outputs["transport_key_r2i"], r2i)

	if failures > 0 {
		fmt.Fprintf(os.Stderr, "%d output(s) mismatched\n", failures)
		os.Exit(1)
	}
	fmt.Println("key schedule reproduces every shared output")
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad hex:", err)
		os.Exit(1)
	}
	return b
}
