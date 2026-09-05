// Command agreement_check reads the shared hybrid key-agreement vector
// (spec/corpus/transcripts/handshake-agreement.json) and confirms this Go
// implementation reproduces the transcript checkpoints and transport keys.
// Given the agreed X25519 and ML-KEM secrets and the transcript inputs, the
// sequence is: mixHash(mesh, ei_pub, ki_ek, n); mixHash(er_pub); mixKey(ss_dh);
// mixHash(ct); mixKey(ss_kem); split(). Invoked by interop/check-agreement-go.sh.
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
		fmt.Fprintln(os.Stderr, "usage: agreement_check <path-to-handshake-agreement.json>")
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
	in := func(k string) []byte { return unhex(doc.Inputs[k]) }

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

	s.MixHash(in("mesh_hex"))
	s.MixHash(in("ei_pub_hex"))
	s.MixHash(in("ki_ek_hex"))
	s.MixHash(in("n_hex"))
	check("h_after_msg1", doc.Outputs["h_after_msg1"], s.H)

	s.MixHash(in("er_pub_hex"))
	s.MixKey(in("ss_dh_hex"))
	check("ck_after_dh", doc.Outputs["ck_after_dh"], s.Ck)

	s.MixHash(in("kem_ct_hex"))
	s.MixKey(in("ss_kem_hex"))
	check("ck_after_kem", doc.Outputs["ck_after_kem"], s.Ck)

	// The msg-2 transcript checkpoint is taken once both message-2 hash inputs
	// (the responder ephemeral and the KEM ciphertext) have been absorbed;
	// mixKey does not alter the transcript hash.
	check("h_after_msg2_ephemerals", doc.Outputs["h_after_msg2_ephemerals"], s.H)

	i2r, r2i := s.Split()
	check("transport_key_i2r", doc.Outputs["transport_key_i2r"], i2r)
	check("transport_key_r2i", doc.Outputs["transport_key_r2i"], r2i)

	if failures > 0 {
		fmt.Fprintf(os.Stderr, "%d checkpoint(s) mismatched\n", failures)
		os.Exit(1)
	}
	fmt.Println("hybrid key agreement reproduces every shared checkpoint")
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad hex:", err)
		os.Exit(1)
	}
	return b
}
