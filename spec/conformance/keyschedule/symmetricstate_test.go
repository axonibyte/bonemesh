package keyschedule

import (
	"encoding/hex"
	"testing"

	"github.com/axonibyte/bonemesh/conformance/corpus"
)

type ksVector struct {
	Inputs struct {
		ProtocolName string `json:"protocol_name"`
		MeshHex      string `json:"mesh_hex"`
		SsDhHex      string `json:"ss_dh_hex"`
		SsKemHex     string `json:"ss_kem_hex"`
		Plaintext1   string `json:"plaintext1_hex"`
		Plaintext2   string `json:"plaintext2_hex"`
	} `json:"inputs"`
	Outputs struct {
		HInit           string `json:"h_init"`
		HAfterMesh      string `json:"h_after_mesh"`
		CkAfterDh       string `json:"ck_after_dh"`
		CkAfterKem      string `json:"ck_after_kem"`
		Ct1Hex          string `json:"ct1_hex"`
		HAfterCt1       string `json:"h_after_ct1"`
		Ct2Hex          string `json:"ct2_hex"`
		HAfterCt2       string `json:"h_after_ct2"`
		TransportKeyI2R string `json:"transport_key_i2r"`
		TransportKeyR2I string `json:"transport_key_r2i"`
	} `json:"outputs"`
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// Reproduces the shared key-schedule vector with this independent Go
// implementation. Matching every output is the cross-language freeze: a Go node
// and the Java reference derive identical keys.
func TestKeyScheduleVector(t *testing.T) {
	var v ksVector
	if err := corpus.LoadInto("transcripts/keyschedule.json", &v); err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	if v.Inputs.ProtocolName != ProtocolName {
		t.Fatalf("protocol name mismatch: %q vs %q", v.Inputs.ProtocolName, ProtocolName)
	}

	s := New()
	eq(t, "h_init", s.TranscriptHash(), v.Outputs.HInit)
	s.MixHash(mustHex(t, v.Inputs.MeshHex))
	eq(t, "h_after_mesh", s.TranscriptHash(), v.Outputs.HAfterMesh)
	s.MixKey(mustHex(t, v.Inputs.SsDhHex))
	eq(t, "ck_after_dh", s.ChainingKey(), v.Outputs.CkAfterDh)
	s.MixKey(mustHex(t, v.Inputs.SsKemHex))
	eq(t, "ck_after_kem", s.ChainingKey(), v.Outputs.CkAfterKem)

	ct1 := s.EncryptAndHash(mustHex(t, v.Inputs.Plaintext1))
	eq(t, "ct1", ct1, v.Outputs.Ct1Hex)
	eq(t, "h_after_ct1", s.TranscriptHash(), v.Outputs.HAfterCt1)
	ct2 := s.EncryptAndHash(mustHex(t, v.Inputs.Plaintext2))
	eq(t, "ct2", ct2, v.Outputs.Ct2Hex)
	eq(t, "h_after_ct2", s.TranscriptHash(), v.Outputs.HAfterCt2)

	i2r, r2i := s.Split()
	eq(t, "transport_key_i2r", i2r, v.Outputs.TransportKeyI2R)
	eq(t, "transport_key_r2i", r2i, v.Outputs.TransportKeyR2I)
}

func eq(t *testing.T, name string, got []byte, wantHex string) {
	t.Helper()
	if hex.EncodeToString(got) != wantHex {
		t.Errorf("%s mismatch\n got:  %s\n want: %s", name, hex.EncodeToString(got), wantHex)
	}
}
