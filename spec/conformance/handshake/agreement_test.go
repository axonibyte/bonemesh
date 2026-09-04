// Package handshake verifies the BMX hybrid key-agreement vector
// (spec/corpus/transcripts/handshake-agreement.json) from the Go side: it
// derives ss_dh independently with crypto/ecdh (X25519) and runs the
// independent Go key schedule, confirming both languages reach the same
// transport keys.
//
// ML-KEM cross-decapsulation and ML-DSA signatures are deferred interop items
// (see spec/corpus/transcripts/README.md): ss_kem is taken from the vector, and
// the schedule freeze from sub-unit 3a plus the X25519 check here cover the rest.
package handshake

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"testing"

	"github.com/axonibyte/bonemesh/conformance/corpus"
	"github.com/axonibyte/bonemesh/conformance/keyschedule"
)

type agreementVector struct {
	Inputs struct {
		MeshHex   string `json:"mesh_hex"`
		EiPrivHex string `json:"ei_priv_hex"`
		EiPubHex  string `json:"ei_pub_hex"`
		ErPubHex  string `json:"er_pub_hex"`
		KiEkHex   string `json:"ki_ek_hex"`
		KemCtHex  string `json:"kem_ct_hex"`
		NHex      string `json:"n_hex"`
		SsDhHex   string `json:"ss_dh_hex"`
		SsKemHex  string `json:"ss_kem_hex"`
	} `json:"inputs"`
	Outputs struct {
		HAfterMsg1           string `json:"h_after_msg1"`
		CkAfterDh            string `json:"ck_after_dh"`
		CkAfterKem           string `json:"ck_after_kem"`
		HAfterMsg2Ephemerals string `json:"h_after_msg2_ephemerals"`
		TransportKeyI2R      string `json:"transport_key_i2r"`
		TransportKeyR2I      string `json:"transport_key_r2i"`
	} `json:"outputs"`
}

func dh(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestAgreementVector(t *testing.T) {
	var v agreementVector
	if err := corpus.LoadInto("transcripts/handshake-agreement.json", &v); err != nil {
		t.Fatalf("load corpus: %v", err)
	}

	// Independent X25519 cross-check: Go derives ss_dh from the initiator's
	// private scalar and the responder's public key, and it must match the
	// vector's ss_dh that Java (BouncyCastle) produced.
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(dh(t, v.Inputs.EiPrivHex))
	if err != nil {
		t.Fatalf("ei_priv: %v", err)
	}
	if got := hex.EncodeToString(priv.PublicKey().Bytes()); got != v.Inputs.EiPubHex {
		t.Errorf("X25519 public key mismatch:\n got:  %s\n want: %s", got, v.Inputs.EiPubHex)
	}
	erPub, err := curve.NewPublicKey(dh(t, v.Inputs.ErPubHex))
	if err != nil {
		t.Fatalf("er_pub: %v", err)
	}
	ssDh, err := priv.ECDH(erPub)
	if err != nil {
		t.Fatalf("ECDH: %v", err)
	}
	if !bytes.Equal(ssDh, dh(t, v.Inputs.SsDhHex)) {
		t.Fatalf("X25519 ss_dh mismatch:\n got:  %s\n want: %s",
			hex.EncodeToString(ssDh), v.Inputs.SsDhHex)
	}

	// Run the key schedule (Go implementation) with the agreed secrets and
	// confirm every transcript checkpoint and both transport keys.
	s := keyschedule.New()
	s.MixHash(dh(t, v.Inputs.MeshHex))
	s.MixHash(dh(t, v.Inputs.EiPubHex))
	s.MixHash(dh(t, v.Inputs.KiEkHex))
	s.MixHash(dh(t, v.Inputs.NHex))
	eq(t, "h_after_msg1", s.TranscriptHash(), v.Outputs.HAfterMsg1)
	s.MixHash(dh(t, v.Inputs.ErPubHex))
	s.MixKey(ssDh)
	eq(t, "ck_after_dh", s.ChainingKey(), v.Outputs.CkAfterDh)
	s.MixHash(dh(t, v.Inputs.KemCtHex))
	s.MixKey(dh(t, v.Inputs.SsKemHex))
	eq(t, "ck_after_kem", s.ChainingKey(), v.Outputs.CkAfterKem)
	eq(t, "h_after_msg2_ephemerals", s.TranscriptHash(), v.Outputs.HAfterMsg2Ephemerals)
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
