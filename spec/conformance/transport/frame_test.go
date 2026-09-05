// Package transport verifies the BoneMesh v3 transport-frame envelope
// (spec/corpus/transcripts/transport-frame.json) from the Go side: it
// reproduces the sealed ciphertext with x/crypto's ChaCha20-Poly1305 and the
// pinned sequence-derived nonce, and opens it. Matching the vector proves a Go
// node can read a transport frame a Java node sealed, and vice versa.
package transport

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/axonibyte/bonemesh/conformance/corpus"
)

type transportVector struct {
	Inputs struct {
		KeyHex            string `json:"key_hex"`
		Seq               uint64 `json:"seq"`
		InnerPlaintextHex string `json:"inner_plaintext_hex"`
	} `json:"inputs"`
	Outputs struct {
		CtHex string `json:"ct_hex"`
	} `json:"outputs"`
}

// nonce is 4 zero bytes then the 64-bit little-endian sequence (protocol.md §4).
func nonce(seq uint64) []byte {
	n := make([]byte, chacha20poly1305.NonceSize)
	binary.LittleEndian.PutUint64(n[4:], seq)
	return n
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestTransportFrameVector(t *testing.T) {
	var v transportVector
	if err := corpus.LoadInto("transcripts/transport-frame.json", &v); err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	key := mustHex(t, v.Inputs.KeyHex)
	inner := mustHex(t, v.Inputs.InnerPlaintextHex)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("new aead: %v", err)
	}

	// Reproduce the sealed ciphertext.
	got := aead.Seal(nil, nonce(v.Inputs.Seq), inner, nil)
	if hex.EncodeToString(got) != v.Outputs.CtHex {
		t.Fatalf("ct mismatch\n got:  %s\n want: %s", hex.EncodeToString(got), v.Outputs.CtHex)
	}

	// Open the vector's ciphertext (as if it arrived from a Java node).
	opened, err := aead.Open(nil, nonce(v.Inputs.Seq), mustHex(t, v.Outputs.CtHex), nil)
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	if !bytes.Equal(opened, inner) {
		t.Fatalf("opened plaintext mismatch:\n got:  %x\n want: %x", opened, inner)
	}
}
