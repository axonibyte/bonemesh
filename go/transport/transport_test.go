// Round-trip and self-test coverage for the transport-envelope AEAD helpers.
// OpenCiphertext is the key-explicit counterpart to SealCiphertext used by the
// bonemesh-inspect tool; it must decrypt exactly what SealCiphertext produced
// for the same (key, seq), and must reject a tampered ciphertext or the wrong
// sequence number (which changes the nonce).
package transport

import (
	"bytes"
	"testing"
)

func TestSealOpenCiphertextRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	pt := []byte(`{"type":"data","mid":"deadbeefdeadbeefdeadbeefdeadbeef"}`)
	for _, seq := range []uint64{0, 1, 42, 65535} {
		ct := SealCiphertext(key, seq, pt)
		got, ok := OpenCiphertext(key, seq, ct)
		if !ok {
			t.Fatalf("seq %d: OpenCiphertext failed to open a freshly sealed frame", seq)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("seq %d: round-trip plaintext mismatch", seq)
		}
	}
}

func TestOpenCiphertextRejectsTamper(t *testing.T) {
	key := make([]byte, 32)
	ct := SealCiphertext(key, 7, []byte("payload"))
	tampered := append([]byte(nil), ct...)
	tampered[0] ^= 0x01
	if _, ok := OpenCiphertext(key, 7, tampered); ok {
		t.Fatal("a tampered ciphertext opened")
	}
}

func TestOpenCiphertextRejectsWrongSeq(t *testing.T) {
	key := make([]byte, 32)
	ct := SealCiphertext(key, 7, []byte("payload"))
	// The seq is the nonce, so opening under a different seq must fail the tag.
	if _, ok := OpenCiphertext(key, 8, ct); ok {
		t.Fatal("ciphertext opened under the wrong sequence number")
	}
}
