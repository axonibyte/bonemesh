// Primitive round-trip and self-test coverage for the crypto package. These
// prove each primitive works and — where it matters — that the oracle actually
// fires on bad input (tampered AEAD, tampered signature), rather than passing
// vacuously. Cross-language agreement on these primitives is proven by the live
// interop matrix and the PQC interop vectors.
package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestSHA256KnownAnswer(t *testing.T) {
	// FIPS 180-4 example: SHA-256("abc").
	got := hex.EncodeToString(SHA256([]byte("abc")))
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got != want {
		t.Fatalf("SHA256(abc)=%s want %s", got, want)
	}
}

func TestAEADSealOpenRoundTrip(t *testing.T) {
	key := SHA256([]byte("k"))
	nonce := make([]byte, 12)
	pt := []byte("hello mesh")
	ct := AEADSeal(key, nonce, []byte("aad"), pt)
	got, ok := AEADOpen(key, nonce, []byte("aad"), ct)
	if !ok || !bytes.Equal(got, pt) {
		t.Fatalf("roundtrip failed ok=%v got=%q", ok, got)
	}
}

func TestAEADOpenRejectsTamper(t *testing.T) {
	key := SHA256([]byte("k"))
	nonce := make([]byte, 12)
	ct := AEADSeal(key, nonce, nil, []byte("hello"))
	ct[3] ^= 0x01
	if _, ok := AEADOpen(key, nonce, nil, ct); ok {
		t.Fatal("tampered ciphertext accepted")
	}
}

func TestAEADOpenRejectsWrongAAD(t *testing.T) {
	key := SHA256([]byte("k"))
	nonce := make([]byte, 12)
	ct := AEADSeal(key, nonce, []byte("aad-1"), []byte("hello"))
	if _, ok := AEADOpen(key, nonce, []byte("aad-2"), ct); ok {
		t.Fatal("wrong AAD accepted")
	}
}

func TestHKDFDeterministicAndLength(t *testing.T) {
	a := HKDF([]byte("salt"), []byte("ikm"), []byte("info"), 64)
	b := HKDF([]byte("salt"), []byte("ikm"), []byte("info"), 64)
	if len(a) != 64 || !bytes.Equal(a, b) {
		t.Fatal("HKDF not deterministic or wrong length")
	}
	c := HKDF([]byte("salt"), []byte("ikm"), []byte("other"), 64)
	if bytes.Equal(a, c) {
		t.Fatal("HKDF ignored info")
	}
}

func TestX25519AgreementSymmetric(t *testing.T) {
	aPub, aPriv := X25519Generate()
	bPub, bPriv := X25519Generate()
	if !bytes.Equal(X25519Agree(aPriv, bPub), X25519Agree(bPriv, aPub)) {
		t.Fatal("X25519 shared secrets differ")
	}
}

func TestMLKEM768EncapsDecaps(t *testing.T) {
	ek, dkSeed := MLKEM768Keypair()
	ss1, ct := MLKEM768Encapsulate(ek)
	ss2, ok := MLKEM768Decapsulate(dkSeed, ct)
	if !ok || !bytes.Equal(ss1, ss2) {
		t.Fatalf("KEM shared secrets differ ok=%v", ok)
	}
}

func TestMLKEM768DecapsRejectsGarbageSeed(t *testing.T) {
	if _, ok := MLKEM768Decapsulate([]byte("too-short"), make([]byte, 1088)); ok {
		t.Fatal("decapsulation accepted a malformed seed")
	}
}

func TestMLDSA65SignVerify(t *testing.T) {
	pub, priv := MLDSA65Generate()
	msg := []byte("transcript hash")
	sig := MLDSA65Sign(priv, msg)
	if !MLDSA65Verify(pub, msg, sig) {
		t.Fatal("valid ML-DSA-65 signature did not verify")
	}
}

func TestMLDSA65VerifyRejectsTamper(t *testing.T) {
	pub, priv := MLDSA65Generate()
	msg := []byte("transcript hash")
	sig := MLDSA65Sign(priv, msg)
	sig[10] ^= 0x01
	if MLDSA65Verify(pub, msg, sig) {
		t.Fatal("tampered signature verified")
	}
	if MLDSA65Verify(pub, []byte("different message"), MLDSA65Sign(priv, msg)) {
		t.Fatal("signature verified against the wrong message")
	}
}
