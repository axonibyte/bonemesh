// Key-schedule known-answer test. The expected values are the shared vector
// (spec/corpus/transcripts/keyschedule.json, security.md §5); reproducing them
// byte-for-byte is what proves the Go symmetric state agrees with the Java,
// Elixir, and Rust ones. Sequence per the vector: init(protocol_name);
// mixHash(mesh); mixKey(ss_dh); mixKey(ss_kem); ct1=encryptAndHash(pt1);
// ct2=encryptAndHash(pt2); split().
package keyschedule

import (
	"encoding/hex"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("unhex %q: %v", s, err)
	}
	return b
}

func TestKnownAnswerVector(t *testing.T) {
	const (
		meshHex      = "61636d652d70726f64"
		ssDHHex      = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
		ssKEMHex     = "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"
		plaintext1   = "726573706f6e6465722d61757468"
		plaintext2   = "696e69746961746f722d61757468"
		hInit        = "ca2ab22f811afb5bca159916bd550d879ac5a6f6640d906dc05e2d9ce12c9824"
		hAfterMesh   = "f36deae782aa75db659a1d0f27b8edac65913a143bdfefa96fcc401b99c8df88"
		ckAfterDH    = "db8ea3441454c76670fd8ec86c28f1f9231b0fef58723c28a046ae457b0a107c"
		ckAfterKEM   = "63e4507c23369f55dbf3fbb1d5d887c11f70b156e145db51f3aa92a02050a379"
		ct1Hex       = "cd2faeb0160163d5ed9c8cb51f305fb9b257fbd4a06b0c371d92cbab994c"
		hAfterCT1    = "316b0b3f656dddfada310c4d82595b2a9c179d68df9fe73f025da9739bef6e4c"
		ct2Hex       = "f56b543d04ce3034e88151cc765c6de343f3039d3f72ee53e16096e3f8d9"
		hAfterCT2    = "ae83a01e2d5cf41eed8fc2df0eae17c322a920a15790454453df958df16ced76"
		transportI2R = "b134801d6ec2279d03afb8ed625aaa787c6e06ceb1c11f347bad6f7432c8cb78"
		transportR2I = "1b29fa1fa1ef13710241c6750c08d2e3188009cc693cf1e78497ca5d97203aee"
	)

	eq := func(name, want string, got []byte) {
		if h := hex.EncodeToString(got); h != want {
			t.Fatalf("%s mismatch\n got: %s\nwant: %s", name, h, want)
		}
	}

	s := New()
	eq("h_init", hInit, s.H)

	s.MixHash(unhex(t, meshHex))
	eq("h_after_mesh", hAfterMesh, s.H)

	s.MixKey(unhex(t, ssDHHex))
	eq("ck_after_dh", ckAfterDH, s.Ck)

	s.MixKey(unhex(t, ssKEMHex))
	eq("ck_after_kem", ckAfterKEM, s.Ck)

	ct1 := s.EncryptAndHash(unhex(t, plaintext1))
	eq("ct1", ct1Hex, ct1)
	eq("h_after_ct1", hAfterCT1, s.H)

	ct2 := s.EncryptAndHash(unhex(t, plaintext2))
	eq("ct2", ct2Hex, ct2)
	eq("h_after_ct2", hAfterCT2, s.H)

	i2r, r2i := s.Split()
	eq("transport_key_i2r", transportI2R, i2r)
	eq("transport_key_r2i", transportR2I, r2i)
}

// TestDecryptAndHashRoundTrip proves the receiving side recovers the plaintext
// and lands on the same transcript hash as the sender — the property the KAT's
// encrypt side asserts, exercised from the other direction.
func TestDecryptAndHashRoundTrip(t *testing.T) {
	mesh := unhex(t, "61636d652d70726f64")
	ssDH := unhex(t, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	ssKEM := unhex(t, "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40")
	pt := []byte("responder-auth")

	send := New()
	send.MixHash(mesh)
	send.MixKey(ssDH)
	send.MixKey(ssKEM)
	ct := send.EncryptAndHash(pt)

	recv := New()
	recv.MixHash(mesh)
	recv.MixKey(ssDH)
	recv.MixKey(ssKEM)
	got, ok := recv.DecryptAndHash(ct)
	if !ok {
		t.Fatal("DecryptAndHash failed")
	}
	if string(got) != string(pt) {
		t.Fatalf("plaintext mismatch: %q", got)
	}
	if hex.EncodeToString(recv.H) != hex.EncodeToString(send.H) {
		t.Fatal("transcript hashes diverged after encrypt/decrypt")
	}
}

// TestDecryptRejectsTamperedCiphertext self-tests the AEAD oracle: a flipped
// ciphertext byte must be rejected, not silently accepted.
func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	s := New()
	s.MixKey(unhex(t, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"))
	ct := s.EncryptAndHash([]byte("payload"))
	ct[0] ^= 0x01
	r := New()
	r.MixKey(unhex(t, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"))
	if _, ok := r.DecryptAndHash(ct); ok {
		t.Fatal("tampered ciphertext was accepted")
	}
}
