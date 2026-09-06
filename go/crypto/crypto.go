// Package crypto provides the BoneMesh v3 cryptographic primitives (security.md
// §1): SHA-256, HKDF-SHA-256, ChaCha20-Poly1305, X25519, ML-KEM-768 (Go stdlib),
// and ML-DSA-65/87 (Cloudflare CIRCL). Public keys, ciphertexts, secrets, and
// signatures are the raw FIPS/RFC encodings, matching the other implementations.
package crypto

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"golang.org/x/crypto/chacha20poly1305"
)

// SHA256 digest.
func SHA256(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

// HKDF is full extract-then-expand HKDF-SHA-256 (RFC 5869).
func HKDF(salt, ikm, info []byte, length int) []byte {
	out, err := hkdf.Key(sha256.New, ikm, salt, string(info), length)
	if err != nil {
		panic(err)
	}
	return out
}

// AEADSeal returns ChaCha20-Poly1305 ciphertext with the 16-byte tag appended.
func AEADSeal(key, nonce, aad, plaintext []byte) []byte {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}
	return aead.Seal(nil, nonce, plaintext, aad)
}

// AEADOpen returns the plaintext, or ok=false on tag failure.
func AEADOpen(key, nonce, aad, ct []byte) ([]byte, bool) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, false
	}
	pt, err := aead.Open(nil, nonce, ct, aad)
	return pt, err == nil
}

// X25519Generate returns (publicKey, privateKey) as raw 32-byte encodings.
func X25519Generate() ([]byte, []byte) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return priv.PublicKey().Bytes(), priv.Bytes()
}

// X25519Agree computes the raw shared secret.
func X25519Agree(privateKey, peerPublic []byte) []byte {
	priv, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		panic(err)
	}
	pub, err := ecdh.X25519().NewPublicKey(peerPublic)
	if err != nil {
		panic(err)
	}
	ss, err := priv.ECDH(pub)
	if err != nil {
		panic(err)
	}
	return ss
}

// MLKEM768Keypair returns (encapsulationKey, decapsulationKeySeed). The seed is
// this node's own private material and never leaves it.
func MLKEM768Keypair() ([]byte, []byte) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		panic(err)
	}
	return dk.EncapsulationKey().Bytes(), dk.Bytes()
}

// MLKEM768Encapsulate encapsulates to a raw encapsulation key, returning
// (sharedSecret, ciphertext).
func MLKEM768Encapsulate(encapsulationKey []byte) ([]byte, []byte) {
	ek, err := mlkem.NewEncapsulationKey768(encapsulationKey)
	if err != nil {
		panic(err)
	}
	ss, ct := ek.Encapsulate()
	return ss, ct
}

// MLKEM768Decapsulate recovers the shared secret from a ciphertext using this
// node's decapsulation-key seed.
func MLKEM768Decapsulate(decapsulationKeySeed, ciphertext []byte) ([]byte, bool) {
	dk, err := mlkem.NewDecapsulationKey768(decapsulationKeySeed)
	if err != nil {
		return nil, false
	}
	ss, err := dk.Decapsulate(ciphertext)
	if err != nil {
		return nil, false
	}
	return ss, true
}

// MLDSA65Verify verifies an ML-DSA-65 signature (empty context).
func MLDSA65Verify(publicKey, message, signature []byte) bool {
	var pub mldsa65.PublicKey
	if err := pub.UnmarshalBinary(publicKey); err != nil {
		return false
	}
	return mldsa65.Verify(&pub, message, nil, signature)
}

// MLDSA65Sign signs a message with an ML-DSA-65 private key (empty context).
func MLDSA65Sign(privateKey, message []byte) []byte {
	var priv mldsa65.PrivateKey
	if err := priv.UnmarshalBinary(privateKey); err != nil {
		panic(err)
	}
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(&priv, message, nil, false, sig); err != nil {
		panic(err)
	}
	return sig
}

// MLDSA65Generate returns (publicKey, privateKey) as raw encodings.
func MLDSA65Generate() ([]byte, []byte) {
	pub, priv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	pubB, _ := pub.MarshalBinary()
	privB, _ := priv.MarshalBinary()
	return pubB, privB
}

// MLDSA87Generate returns (publicKey, privateKey) as raw encodings — the mesh
// root keypair.
func MLDSA87Generate() ([]byte, []byte) {
	pub, priv, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	pubB, _ := pub.MarshalBinary()
	privB, _ := priv.MarshalBinary()
	return pubB, privB
}

// MLDSA87Sign signs a message with an ML-DSA-87 private key (empty context).
func MLDSA87Sign(privateKey, message []byte) []byte {
	var priv mldsa87.PrivateKey
	if err := priv.UnmarshalBinary(privateKey); err != nil {
		panic(err)
	}
	sig := make([]byte, mldsa87.SignatureSize)
	if err := mldsa87.SignTo(&priv, message, nil, false, sig); err != nil {
		panic(err)
	}
	return sig
}

// MLDSA87Verify verifies an ML-DSA-87 signature (empty context) — the mesh root.
func MLDSA87Verify(publicKey, message, signature []byte) bool {
	var pub mldsa87.PublicKey
	if err := pub.UnmarshalBinary(publicKey); err != nil {
		return false
	}
	return mldsa87.Verify(&pub, message, nil, signature)
}
