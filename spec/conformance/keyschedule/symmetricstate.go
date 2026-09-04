// Package keyschedule is an independent Go implementation of the BMX key
// schedule (security.md §5), written from the spec — not ported from the Java
// reference. Reproducing the shared vector
// (spec/corpus/transcripts/keyschedule.json) with this independent
// implementation is the cross-language freeze of the key-schedule constants:
// both languages derive identical transcript hashes, chaining keys, and
// transport keys.
package keyschedule

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"

	"golang.org/x/crypto/chacha20poly1305"
)

// ProtocolName is the pinned BMX protocol name that seeds the state.
const ProtocolName = "BoneMesh_BMX_v3_X25519MLKEM768_ChaChaPoly_SHA256"

// State is the Noise-style symmetric state carrying the transcript hash h and
// chaining key ck.
type State struct {
	h     []byte
	ck    []byte
	key   []byte
	nonce uint64
}

// New initializes the state from the pinned protocol name.
func New() *State {
	sum := sha256.Sum256([]byte(ProtocolName))
	h := sum[:]
	ck := make([]byte, len(h))
	copy(ck, h)
	return &State{h: h, ck: ck}
}

// MixHash absorbs data into the transcript hash: h = SHA-256(h || data).
func (s *State) MixHash(data []byte) {
	sum := sha256.Sum256(append(append([]byte{}, s.h...), data...))
	s.h = sum[:]
}

// MixKey derives a fresh key and chaining key from input key material.
func (s *State) MixKey(ikm []byte) {
	okm, err := hkdf.Key(sha256.New, ikm, s.ck, "", 64)
	if err != nil {
		panic(err)
	}
	s.ck = okm[:32]
	s.key = okm[32:64]
	s.nonce = 0
}

// EncryptAndHash seals plaintext with h as associated data, then absorbs the
// ciphertext.
func (s *State) EncryptAndHash(plaintext []byte) []byte {
	aead, err := chacha20poly1305.New(s.key)
	if err != nil {
		panic(err)
	}
	ct := aead.Seal(nil, s.nextNonce(), plaintext, s.h)
	s.MixHash(ct)
	return ct
}

// Split derives the two directional transport keys from the final chaining key.
func (s *State) Split() (i2r, r2i []byte) {
	okm, err := hkdf.Key(sha256.New, []byte{}, s.ck, "", 64)
	if err != nil {
		panic(err)
	}
	return okm[:32], okm[32:64]
}

// TranscriptHash returns a copy of the current transcript hash.
func (s *State) TranscriptHash() []byte {
	out := make([]byte, len(s.h))
	copy(out, s.h)
	return out
}

// ChainingKey returns a copy of the current chaining key.
func (s *State) ChainingKey() []byte {
	out := make([]byte, len(s.ck))
	copy(out, s.ck)
	return out
}

// nextNonce builds the 12-byte AEAD nonce (4 zero bytes then the little-endian
// counter) and increments the counter.
func (s *State) nextNonce() []byte {
	n := make([]byte, chacha20poly1305.NonceSize)
	binary.LittleEndian.PutUint64(n[4:], s.nonce)
	s.nonce++
	return n
}
