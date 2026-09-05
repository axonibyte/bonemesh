// Package keyschedule implements the BMX key schedule (security.md §5): a
// Noise-style symmetric state carrying a transcript hash h and chaining key ck.
// Pinned constants match every other implementation (shared vector
// spec/corpus/transcripts/keyschedule.json).
package keyschedule

import (
	"encoding/binary"

	"github.com/axonibyte/bonemesh/gonode/crypto"
)

// ProtocolName seeds the state.
const ProtocolName = "BoneMesh_BMX_v3_X25519MLKEM768_ChaChaPoly_SHA256"

// State is the symmetric state.
type State struct {
	H     []byte
	Ck    []byte
	key   []byte
	nonce uint64
}

// New initializes from the protocol name.
func New() *State {
	h := crypto.SHA256([]byte(ProtocolName))
	ck := make([]byte, len(h))
	copy(ck, h)
	return &State{H: h, Ck: ck}
}

// MixHash absorbs data: h = SHA-256(h || data).
func (s *State) MixHash(data []byte) {
	s.H = crypto.SHA256(append(append([]byte{}, s.H...), data...))
}

// MixKey derives a fresh key and chaining key, resetting the nonce.
func (s *State) MixKey(ikm []byte) {
	okm := crypto.HKDF(s.Ck, ikm, nil, 64)
	s.Ck = okm[:32]
	s.key = okm[32:64]
	s.nonce = 0
}

// EncryptAndHash seals plaintext with h as AAD, then absorbs the ciphertext.
func (s *State) EncryptAndHash(plaintext []byte) []byte {
	ct := crypto.AEADSeal(s.key, s.nonce12(), s.H, plaintext)
	s.nonce++
	s.MixHash(ct)
	return ct
}

// DecryptAndHash opens a ciphertext (AAD is current h), then absorbs it.
func (s *State) DecryptAndHash(ciphertext []byte) ([]byte, bool) {
	ad := s.H
	pt, ok := crypto.AEADOpen(s.key, s.nonce12(), ad, ciphertext)
	if !ok {
		return nil, false
	}
	s.nonce++
	s.MixHash(ciphertext)
	return pt, true
}

// Split derives the two directional transport keys.
func (s *State) Split() (i2r, r2i []byte) {
	okm := crypto.HKDF(s.Ck, nil, nil, 64)
	return okm[:32], okm[32:64]
}

func (s *State) nonce12() []byte {
	n := make([]byte, 12)
	binary.LittleEndian.PutUint64(n[4:], s.nonce)
	return n
}
