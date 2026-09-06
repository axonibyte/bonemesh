// Package transport implements the encrypted transport channel over a completed
// handshake (protocol.md §4): each frame is a sequence-numbered AEAD carrier
// {"seq":n,"ct":...} whose plaintext is the inner JSON message. The
// per-direction sequence is the ChaCha20-Poly1305 nonce; reordered or replayed
// frames are rejected. Matches the shared transport-frame vector.
package transport

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"

	"github.com/axonibyte/bonemesh/gonode/crypto"
	"github.com/axonibyte/bonemesh/gonode/handshake"
)

// Transport is a transport session.
type Transport struct {
	sendKey    []byte
	receiveKey []byte
	sendSeq    uint64
	receiveSeq uint64
}

// New builds a transport session from a completed handshake session.
func New(s *handshake.Session) *Transport {
	return &Transport{sendKey: s.SendKey, receiveKey: s.ReceiveKey}
}

// SendSeq and ReceiveSeq report the per-direction frame counters, so a node can
// decide when a rekey is due (F5).
func (t *Transport) SendSeq() uint64    { return t.sendSeq }
func (t *Transport) ReceiveSeq() uint64 { return t.receiveSeq }

// SwapSend installs a new outbound key and resets the send counter to 0. Called
// at the rekey boundary immediately after sealing the last old-key frame in
// this direction, so the very next frame uses the new key at seq 0 (F5).
func (t *Transport) SwapSend(key []byte) {
	t.sendKey = key
	t.sendSeq = 0
}

// SwapReceive installs a new inbound key and resets the receive counter, called
// immediately after opening the last old-key frame in this direction.
func (t *Transport) SwapReceive(key []byte) {
	t.receiveKey = key
	t.receiveSeq = 0
}

// Seal seals an inner message into a {seq, ct} carrier.
func (t *Transport) Seal(inner map[string]any) map[string]any {
	seq := t.sendSeq
	pt, _ := json.Marshal(inner)
	ct := SealCiphertext(t.sendKey, seq, pt)
	t.sendSeq++
	return map[string]any{"seq": seq, "ct": base64.StdEncoding.EncodeToString(ct)}
}

// Open opens a carrier, enforcing in-order delivery.
func (t *Transport) Open(carrier map[string]any) (map[string]any, error) {
	seq, err := asUint(carrier["seq"])
	if err != nil {
		return nil, err
	}
	if seq != t.receiveSeq {
		return nil, errors.New("out-of-order frame")
	}
	ctStr, _ := carrier["ct"].(string)
	ct, err := base64.StdEncoding.DecodeString(ctStr)
	if err != nil {
		return nil, errors.New("bad ct")
	}
	pt, ok := crypto.AEADOpen(t.receiveKey, nonce(seq), nil, ct)
	if !ok {
		return nil, errors.New("frame authentication failed")
	}
	t.receiveSeq++
	var inner map[string]any
	dec := json.NewDecoder(bytes.NewReader(pt))
	dec.UseNumber()
	if err := dec.Decode(&inner); err != nil {
		return nil, errors.New("bad inner json")
	}
	return inner, nil
}

// SealCiphertext is the single transport-envelope AEAD implementation.
func SealCiphertext(key []byte, seq uint64, plaintext []byte) []byte {
	return crypto.AEADSeal(key, nonce(seq), nil, plaintext)
}

// OpenCiphertext decrypts a transport-envelope ciphertext with an explicit key
// and sequence number — the counterpart to SealCiphertext, for consumers (the
// bonemesh-inspect tool) that hold keys directly and cannot use the strict
// in-order Transport.Open. Returns (plaintext, true) on success.
func OpenCiphertext(key []byte, seq uint64, ct []byte) ([]byte, bool) {
	return crypto.AEADOpen(key, nonce(seq), nil, ct)
}

func nonce(seq uint64) []byte {
	n := make([]byte, 12)
	binary.LittleEndian.PutUint64(n[4:], seq)
	return n
}

func asUint(v any) (uint64, error) {
	switch t := v.(type) {
	case json.Number:
		i, err := t.Int64()
		return uint64(i), err
	case float64:
		return uint64(t), nil
	default:
		return 0, errors.New("missing seq")
	}
}
