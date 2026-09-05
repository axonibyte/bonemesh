// Package handshake implements the BMX handshake (security.md §4): a
// three-message, mutually authenticated, forward-secret exchange. Hybrid
// X25519 + ML-KEM-768 forward secrecy through the key schedule; authentication
// by a root-signed certificate plus an ML-DSA signature over the live
// transcript. Field-for-field identical to the Java, Elixir, and Rust
// implementations.
package handshake

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/axonibyte/bonemesh/gonode/cert"
	"github.com/axonibyte/bonemesh/gonode/crypto"
	"github.com/axonibyte/bonemesh/gonode/keyschedule"
)

// Session is the completed result: directional transport keys and the peer cert.
type Session struct {
	SendKey    []byte
	ReceiveKey []byte
	PeerCert   map[string]any
}

// Handshake is a single-use exchange threaded through the step methods.
type Handshake struct {
	mesh       string
	rootPublic []byte
	now        int64
	cert       map[string]any
	idPrivate  []byte
	ks         *keyschedule.State
	ephDHPub   []byte
	ephDHPriv  []byte
	ephKEMek   []byte
	ephKEMdk   []byte
	session    *Session
}

// Initiator creates the initiating side.
func Initiator(mesh string, rootPublic []byte, now int64, c map[string]any, idPrivate []byte) *Handshake {
	return newHS(mesh, rootPublic, now, c, idPrivate)
}

// Responder creates the responding side.
func Responder(mesh string, rootPublic []byte, now int64, c map[string]any, idPrivate []byte) *Handshake {
	return newHS(mesh, rootPublic, now, c, idPrivate)
}

func newHS(mesh string, rootPublic []byte, now int64, c map[string]any, idPrivate []byte) *Handshake {
	ks := keyschedule.New()
	ks.MixHash([]byte(mesh))
	return &Handshake{mesh: mesh, rootPublic: rootPublic, now: now, cert: c, idPrivate: idPrivate, ks: ks}
}

// WriteMessage1 (initiator) produces message 1.
func (h *Handshake) WriteMessage1() []byte {
	h.ephDHPub, h.ephDHPriv = crypto.X25519Generate()
	h.ephKEMek, h.ephKEMdk = crypto.MLKEM768Keypair()
	n := make([]byte, 32)
	rand.Read(n)
	h.ks.MixHash(h.ephDHPub)
	h.ks.MixHash(h.ephKEMek)
	h.ks.MixHash(n)
	return line(map[string]any{
		"t": "bmx1", "v": 3, "mesh": h.mesh,
		"e": b64(h.ephDHPub), "k": b64(h.ephKEMek), "n": b64(n),
	})
}

// ReadMessage1WriteMessage2 (responder) consumes msg1, produces msg2.
func (h *Handshake) ReadMessage1WriteMessage2(msg1 []byte) ([]byte, error) {
	m, err := decode(msg1)
	if err != nil {
		return nil, err
	}
	if m["t"] != "bmx1" {
		return nil, errors.New("expected bmx1")
	}
	if v, _ := m["v"].(json.Number); v.String() != "3" {
		return nil, errors.New("unsupported version")
	}
	if m["mesh"] != h.mesh {
		return nil, errors.New("mesh mismatch")
	}
	eiPub, _ := unb64(m["e"])
	kiEk, _ := unb64(m["k"])
	n, _ := unb64(m["n"])
	h.ks.MixHash(eiPub)
	h.ks.MixHash(kiEk)
	h.ks.MixHash(n)

	erPub, erPriv := crypto.X25519Generate()
	h.ks.MixHash(erPub)
	h.ks.MixKey(crypto.X25519Agree(erPriv, eiPub))

	ssKem, ct := crypto.MLKEM768Encapsulate(kiEk)
	h.ks.MixHash(ct)
	h.ks.MixKey(ssKem)

	auth := h.sealIdentity()
	return line(map[string]any{"t": "bmx2", "e": b64(erPub), "ct": b64(ct), "auth": b64(auth)}), nil
}

// ReadMessage2WriteMessage3 (initiator) verifies the responder, produces msg3.
func (h *Handshake) ReadMessage2WriteMessage3(msg2 []byte) ([]byte, error) {
	m, err := decode(msg2)
	if err != nil {
		return nil, err
	}
	erPub, _ := unb64(m["e"])
	ct, _ := unb64(m["ct"])
	auth, _ := unb64(m["auth"])

	h.ks.MixHash(erPub)
	h.ks.MixKey(crypto.X25519Agree(h.ephDHPriv, erPub))
	h.ks.MixHash(ct)
	ssKem, ok := crypto.MLKEM768Decapsulate(h.ephKEMdk, ct)
	if !ok {
		return nil, errors.New("decapsulation failed")
	}
	h.ks.MixKey(ssKem)

	peerCert, err := h.openIdentity(auth)
	if err != nil {
		return nil, err
	}
	authI := h.sealIdentity()
	out := line(map[string]any{"t": "bmx3", "auth": b64(authI)})
	i2r, r2i := h.ks.Split()
	h.session = &Session{SendKey: i2r, ReceiveKey: r2i, PeerCert: peerCert}
	return out, nil
}

// ReadMessage3 (responder) verifies the initiator, completing the handshake.
func (h *Handshake) ReadMessage3(msg3 []byte) error {
	m, err := decode(msg3)
	if err != nil {
		return err
	}
	auth, _ := unb64(m["auth"])
	peerCert, err := h.openIdentity(auth)
	if err != nil {
		return err
	}
	i2r, r2i := h.ks.Split()
	h.session = &Session{SendKey: r2i, ReceiveKey: i2r, PeerCert: peerCert}
	return nil
}

// SessionResult returns the completed session.
func (h *Handshake) SessionResult() *Session { return h.session }

func (h *Handshake) sealIdentity() []byte {
	sig := crypto.MLDSA65Sign(h.idPrivate, h.ks.H)
	payload, _ := json.Marshal(map[string]any{"cert": h.cert, "sig": b64(sig)})
	return h.ks.EncryptAndHash(payload)
}

func (h *Handshake) openIdentity(auth []byte) (map[string]any, error) {
	hPre := append([]byte{}, h.ks.H...)
	pt, ok := h.ks.DecryptAndHash(auth)
	if !ok {
		return nil, errors.New("handshake authentication failed")
	}
	// UseNumber so the nested certificate's integers stay json.Number for
	// canonicalization and verification.
	payload, err := decode(pt)
	if err != nil {
		return nil, errors.New("bad auth payload")
	}
	peerCert, _ := payload["cert"].(map[string]any)
	if err := cert.Verify(peerCert, h.rootPublic, h.mesh, h.now); err != nil {
		return nil, errors.New("peer certificate invalid: " + err.Error())
	}
	sig, _ := unb64(payload["sig"])
	idk, _ := cert.IdentityKey(peerCert)
	if !crypto.MLDSA65Verify(idk, hPre, sig) {
		return nil, errors.New("peer transcript signature does not verify")
	}
	return peerCert, nil
}

func line(m map[string]any) []byte {
	b, _ := json.Marshal(m)
	return append(b, '\n')
}

func decode(b []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, errors.New("invalid json")
	}
	return m, nil
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func unb64(v any) ([]byte, error) {
	s, ok := v.(string)
	if !ok {
		return nil, errors.New("expected base64 string")
	}
	return base64.StdEncoding.DecodeString(s)
}
