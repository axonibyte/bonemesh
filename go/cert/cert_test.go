// Certificate build/verify tests (security.md §3). A cert is a mesh-root-signed
// binding of a label to an ML-DSA-65 identity key; its signed pre-image is the
// canon canonicalization of every field except "sig". The root here is a
// throwaway ML-DSA-87 key generated in-test via CIRCL, so the suite is
// self-contained and does not depend on the Java CA.
package cert

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/axonibyte/bonemesh/gonode/canon"
	"github.com/axonibyte/bonemesh/gonode/crypto"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

const (
	mesh = "acme-prod"
	nbf  = int64(1000)
	exp  = int64(2000)
	now  = int64(1500)
)

// signedCert issues a root-signed certificate and returns it with the raw root
// public key.
func signedCert(t *testing.T, label string) (map[string]any, []byte) {
	t.Helper()
	rootPub, rootPriv, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	idk, _ := crypto.MLDSA65Generate()
	c := Build(mesh, label, idk, nbf, exp)
	pre, err := canon.Canonicalize(c)
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, mldsa87.SignatureSize)
	if err := mldsa87.SignTo(rootPriv, []byte(pre), nil, false, sig); err != nil {
		t.Fatal(err)
	}
	c["sig"] = base64.StdEncoding.EncodeToString(sig)
	rootPubB, _ := rootPub.MarshalBinary()
	return c, rootPubB
}

func TestVerifyValidCert(t *testing.T) {
	c, root := signedCert(t, "alpha")
	if err := Verify(c, root, mesh, now); err != nil {
		t.Fatalf("valid cert rejected: %v", err)
	}
}

func TestIdentityKeyRoundTrip(t *testing.T) {
	idk, _ := crypto.MLDSA65Generate()
	c := Build(mesh, "alpha", idk, nbf, exp)
	got, err := IdentityKey(c)
	if err != nil {
		t.Fatal(err)
	}
	if base64.StdEncoding.EncodeToString(got) != base64.StdEncoding.EncodeToString(idk) {
		t.Fatal("identity key round-trip mismatch")
	}
}

func TestVerifyRejectsTamperedLabel(t *testing.T) {
	c, root := signedCert(t, "alpha")
	c["label"] = "mallory" // signature was over "alpha"
	if err := Verify(c, root, mesh, now); err == nil {
		t.Fatal("tampered label accepted")
	}
}

func TestVerifyRejectsTamperedIdentityKey(t *testing.T) {
	c, root := signedCert(t, "alpha")
	other, _ := crypto.MLDSA65Generate()
	c["idk"] = base64.StdEncoding.EncodeToString(other)
	if err := Verify(c, root, mesh, now); err == nil {
		t.Fatal("swapped identity key accepted")
	}
}

func TestVerifyRejectsWrongMesh(t *testing.T) {
	c, root := signedCert(t, "alpha")
	if err := Verify(c, root, "other-mesh", now); err == nil {
		t.Fatal("wrong mesh accepted")
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	c, root := signedCert(t, "alpha")
	if err := Verify(c, root, mesh, exp+1); err == nil {
		t.Fatal("expired cert accepted")
	}
}

func TestVerifyRejectsNotYetValid(t *testing.T) {
	c, root := signedCert(t, "alpha")
	if err := Verify(c, root, mesh, nbf-1); err == nil {
		t.Fatal("not-yet-valid cert accepted")
	}
}

func TestVerifyRejectsUnsigned(t *testing.T) {
	idk, _ := crypto.MLDSA65Generate()
	c := Build(mesh, "alpha", idk, nbf, exp)
	if err := Verify(c, make([]byte, mldsa87.PublicKeySize), mesh, now); err == nil {
		t.Fatal("unsigned cert accepted")
	}
}

func TestVerifyRejectsWrongRoot(t *testing.T) {
	c, _ := signedCert(t, "alpha")
	otherPub, _, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherRoot, _ := otherPub.MarshalBinary()
	if err := Verify(c, otherRoot, mesh, now); err == nil {
		t.Fatal("cert verified under the wrong root key")
	}
}

// TestBuildEmitsJSONNumbers guards the integer representation: v/nbf/exp must be
// json.Number so canonicalization sees integers, not floats.
func TestBuildEmitsJSONNumbers(t *testing.T) {
	idk, _ := crypto.MLDSA65Generate()
	c := Build(mesh, "alpha", idk, nbf, exp)
	for _, k := range []string{"v", "nbf", "exp"} {
		if _, ok := c[k].(json.Number); !ok {
			t.Fatalf("field %q is %T, want json.Number", k, c[k])
		}
	}
}
