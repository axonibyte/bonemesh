// Package cert implements the BoneMesh v3 membership certificate (security.md
// §3): a mesh-root-signed binding of a label to a node's ML-DSA-65 identity key.
// Represented as map[string]any (the JSON form); its signed pre-image is the
// canon canonicalization of every field except "sig".
package cert

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/axonibyte/bonemesh/gonode/canon"
	"github.com/axonibyte/bonemesh/gonode/crypto"
)

// Build makes an unsigned certificate. identityKey is the raw ML-DSA-65 public key.
func Build(mesh, label string, identityKey []byte, notBefore, notAfter int64) map[string]any {
	return map[string]any{
		"v":     json.Number("3"),
		"mesh":  mesh,
		"label": label,
		"idk":   base64.StdEncoding.EncodeToString(identityKey),
		"nbf":   json.Number(fmt.Sprintf("%d", notBefore)),
		"exp":   json.Number(fmt.Sprintf("%d", notAfter)),
	}
}

// Verify checks a certificate against the pinned root public key, mesh, and time.
func Verify(cert map[string]any, rootPublic []byte, expectedMesh string, now int64) error {
	if s, _ := cert["mesh"].(string); s != expectedMesh {
		return errors.New("mesh mismatch")
	}
	if nbf, ok := asInt(cert["nbf"]); !ok || now < nbf {
		return errors.New("certificate not yet valid")
	}
	if exp, ok := asInt(cert["exp"]); !ok || now > exp {
		return errors.New("certificate expired")
	}
	sigB64, ok := cert["sig"].(string)
	if !ok {
		return errors.New("certificate is unsigned")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return errors.New("signature is not base64")
	}
	preImage, err := canon.Canonicalize(cert)
	if err != nil {
		return err
	}
	if !crypto.MLDSA87Verify(rootPublic, []byte(preImage), sig) {
		return errors.New("root signature does not verify")
	}
	return nil
}

// IdentityKey returns the node's raw ML-DSA-65 public key.
func IdentityKey(cert map[string]any) ([]byte, error) {
	idk, _ := cert["idk"].(string)
	return base64.StdEncoding.DecodeString(idk)
}

func asInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}
