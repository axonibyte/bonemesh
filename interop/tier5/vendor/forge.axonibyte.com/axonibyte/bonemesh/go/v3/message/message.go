// Package message implements BoneMesh v3 message schema validation (protocol.md
// §4) and inner-message builders. The validator mirrors the other
// implementations reason-for-reason (shared corpus: spec/corpus/messages.json).
package message

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
)

// DefaultTTL is the default hop limit for application data.
const DefaultTTL = 16

// Validate checks a message against a named schema. Returns "" if valid, else a
// reason tag. Schemas: bmx1, envelope, data, ack.
func Validate(schema string, f map[string]any) string {
	switch schema {
	case "bmx1":
		return validateBMX1(f)
	case "envelope":
		return validateEnvelope(f)
	case "data":
		return validateData(f)
	case "ack":
		return validateAck(f)
	default:
		return "unknown-schema"
	}
}

func validateBMX1(f map[string]any) string {
	if s, _ := f["t"].(string); s != "bmx1" {
		return "type"
	}
	if v, ok := asInt(f["v"]); !ok || v != 3 {
		return "version"
	}
	if s, ok := f["mesh"].(string); !ok || s == "" {
		return "empty-mesh"
	}
	for _, k := range []string{"e", "k", "n"} {
		v, ok := f[k]
		if !ok {
			return "missing-field"
		}
		if r := base64Reason(v); r != "" {
			return r
		}
	}
	return ""
}

func validateEnvelope(f map[string]any) string {
	seq, ok := asInt(f["seq"])
	if !ok {
		return "missing-field"
	}
	if seq < 0 {
		return "seq-range"
	}
	if _, ok := f["ct"]; !ok {
		return "missing-field"
	}
	return base64Reason(f["ct"])
}

func validateData(f map[string]any) string {
	if s, _ := f["type"].(string); s != "data" {
		return "type"
	}
	if r := midReason(f["mid"]); r != "" {
		return r
	}
	if _, ok := f["to"].(string); !ok {
		return "missing-field"
	}
	if _, ok := f["from"].(string); !ok {
		return "missing-field"
	}
	ttl, ok := asInt(f["ttl"])
	if !ok {
		return "missing-field"
	}
	if ttl < 1 || ttl > 255 {
		return "ttl-range"
	}
	if _, ok := f["payload"]; !ok {
		return "missing-field"
	}
	return ""
}

func validateAck(f map[string]any) string {
	if s, _ := f["type"].(string); s != "ack" {
		return "type"
	}
	return midReason(f["mid"])
}

func asInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}

func base64Reason(v any) string {
	s, ok := v.(string)
	if !ok {
		return "not-base64"
	}
	if _, err := base64.StdEncoding.DecodeString(s); err != nil {
		return "not-base64"
	}
	return ""
}

func midReason(v any) string {
	s, ok := v.(string)
	if !ok || len(s) != 32 {
		return "mid-format"
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return "mid-format"
		}
	}
	return ""
}

// NewMID returns a fresh 128-bit message id as 32 lowercase-hex characters.
func NewMID() string {
	var id [16]byte
	rand.Read(id[:])
	return hex.EncodeToString(id[:])
}

// Data builds an application data message.
func Data(mid, from, to string, ttl int, payload any) map[string]any {
	return map[string]any{"type": "data", "mid": mid, "from": from, "to": to, "ttl": ttl, "payload": payload}
}

// Ack builds an acknowledgement.
func Ack(mid string) map[string]any {
	return map[string]any{"type": "ack", "mid": mid}
}

// Echo builds an echo response to a probe.
func Echo(token int64) map[string]any {
	return map[string]any{"type": "echo", "token": token}
}
