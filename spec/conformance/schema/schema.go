// Package schema validates BoneMesh v3 message objects against the pinned
// schemas (protocol.md §4, security.md §4). It reports the first violation as a
// short reason tag matching the conformance corpus.
package schema

import (
	"encoding/base64"
	"encoding/json"
)

// Validate checks frame against the named schema and returns "" if valid, or a
// reason tag. Recognized schemas: "bmx1", "envelope", "data", "ack", "nak",
// "bye".
func Validate(name string, frame map[string]any) string {
	switch name {
	case "bmx1":
		return validateBMX1(frame)
	case "envelope":
		return validateEnvelope(frame)
	case "data":
		return validateData(frame)
	case "ack":
		return validateAck(frame)
	case "nak":
		return validateNak(frame)
	case "bye":
		return validateBye(frame)
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
		if r := checkBase64(v); r != "" {
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
	v, ok := f["ct"]
	if !ok {
		return "missing-field"
	}
	return checkBase64(v)
}

func validateData(f map[string]any) string {
	if s, _ := f["type"].(string); s != "data" {
		return "type"
	}
	if r := checkMID(f["mid"]); r != "" {
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
	return checkMID(f["mid"])
}

// validateNak checks a NAK, which is routed back toward the origin like data
// (to/from/ttl) and additionally names the failing hop and a reason. The reason
// string is required but its value is not enum-checked — an unrecognized reason
// is accepted so a future reason value is not a wire break (protocol.md §8).
func validateNak(f map[string]any) string {
	if s, _ := f["type"].(string); s != "nak" {
		return "type"
	}
	if r := checkMID(f["mid"]); r != "" {
		return r
	}
	if s, ok := f["hop"].(string); !ok || s == "" {
		return "missing-field"
	}
	if s, ok := f["reason"].(string); !ok || s == "" {
		return "missing-field"
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
	return ""
}

// validateBye checks a graceful session-close control. It is link-local (not
// routed), so it carries only its type; an optional reason string is not
// validated further.
func validateBye(f map[string]any) string {
	if s, _ := f["type"].(string); s != "bye" {
		return "type"
	}
	return ""
}

// asInt accepts a json.Number that is an integer.
func asInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	if err != nil {
		return 0, false
	}
	return i, true
}

func checkBase64(v any) string {
	s, ok := v.(string)
	if !ok {
		return "not-base64"
	}
	if _, err := base64.StdEncoding.DecodeString(s); err != nil {
		return "not-base64"
	}
	return ""
}

// checkMID enforces a 32-char lowercase-hex message id (protocol.md §0).
func checkMID(v any) string {
	s, ok := v.(string)
	if !ok {
		return "mid-format"
	}
	if len(s) != 32 {
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
