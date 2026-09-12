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
	case "bmx2":
		return validateBMX2(frame)
	case "bmx3":
		return validateBMX3(frame)
	case "disco":
		return validateDisco(frame)
	case "probe":
		return validateTokenCarrier(frame, "probe")
	case "echo":
		return validateTokenCarrier(frame, "echo")
	case "rekey":
		return validateRekey(frame)
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

// Handshake messages 2 and 3 (security.md §4). Both carry one sealed "auth"
// member rather than separate cert and sig. This package is an independent reading
// of the spec, so the rules are written out here rather than shared with any
// implementation -- a check that imports the thing it checks agrees with itself.
func validateBMX2(f map[string]any) string {
	if s, _ := f["t"].(string); s != "bmx2" {
		return "type"
	}
	return requireB64(f, "e", "ct", "auth")
}

func validateBMX3(f map[string]any) string {
	if s, _ := f["t"].(string); s != "bmx3" {
		return "type"
	}
	return requireB64(f, "auth")
}

// Route advertisement (protocol.md §4.2, §6). An empty advertisement is {}.
func validateDisco(f map[string]any) string {
	if s, _ := f["type"].(string); s != "disco" {
		return "type"
	}
	raw, has := f["routes"]
	if !has {
		return "missing-field"
	}
	routes, ok := raw.(map[string]any)
	if !ok {
		return "routes-format"
	}
	for _, v := range routes {
		cost, ok := asInt(v)
		if !ok || cost < 0 {
			return "routes-format"
		}
	}
	return ""
}

// Latency measurement pair (§4.2, §5). The token is opaque to the responder,
// which echoes it back unchanged, so only its type is constrained.
func validateTokenCarrier(f map[string]any, want string) string {
	if s, _ := f["type"].(string); s != want {
		return "type"
	}
	if _, has := f["token"]; !has {
		return "missing-field"
	}
	if _, ok := asInt(f["token"]); !ok {
		return "token-format"
	}
	return ""
}

// Tunneled BMX rekey (§4.2, security.md §6). Phases 1-3 carry the BMX bytes in
// "body"; phase 4 carries no BMX message and must omit it.
func validateRekey(f map[string]any) string {
	if s, _ := f["type"].(string); s != "rekey" {
		return "type"
	}
	if r := checkMID(f["mid"]); r != "" {
		return r
	}
	if _, has := f["phase"]; !has {
		return "missing-field"
	}
	phase, ok := asInt(f["phase"])
	if !ok || phase < 1 || phase > 4 {
		return "phase-range"
	}
	_, hasBody := f["body"]
	if phase == 4 {
		if hasBody {
			return "body-or-phase"
		}
		return ""
	}
	if !hasBody {
		return "body-or-phase"
	}
	return checkBase64(f["body"])
}

// Every named member must be present and Base64.
func requireB64(f map[string]any, keys ...string) string {
	for _, k := range keys {
		if _, has := f[k]; !has {
			return "missing-field"
		}
		if r := checkBase64(f[k]); r != "" {
			return r
		}
	}
	return ""
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
	return checkChunking(f)
}

// MaxChunks is protocol.md §0's chunk-count ceiling, deliberately duplicated here
// rather than imported from an implementation. This package is a second, independent
// reading of the spec -- the whole point of a neutral conformance validator -- and a
// check that shares its constant with the thing it checks agrees with itself no
// matter what either one says.
const MaxChunks = 1024

// checkChunking validates the splitting half of the data schema (protocol.md §6.1):
// the shape of "chunk", its bounds, and the rule that exactly one of "payload" and
// "seg" is present.
//
// The exclusion is the load-bearing part. It is what stops a node that does not
// reassemble from handing a fragment to the application as though it were a whole
// message -- the silent corruption D11 described.
//
// Carrying neither stays "missing-field" rather than becoming a splitting error: it
// is an absent field and the corpus has pinned that reason since 3.0.0.
func checkChunking(f map[string]any) string {
	n := int64(1)
	if raw, has := f["chunk"]; has {
		chunk, ok := raw.(map[string]any)
		if !ok {
			return "chunk-format"
		}
		i, iOK := asInt(chunk["i"])
		n, ok = asInt(chunk["n"])
		if !ok || !iOK {
			return "chunk-format"
		}
		if n < 1 || n > MaxChunks {
			return "chunk-range"
		}
		if i < 0 || i >= n {
			return "chunk-range"
		}
	}
	segRaw, hasSeg := f["seg"]
	_, hasPayload := f["payload"]
	if !hasPayload && !hasSeg {
		return "missing-field"
	}
	if n == 1 && hasSeg {
		return "payload-or-seg" // a whole message carries its payload
	}
	if n > 1 && hasPayload {
		return "payload-or-seg" // a segment does not
	}
	if hasSeg {
		if _, ok := segRaw.(string); !ok {
			return "seg-format"
		}
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
