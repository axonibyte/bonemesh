// Package canon implements the BoneMesh restricted-JCS certificate
// canonicalization (security.md §11.1): the exact byte string the mesh root
// signs. Certificates contain only JSON strings and non-negative integers, so
// this is a small, deterministic subset of RFC 8785 rather than the full scheme.
package canon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf16"
)

// Canonicalize returns the canonical UTF-8 bytes for a certificate object,
// after removing any "sig" member. The input is the JSON value as decoded with
// json.Decoder.UseNumber, so integers survive exactly. It errors on any value
// that a certificate may not contain (float, bool, null, array), which keeps a
// malformed certificate from being silently signed.
func Canonicalize(cert map[string]any) ([]byte, error) {
	filtered := make(map[string]any, len(cert))
	for k, v := range cert {
		if k == "sig" {
			continue
		}
		filtered[k] = v
	}
	var b bytes.Buffer
	if err := encodeObject(&b, filtered); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func encodeObject(b *bytes.Buffer, m map[string]any) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		encodeString(b, k)
		b.WriteByte(':')
		if err := encodeValue(b, m[k]); err != nil {
			return err
		}
	}
	b.WriteByte('}')
	return nil
}

func encodeValue(b *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case string:
		encodeString(b, t)
		return nil
	case json.Number:
		return encodeInteger(b, t)
	case map[string]any:
		return encodeObject(b, t)
	default:
		return fmt.Errorf("canon: value type %T is not permitted in a certificate", v)
	}
}

func encodeInteger(b *bytes.Buffer, n json.Number) error {
	i, err := strconv.ParseInt(n.String(), 10, 64)
	if err != nil {
		return fmt.Errorf("canon: %q is not an integer: %w", n.String(), err)
	}
	if i < 0 {
		return fmt.Errorf("canon: certificate integers must be non-negative, got %d", i)
	}
	b.WriteString(strconv.FormatInt(i, 10))
	return nil
}

// encodeString emits a JSON string with minimal escaping (security.md §11.1
// step 4): only " \ and controls < 0x20 are escaped; non-ASCII stays raw UTF-8.
func encodeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// lessUTF16 compares two strings by their UTF-16 code-unit sequences, the
// ordering RFC 8785 (and thus security.md §11.1 step 2) mandates.
func lessUTF16(a, c string) bool {
	ua, uc := utf16.Encode([]rune(a)), utf16.Encode([]rune(c))
	for i := 0; i < len(ua) && i < len(uc); i++ {
		if ua[i] != uc[i] {
			return ua[i] < uc[i]
		}
	}
	return len(ua) < len(uc)
}
