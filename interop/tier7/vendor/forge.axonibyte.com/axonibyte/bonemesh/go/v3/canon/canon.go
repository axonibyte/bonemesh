// Package canon implements the BoneMesh restricted-JCS certificate
// canonicalization (security.md §11.1): the exact byte string the mesh root
// signs. Byte-for-byte identical to the Java, Elixir, and Rust implementations
// (and the Go conformance runner) over the shared corpus (spec/corpus/canon.json).
package canon

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Canonicalize returns the canonical UTF-8 bytes for a certificate object,
// after removing any "sig" member. The value must decode with UseNumber so
// integers survive exactly.
func Canonicalize(cert map[string]any) (string, error) {
	filtered := make(map[string]any, len(cert))
	for k, v := range cert {
		if k != "sig" {
			filtered[k] = v
		}
	}
	var b strings.Builder
	if err := encodeObject(&b, filtered); err != nil {
		return "", err
	}
	return b.String(), nil
}

func encodeObject(b *strings.Builder, m map[string]any) error {
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

func encodeValue(b *strings.Builder, v any) error {
	switch t := v.(type) {
	case string:
		encodeString(b, t)
		return nil
	case json.Number:
		i, err := strconv.ParseInt(t.String(), 10, 64)
		if err != nil {
			return fmt.Errorf("canon: %q is not an integer", t.String())
		}
		if i < 0 {
			return fmt.Errorf("canon: negative integer %d", i)
		}
		b.WriteString(strconv.FormatInt(i, 10))
		return nil
	case map[string]any:
		return encodeObject(b, t)
	default:
		return fmt.Errorf("canon: value type %T not permitted in a certificate", v)
	}
}

func encodeString(b *strings.Builder, s string) {
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

func lessUTF16(a, c string) bool {
	ua, uc := utf16.Encode([]rune(a)), utf16.Encode([]rune(c))
	for i := 0; i < len(ua) && i < len(uc); i++ {
		if ua[i] != uc[i] {
			return ua[i] < uc[i]
		}
	}
	return len(ua) < len(uc)
}
