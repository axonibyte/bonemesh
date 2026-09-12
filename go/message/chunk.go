// Splitting and reassembly of oversized application payloads (protocol.md §6.1).
//
// A payload too large for one transport frame is serialized, its UTF-8 bytes cut
// into segments of at most MaxSegmentBytes on character boundaries, and each
// segment sent as a data message sharing one message id, carrying chunk {i, n}
// and a top-level "seg" string and NO "payload". A payload that fits travels
// whole, with "payload" and no "seg".
//
// Segments are text, not Base64: §0's Base64 rule covers binary fields, a slice
// of JSON text is already UTF-8, and a JSON string carries it directly, so a
// split message stays readable through the key-log inspector (decisions #3, #5,
// #25). Cutting on a byte budget rather than a character count is what keeps the
// split identical across the seven implementations, because UTF-8 has no
// surrogates.
package message

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Pinned by protocol.md §0 and enforced by spec/corpus/messages.json.
const (
	// MaxSegmentBytes is the most payload bytes one segment may carry.
	MaxSegmentBytes = 24000
	// MaxChunks is the most segments one application message may be split into.
	MaxChunks = 1024
	// MaxReassemblyBuffer is the most segment bytes buffered at once, summed
	// across every in-flight message.
	MaxReassemblyBuffer = 16777216
	// MaxConcurrentReassemblies is the most messages that may be mid-reassembly.
	MaxConcurrentReassemblies = 256
	// ReassemblyTimeoutMillis is how long a partially-filled message may sit.
	ReassemblyTimeoutMillis = 30000
)

// DataSegment builds one segment of a split application message. A segment
// carries "seg" and deliberately carries no "payload": the two are mutually
// exclusive, so a node that does not reassemble sees a data message with no
// payload and rejects it rather than handing a fragment to the application.
func DataSegment(mid, from, to string, ttl, i, n int, seg string) map[string]any {
	return map[string]any{
		"type": "data", "mid": mid, "from": from, "to": to, "ttl": ttl,
		"chunk": map[string]any{"i": i, "n": n},
		"seg":   seg,
	}
}

// Split returns the data messages carrying a payload: one whole message when it
// fits, else its segments in ascending order. An error means no conforming
// destination would reassemble it, so the caller is told locally rather than the
// mesh carrying a message that cannot arrive (§6.1, Bounds).
func Split(mid, from, to string, ttl int, payload any) ([]map[string]any, error) {
	src, err := marshalUnescaped(payload)
	if err != nil {
		return nil, err
	}
	if len(src) <= MaxSegmentBytes {
		return []map[string]any{Data(mid, from, to, ttl, payload)}, nil
	}
	if len(src) > MaxReassemblyBuffer {
		return nil, fmt.Errorf("payload of %d bytes exceeds the reassembly buffer maximum of %d",
			len(src), MaxReassemblyBuffer)
	}

	var segs []string
	for pos := 0; pos < len(src); {
		end := charBoundary(src, pos, min(pos+MaxSegmentBytes, len(src)))
		segs = append(segs, string(src[pos:end]))
		pos = end
	}
	if len(segs) > MaxChunks {
		return nil, fmt.Errorf("payload needs %d segments, over the maximum of %d", len(segs), MaxChunks)
	}

	out := make([]map[string]any, 0, len(segs))
	for i, seg := range segs {
		out = append(out, DataSegment(mid, from, to, ttl, i, len(segs), seg))
	}
	return out, nil
}

// marshalUnescaped serializes a payload the way the other six implementations do.
//
// encoding/json escapes <, > and & to \u003c, \u003e and \u0026 by default, and
// nothing else in the fleet does: measured on one payload, Go produced 35 bytes where
// Java, Rust, JS, PHP, Elixir and Python all produced 20. Both forms parse to the
// same string, so this was never a wire-compatibility fault -- but it put Go's cuts
// in different places for any payload containing one of those three characters, which
// would have made spec/corpus/chunk.json unpinnable for six of seven ports or forced
// the vectors to avoid the characters entirely.
func marshalUnescaped(payload any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return nil, err
	}
	// Encode appends a newline that Marshal does not.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// charBoundary walks a proposed cut back to the nearest character boundary at or
// before it, so a segment never ends mid-character and is itself valid UTF-8.
func charBoundary(src []byte, start, end int) int {
	if end >= len(src) {
		return end // the tail is always a boundary
	}
	e := end
	for e > start && src[e]&0xC0 == 0x80 { // 10xxxxxx is a continuation byte
		e--
	}
	// A UTF-8 character is at most 4 bytes and a segment is 24000, so e cannot
	// reach start from well-formed input; falling back keeps a malformed
	// serializer from producing a zero-length segment and looping forever.
	if e > start {
		return e
	}
	return end
}

// Reassembler rebuilds split payloads at the destination, the counterpart to
// Split. Offer each inbound data message; it returns the payload once the final
// segment of a message id arrives.
//
// Every §0 bound is enforced BEFORE any allocation keyed on a number the peer
// chose. That ordering is the point: the Java reference sized its buffer on the
// peer's n and validated afterwards, so one frame claiming two billion segments
// exhausted the heap -- defect D7 reintroduced by the feature meant to fix it.
//
// Three bounds, none redundant: the byte budget caps one large message, the
// in-flight count caps a flood of distinct ids each carrying an empty segment
// (which costs nothing against a byte budget and still costs memory), and the
// timeout stops an abandoned message pinning memory for the session's life.
//
// Not safe for concurrent use; a Node serializes offers through its own lock.
type Reassembler struct {
	partials map[string]*partial
	order    []string // insertion order, so the timeout sweep walks oldest-first
	buffered int
}

type partial struct {
	segments []string
	seen     []bool
	received int
	bytes    int
	started  int64
}

// NewReassembler returns an empty reassembler.
func NewReassembler() *Reassembler {
	return &Reassembler{partials: map[string]*partial{}}
}

// Offer feeds one inbound data message. It returns the reassembled payload and
// true when a message completes, else nil and false. nowMillis is passed in
// rather than read so the timeout is testable without sleeping.
func (r *Reassembler) Offer(msg map[string]any, nowMillis int64) (any, bool) {
	r.sweep(nowMillis)

	chunkRaw, hasChunk := msg["chunk"]
	n := 1
	var chunk map[string]any
	if hasChunk {
		var ok bool
		chunk, ok = chunkRaw.(map[string]any)
		if !ok {
			return nil, false // chunk is not an object
		}
		if n, ok = chunkInt(chunk["n"]); !ok {
			return nil, false
		}
	}
	if !hasChunk || n == 1 {
		// A whole message carries payload and no seg. One claiming n == 1 while
		// carrying seg instead is malformed, not a one-segment split -- and so is
		// one carrying both, which is why the seg check is here and not only in the
		// schema. Found by mutation: without it a message with payload AND seg was
		// delivered, since the payload lookup alone cannot see the contradiction.
		if _, hasSeg := msg["seg"]; hasSeg {
			return nil, false
		}
		payload, ok := msg["payload"]
		if !ok {
			return nil, false
		}
		return payload, true
	}

	// Bounds first, allocation second.
	i, ok := chunkInt(chunk["i"])
	if !ok || n < 1 || n > MaxChunks || i < 0 || i >= n {
		return nil, false
	}
	seg, ok := msg["seg"].(string)
	if !ok {
		return nil, false // a segment without its slice
	}
	mid, ok := msg["mid"].(string)
	if !ok {
		return nil, false
	}

	p := r.partials[mid]
	if p == nil {
		if len(r.partials) >= MaxConcurrentReassemblies {
			return nil, false
		}
		p = &partial{segments: make([]string, n), seen: make([]bool, n), started: nowMillis}
		r.partials[mid] = p
		r.order = append(r.order, mid)
	} else if len(p.segments) != n {
		r.discard(mid, p) // the peer changed n mid-message
		return nil, false
	}

	if !p.seen[i] {
		if r.buffered+len(seg) > MaxReassemblyBuffer {
			r.discard(mid, p)
			return nil, false
		}
		p.segments[i] = seg
		p.seen[i] = true
		p.received++
		p.bytes += len(seg)
		r.buffered += len(seg)
	}
	if p.received != n {
		return nil, false
	}

	r.discard(mid, p)
	var payload any
	dec := json.NewDecoder(strings.NewReader(strings.Join(p.segments, "")))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		return nil, false // the segments did not rebuild valid JSON
	}
	return payload, true
}

// InFlight is the number of messages currently mid-reassembly. Exported for the
// tests that assert the bounds release memory rather than merely refusing to add
// to it -- a reassembler that rejects a segment but keeps its partial forever is
// still a leak, and the refusal alone cannot show that.
func (r *Reassembler) InFlight() int { return len(r.partials) }

// Buffered is the segment bytes held across every in-flight message.
func (r *Reassembler) Buffered() int { return r.buffered }

func (r *Reassembler) discard(mid string, p *partial) {
	delete(r.partials, mid)
	r.buffered -= p.bytes
	for k, id := range r.order {
		if id == mid {
			r.order = append(r.order[:k], r.order[k+1:]...)
			break
		}
	}
}

func (r *Reassembler) sweep(nowMillis int64) {
	for len(r.order) > 0 {
		mid := r.order[0]
		p := r.partials[mid]
		if p == nil {
			r.order = r.order[1:]
			continue
		}
		if nowMillis-p.started < ReassemblyTimeoutMillis {
			break // insertion-ordered: the rest are younger
		}
		delete(r.partials, mid)
		r.buffered -= p.bytes
		r.order = r.order[1:]
	}
}

// chunkInt accepts the integer forms a chunk index can legitimately arrive as --
// json.Number from the wire, int from a locally-built message -- and rejects
// everything else, including a float with a fractional part.
func chunkInt(v any) (int, bool) {
	switch t := v.(type) {
	case json.Number:
		i, err := t.Int64()
		return int(i), err == nil
	case int:
		return t, true
	case int64:
		return int(t), true
	case float64:
		if t != float64(int64(t)) {
			return 0, false
		}
		return int(t), true
	}
	return 0, false
}
