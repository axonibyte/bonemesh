// Splitting and reassembly tests (protocol.md §6.1).
//
// Two groups. The first pins the format: a small payload travels whole, a large
// one splits and rebuilds byte-identically, segments are text rather than Base64,
// and cuts land on character boundaries even when every character is multi-byte.
//
// The second pins the bounds, which is the half that had no coverage anywhere
// before 3.3.0 and where the defect was. Each asserts that a hostile message is
// refused AND that refusing it released whatever it claimed: a reassembler that
// rejects a segment but keeps its partial forever is still a leak, and the
// refusal alone cannot show that.
package message

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const testMID = "0123456789abcdef0123456789abcdef"

// wire round-trips a built message through JSON so its numbers arrive as
// json.Number, exactly as they would off a transport frame.
func wire(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]any
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

func seg(t *testing.T, mid string, i, n int, s string) map[string]any {
	return wire(t, DataSegment(mid, "a", "b", 16, i, n, s))
}

func blob(nchars int) string {
	var sb strings.Builder
	for i := 0; i < nchars; i++ {
		sb.WriteByte(byte('a' + i%26))
	}
	return sb.String()
}

// ---- format ----

func TestSmallPayloadTravelsWhole(t *testing.T) {
	payload := map[string]any{"line": "hello"}
	msgs, err := Split(testMID, "a", "b", 16, payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("want 1 message, got %d", len(msgs))
	}
	if _, has := msgs[0]["chunk"]; has {
		t.Error("a whole message must not carry chunk")
	}
	if _, has := msgs[0]["seg"]; has {
		t.Error("a whole message must not carry seg")
	}
}

func TestLargePayloadSplitsAndReassembles(t *testing.T) {
	payload := map[string]any{"blob": blob(120000)}
	msgs, err := Split(testMID, "a", "b", 16, payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) < 2 {
		t.Fatalf("large payload was not split (%d messages)", len(msgs))
	}
	for i, m := range msgs {
		if r := Validate("data", wire(t, m)); r != "" {
			t.Errorf("segment %d failed the data schema: %s", i, r)
		}
		if _, has := m["payload"]; has {
			t.Errorf("segment %d carries a payload", i)
		}
		s, ok := m["seg"].(string)
		if !ok {
			t.Fatalf("segment %d has no seg string", i)
		}
		if len(s) > MaxSegmentBytes {
			t.Errorf("segment %d is %d bytes, over the pinned maximum", i, len(s))
		}
	}

	r := NewReassembler()
	for i := 0; i < len(msgs)-1; i++ {
		if _, done := r.Offer(wire(t, msgs[i]), 0); done {
			t.Fatalf("completed early at segment %d", i)
		}
	}
	got, done := r.Offer(wire(t, msgs[len(msgs)-1]), 0)
	if !done {
		t.Fatal("never completed")
	}
	want, _ := json.Marshal(payload)
	have, _ := json.Marshal(got)
	if string(want) != string(have) {
		t.Error("reassembled payload differs from the original")
	}
	if r.InFlight() != 0 || r.Buffered() != 0 {
		t.Errorf("a completed message stayed buffered: %d in flight, %d bytes", r.InFlight(), r.Buffered())
	}
}

func TestSegmentsAreTextNotBase64(t *testing.T) {
	// decision #25: a segment is a slice of the payload's JSON text, so it stays
	// readable through the key-log inspector. Concatenation must reproduce the
	// serialized payload with no decode step.
	payload := map[string]any{"blob": blob(60000)}
	msgs, err := Split(testMID, "a", "b", 16, payload)
	if err != nil {
		t.Fatal(err)
	}
	var joined strings.Builder
	for _, m := range msgs {
		joined.WriteString(m["seg"].(string))
	}
	want, _ := json.Marshal(payload)
	if joined.String() != string(want) {
		t.Error("segments did not concatenate back to the payload's JSON text")
	}
	if !strings.HasPrefix(msgs[0]["seg"].(string), "{") {
		t.Error("the first segment should open the payload's JSON, not a Base64 blob")
	}
}

func TestCutsLandOnCharacterBoundaries(t *testing.T) {
	// Every character is 3 UTF-8 bytes, so 24000 divides unevenly and a naive
	// byte cut would split one.
	payload := map[string]any{"cjk": strings.Repeat("日", 40000)}
	msgs, err := Split(testMID, "a", "b", 16, payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) < 2 {
		t.Fatal("payload was not split")
	}
	for i, m := range msgs {
		s := m["seg"].(string)
		if !utf8Valid(s) {
			t.Errorf("segment %d is not valid UTF-8, so a cut split a character", i)
		}
		if len(s) > MaxSegmentBytes {
			t.Errorf("segment %d is over the pinned maximum", i)
		}
	}
	r := NewReassembler()
	var done bool
	var got any
	for _, m := range msgs {
		got, done = r.Offer(wire(t, m), 0)
	}
	if !done {
		t.Fatal("never completed")
	}
	want, _ := json.Marshal(payload)
	have, _ := json.Marshal(got)
	if string(want) != string(have) {
		t.Error("multi-byte payload did not round-trip")
	}
}

func utf8Valid(s string) bool {
	for _, r := range s {
		if r == '�' {
			return false
		}
	}
	return true
}

func TestOutOfOrderSegmentsStillReassemble(t *testing.T) {
	payload := map[string]any{"blob": blob(120000)}
	msgs, _ := Split(testMID, "a", "b", 16, payload)
	r := NewReassembler()
	var got any
	var done bool
	for i := len(msgs) - 1; i >= 0; i-- {
		got, done = r.Offer(wire(t, msgs[i]), 0)
	}
	if !done {
		t.Fatal("reverse order never completed")
	}
	want, _ := json.Marshal(payload)
	have, _ := json.Marshal(got)
	if string(want) != string(have) {
		t.Error("out-of-order reassembly produced a different payload")
	}
}

// ---- bounds ----

func TestAbsurdChunkCountIsRefusedBeforeAllocating(t *testing.T) {
	// The Java reference sized its buffer on the peer's n before validating it,
	// so one frame claiming two billion segments exhausted the heap. Both oracles
	// matter: the offer is refused, AND nothing was retained, which is what shows
	// no allocation happened.
	r := NewReassembler()
	for _, n := range []int{1<<31 - 1, 2000000000, 1000000, MaxChunks + 1} {
		if _, done := r.Offer(seg(t, testMID, 0, n, "x"), 0); done {
			t.Errorf("accepted n=%d", n)
		}
		if r.InFlight() != 0 || r.Buffered() != 0 {
			t.Fatalf("n=%d was buffered anyway (%d in flight)", n, r.InFlight())
		}
	}
	// The boundary itself is legal, so this is a bound and not a blanket ban.
	r.Offer(seg(t, testMID, 0, MaxChunks, "x"), 0)
	if r.InFlight() != 1 {
		t.Error("the maximum legal chunk count was refused")
	}
}

func TestMalformedChunkMetadataIsRefused(t *testing.T) {
	r := NewReassembler()
	bad := []map[string]any{}
	m := seg(t, testMID, 0, 3, "x")
	m["chunk"] = "not-an-object"
	bad = append(bad, m)
	m = seg(t, testMID, 0, 3, "x")
	m["chunk"] = map[string]any{"i": "zero", "n": json.Number("3")}
	bad = append(bad, m)
	m = seg(t, testMID, 0, 3, "x")
	m["chunk"] = map[string]any{"i": json.Number("0")} // no n
	bad = append(bad, m)
	bad = append(bad, seg(t, testMID, 3, 3, "x"))  // i == n
	bad = append(bad, seg(t, testMID, -1, 3, "x")) // i < 0
	bad = append(bad, seg(t, testMID, 0, 0, "x"))  // n == 0
	for k, msg := range bad {
		if _, done := r.Offer(msg, 0); done {
			t.Errorf("case %d: accepted malformed chunk", k)
		}
		if r.InFlight() != 0 {
			t.Fatalf("case %d: malformed chunk was buffered", k)
		}
	}
}

func TestSegmentWithoutItsSliceIsRefused(t *testing.T) {
	r := NewReassembler()
	m := seg(t, testMID, 0, 3, "x")
	delete(m, "seg")
	if _, done := r.Offer(m, 0); done {
		t.Error("accepted a segment with no slice")
	}
	if r.InFlight() != 0 {
		t.Error("it was buffered anyway")
	}
}

func TestWholeMessageClaimingToBeASegmentIsNotDelivered(t *testing.T) {
	// n == 1 with seg instead of payload is malformed, not a one-segment split.
	r := NewReassembler()
	if _, done := r.Offer(seg(t, testMID, 0, 1, `{"a":1}`), 0); done {
		t.Error("delivered a fragment as a whole payload")
	}
	if got := Validate("data", seg(t, testMID, 0, 1, `{"a":1}`)); got != "payload-or-seg" {
		t.Errorf("schema verdict = %q, want payload-or-seg", got)
	}
}

func TestMessageCarryingBothPayloadAndSegmentIsNotDelivered(t *testing.T) {
	// Found by mutation. The whole-message path looked up payload and returned it,
	// so a message contradicting itself -- payload AND seg -- was delivered. The
	// schema rejects it, but the schema is not on the wire path (decision #27), so
	// the reassembler has to refuse it too.
	r := NewReassembler()
	both := wire(t, Data(testMID, "a", "b", 16, map[string]any{"x": 1}))
	both["seg"] = "{"
	if _, done := r.Offer(both, 0); done {
		t.Error("a self-contradicting message was delivered")
	}
	withChunk := seg(t, testMID, 0, 1, "{")
	withChunk["payload"] = map[string]any{"x": 1}
	if _, done := r.Offer(withChunk, 0); done {
		t.Error("a self-contradicting n==1 message was delivered")
	}
}

func TestNonObjectChunkIsRefusedEvenWithAPayload(t *testing.T) {
	// The distinguishing input: a garbage chunk on a message that DOES carry a
	// payload. Java conflated "chunk absent" with "chunk unparseable" and delivered
	// it; nothing tested the case, which is how that survived.
	r := NewReassembler()
	for _, garbage := range []any{"1/3", json.Number("7"), []any{}} {
		m := wire(t, Data(testMID, "a", "b", 16, map[string]any{"x": 1}))
		m["chunk"] = garbage
		if _, done := r.Offer(m, 0); done {
			t.Errorf("delivered a message whose chunk was %T", garbage)
		}
		if Validate("data", m) == "" {
			t.Errorf("the schema accepted a chunk of %T", garbage)
		}
	}
}

func TestConcurrentReassembliesAreBounded(t *testing.T) {
	r := NewReassembler()
	for k := 0; k < MaxConcurrentReassemblies; k++ {
		r.Offer(seg(t, fmt.Sprintf("%032x", k), 0, 4, "x"), 0)
	}
	if r.InFlight() != MaxConcurrentReassemblies {
		t.Fatalf("in flight = %d, want %d", r.InFlight(), MaxConcurrentReassemblies)
	}
	r.Offer(seg(t, fmt.Sprintf("%032x", 9999), 0, 4, "x"), 0)
	if r.InFlight() != MaxConcurrentReassemblies {
		t.Errorf("the bound was exceeded: %d in flight", r.InFlight())
	}
}

func TestBufferedBytesAreBounded(t *testing.T) {
	// The in-flight bound (256) is reached long before 16 MiB of segments can be
	// spread across separate message ids, so the byte budget is only reachable
	// inside one message: 1024 segments of 24000 bytes is 24.5 MB, over the
	// ceiling. That is the case to drive.
	r := NewReassembler()
	full := strings.Repeat("y", MaxSegmentBytes)
	accepted := 0
	for i := 0; i < MaxChunks; i++ {
		r.Offer(seg(t, testMID, i, MaxChunks, full), 0)
		if r.InFlight() == 0 {
			break // abandoned: the budget refused it
		}
		accepted++
		if r.Buffered() > MaxReassemblyBuffer {
			t.Fatalf("the buffer maximum was exceeded at segment %d", i)
		}
	}
	if want := MaxReassemblyBuffer / MaxSegmentBytes; accepted != want {
		t.Errorf("accepted %d segments, want %d before abandoning", accepted, want)
	}
	if r.InFlight() != 0 || r.Buffered() != 0 {
		t.Errorf("abandoning did not return the bytes: %d in flight, %d bytes", r.InFlight(), r.Buffered())
	}
}

func TestStalePartialsAreSwept(t *testing.T) {
	r := NewReassembler()
	r.Offer(seg(t, testMID, 0, 3, "x"), 1000)
	if r.InFlight() != 1 {
		t.Fatal("the first segment was not buffered")
	}
	// Just inside the timeout: still held.
	r.Offer(seg(t, testMID, 1, 3, "y"), 1000+ReassemblyTimeoutMillis-1)
	if r.InFlight() != 1 {
		t.Error("swept too early")
	}
	// At the timeout: gone, and its bytes back.
	r.Offer(seg(t, strings.Repeat("1", 32), 0, 3, "z"), 1000+ReassemblyTimeoutMillis)
	if r.InFlight() != 1 {
		t.Errorf("the stale partial was not swept: %d in flight", r.InFlight())
	}
	if r.Buffered() != 1 {
		t.Errorf("swept bytes were not returned: %d buffered", r.Buffered())
	}
}

func TestOversizedPayloadFailsAtTheOrigin(t *testing.T) {
	// §6.1: an origin whose payload no conforming destination would reassemble is
	// told locally rather than emitting it.
	if _, err := Split(testMID, "a", "b", 16, map[string]any{"blob": blob(MaxReassemblyBuffer + 1)}); err == nil {
		t.Error("an oversized payload was accepted")
	}
}
