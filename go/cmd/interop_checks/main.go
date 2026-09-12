// Command interop_checks runs corpus-driven checks for the Go port: the
// `framing` subcommand confirms the Go frame classifier reaches the same
// verdicts as the Java, Rust, and Elixir implementations over
// spec/corpus/framing.json, and `messages` does the same for the message
// validator over spec/corpus/messages.json. Invoked by interop/check-framing-go.sh
// and interop/check-messages-go.sh.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/axonibyte/bonemesh/gonode/frame"
	"github.com/axonibyte/bonemesh/gonode/message"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: interop_checks <framing|messages|chunk> <corpus.json>")
		os.Exit(2)
	}
	doc := decode(os.Args[2])
	var fails int
	switch os.Args[1] {
	case "framing":
		fails = checkFraming(doc)
	case "messages":
		fails = checkMessages(doc)
	case "chunk":
		fails = checkChunk(doc)
	default:
		fmt.Fprintln(os.Stderr, "unknown mode:", os.Args[1])
		os.Exit(2)
	}
	if fails > 0 {
		os.Exit(1)
	}
}

func checkFraming(doc map[string]any) int {
	cases, _ := doc["cases"].([]any)
	fails := 0
	for _, raw := range cases {
		c := raw.(map[string]any)
		name, _ := c["name"].(string)
		cap := frame.TransportCap
		if c["kind"] == "handshake" {
			cap = frame.HandshakeCap
		}
		b64, _ := c["bytes_b64"].(string)
		data, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			report(name, false, &fails)
			continue
		}
		_, reason := frame.Classify(data, cap)
		var ok bool
		if c["expect"] == "accept" {
			ok = reason == ""
		} else {
			want, _ := c["reason"].(string)
			ok = reason == want
		}
		report(name, ok, &fails)
	}
	fmt.Printf("framing: %d cases checked\n", len(cases))
	return fails
}

func checkMessages(doc map[string]any) int {
	cases, _ := doc["cases"].([]any)
	fails := 0
	for _, raw := range cases {
		c := raw.(map[string]any)
		name, _ := c["name"].(string)
		schema, _ := c["schema"].(string)
		f, _ := c["frame"].(map[string]any)
		reason := message.Validate(schema, f)
		var ok bool
		if c["expect"] == "valid" {
			ok = reason == ""
		} else {
			want, _ := c["reason"].(string)
			ok = reason == want
		}
		report(name, ok, &fails)
	}
	fmt.Printf("messages: %d cases checked\n", len(cases))
	return fails
}

func report(name string, ok bool, fails *int) {
	if ok {
		fmt.Printf("PASS %s\n", name)
	} else {
		fmt.Printf("FAIL %s\n", name)
		*fails++
	}
}

// checkChunk verifies splitting against the shared corpus (spec/corpus/chunk.json).
//
// Two things, and the second is the one nothing else can see. First the pinned §0
// constants must match this implementation's -- including the three (chunk count,
// in-flight count, timeout) that specsrc deliberately does not check, because a
// substring search for 1024, 256 or 30000 is satisfied by any buffer size already in
// the tree. Second, the segments this implementation produces must land on exactly
// the byte boundaries the corpus pins, which is how all seven are shown to cut in the
// SAME places rather than merely to cut.
func checkChunk(doc map[string]any) int {
	var fails int
	mine := map[string]int{
		"max_segment_bytes":           message.MaxSegmentBytes,
		"max_chunks":                  message.MaxChunks,
		"max_reassembly_buffer":       message.MaxReassemblyBuffer,
		"max_concurrent_reassemblies": message.MaxConcurrentReassemblies,
		"reassembly_timeout_millis":   message.ReassemblyTimeoutMillis,
	}
	pinned, _ := doc["constants"].(map[string]any)
	if len(pinned) == 0 {
		fmt.Fprintln(os.Stderr, "corpus declares no chunk constants")
		return 1
	}
	for name, raw := range pinned {
		want, _ := raw.(json.Number).Int64()
		got, known := mine[name]
		ok := known && int64(got) == want
		if ok {
			fmt.Printf("PASS constant %s\n", name)
		} else {
			fmt.Printf("FAIL constant %s  (have %d, corpus pins %d)\n", name, got, want)
			fails++
		}
	}

	cases, _ := doc["split_cases"].([]any)
	if len(cases) == 0 {
		fmt.Fprintln(os.Stderr, "corpus has no split cases")
		return 1
	}
	mid, _ := doc["mid"].(string)
	for _, raw := range cases {
		c, _ := raw.(map[string]any)
		name, _ := c["name"].(string)
		key, _ := c["key"].(string)
		unit, _ := c["unit"].(string)
		times, _ := c["times"].(json.Number).Int64()
		payload := map[string]any{key: strings.Repeat(unit, int(times))}

		msgs, err := message.Split(mid, "a", "b", 16, payload)
		if err != nil {
			fmt.Printf("FAIL %s  (split: %v)\n", name, err)
			fails++
			continue
		}
		_, hasPayload := msgs[0]["payload"]
		whole := len(msgs) == 1 && hasPayload
		lengths := []int{}
		if !whole {
			for _, m := range msgs {
				lengths = append(lengths, len(m["seg"].(string)))
			}
		}
		wantWhole, _ := c["expect_whole"].(bool)
		wantLens := []int{}
		for _, l := range c["segment_byte_lengths"].([]any) {
			v, _ := l.(json.Number).Int64()
			wantLens = append(wantLens, int(v))
		}
		ok := whole == wantWhole && fmt.Sprint(lengths) == fmt.Sprint(wantLens)
		detail := ""
		if !ok {
			detail = fmt.Sprintf("  (whole=%v want %v; lengths=%v want %v)", whole, wantWhole, lengths, wantLens)
		}
		// A round-trip as the second oracle: matching lengths would not catch
		// segments that are the right size and the wrong bytes.
		if ok && !whole {
			var joined strings.Builder
			for _, m := range msgs {
				joined.WriteString(m["seg"].(string))
			}
			var rebuilt map[string]any
			if json.Unmarshal([]byte(joined.String()), &rebuilt) != nil ||
				rebuilt[key] != payload[key] {
				ok, detail = false, "  (segments did not rebuild the payload)"
			}
		}
		if ok {
			fmt.Printf("PASS %s\n", name)
		} else {
			fmt.Printf("FAIL %s%s\n", name, detail)
			fails++
		}
	}
	if fails == 0 {
		fmt.Println("splitting agrees with every pinned constant and cut position")
	}
	return fails
}

func decode(path string) map[string]any {
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return m
}
