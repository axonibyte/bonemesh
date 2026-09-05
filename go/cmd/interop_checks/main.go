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

	"github.com/axonibyte/bonemesh/gonode/frame"
	"github.com/axonibyte/bonemesh/gonode/message"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: interop_checks <framing|messages> <corpus.json>")
		os.Exit(2)
	}
	doc := decode(os.Args[2])
	var fails int
	switch os.Args[1] {
	case "framing":
		fails = checkFraming(doc)
	case "messages":
		fails = checkMessages(doc)
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
