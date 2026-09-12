// Command keylog_check reads the shared key-log vector (spec/corpus/keylog.json)
// and confirms this implementation can open a key-logged capture.
//
// security.md §8 pins one implementation-neutral key-log format precisely so a
// single inspector reads a log written by a node in any language. That claim needs
// agreement in BOTH directions: emitting lines your own reader accepts is not
// enough. This checks the reading half against a committed capture the Java
// reference produced. The writing half is covered by each port's own key-log tests
// and, live and cross-language, by interop tier 10.
//
// Invoked by interop/check-keylog-go.sh.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/axonibyte/bonemesh/gonode/transport"
)

var label = regexp.MustCompile(`^BMX3_(I2R|R2I)_TRAFFIC_(\d+)$`)

type vector struct {
	Keylog  []string `json:"keylog"`
	Capture []struct {
		Dir   string `json:"dir"`
		Frame struct {
			Ct  string `json:"ct"`
			Seq uint64 `json:"seq"`
		} `json:"frame"`
	} `json:"capture"`
	Expected []struct {
		Dir   string          `json:"dir"`
		Epoch int             `json:"epoch"`
		Seq   uint64          `json:"seq"`
		Inner json.RawMessage `json:"inner"`
	} `json:"expected"`
}

// parseKeylog maps "<dir>:<epoch>" to a key. '#' lines are comments; an unknown
// label shape is ignored rather than fatal, so a future label is not a break.
func parseKeylog(lines []string) map[string][]byte {
	keys := map[string][]byte{}
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 3 {
			continue
		}
		m := label.FindStringSubmatch(parts[0])
		if m == nil {
			continue
		}
		key, err := hex.DecodeString(parts[2])
		if err != nil || len(key) != 32 {
			continue
		}
		keys[strings.ToLower(m[1])+":"+m[2]] = key
	}
	return keys
}

// canon re-marshals through a map so key order stops mattering: the contract is
// the structure, not the text.
func canon(raw []byte) (string, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return "", err
	}
	out, err := json.Marshal(v)
	return string(out), err
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: keylog_check <path-to-keylog.json>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(v.Capture) == 0 || len(v.Capture) != len(v.Expected) {
		fmt.Fprintf(os.Stderr, "vector malformed: %d capture, %d expected\n", len(v.Capture), len(v.Expected))
		os.Exit(1)
	}
	keys := parseKeylog(v.Keylog)
	if len(keys) == 0 {
		fmt.Fprintln(os.Stderr, "no usable key-log entries in the vector")
		os.Exit(1)
	}

	failures := 0
	for i, frame := range v.Capture {
		want := v.Expected[i]
		ct, err := base64.StdEncoding.DecodeString(frame.Frame.Ct)
		if err != nil {
			fmt.Printf("FAIL frame %d: ct is not base64\n", i)
			failures++
			continue
		}
		key, ok := keys[frame.Dir+":"+strconv.Itoa(want.Epoch)]
		if !ok {
			fmt.Printf("FAIL frame %d: no key for %s epoch %d\n", i, frame.Dir, want.Epoch)
			failures++
			continue
		}
		pt, ok := transport.OpenCiphertext(key, frame.Frame.Seq, ct)
		if !ok {
			fmt.Printf("FAIL frame %d: the logged %s key did not open it\n", i, frame.Dir)
			failures++
			continue
		}
		got, err1 := canon(pt)
		wantCanon, err2 := canon(want.Inner)
		if err1 != nil || err2 != nil {
			fmt.Printf("FAIL frame %d: inner is not JSON\n", i)
			failures++
			continue
		}
		if got == wantCanon {
			fmt.Printf("PASS frame %d (%s seq %d)\n", i, frame.Dir, frame.Frame.Seq)
		} else {
			fmt.Printf("FAIL frame %d\n  got:  %s\n  want: %s\n", i, got, wantCanon)
			failures++
		}
	}

	// Self-test the oracle: a ciphertext no key seals must be refused, or a
	// checker that reported success for everything would look identical to this.
	var anyKey []byte
	for _, k := range keys {
		anyKey = k
		break
	}
	if _, ok := transport.OpenCiphertext(anyKey, 0, make([]byte, 32)); ok {
		fmt.Println("FAIL self-test: an unopenable frame was accepted")
		failures++
	} else {
		fmt.Println("PASS self-test: an unopenable frame is refused")
	}

	if failures > 0 {
		fmt.Fprintf(os.Stderr, "%d key-log frame(s) failed\n", failures)
		os.Exit(1)
	}
	fmt.Println("every captured frame opens with its logged key and reproduces the vector")
}
