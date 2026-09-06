// Command bonemesh-inspect decrypts a captured BoneMesh transport stream using
// a key-log file, and prints the inner JSON of each frame — the encrypted-
// traffic debugging tool of security.md §8, in the spirit of tcpdump + an
// SSLKEYLOGFILE reader. It never touches private keys or the network: it reads
// the derived per-direction transport keys a node wrote to its BONEMESH_KEYLOG
// and applies them to a capture.
//
// Usage:
//
//	bonemesh-inspect --keylog <file> --capture <file>
//
// Key-log format (security.md §8), one entry per line, '#' comments ignored:
//
//	BMX3_I2R_TRAFFIC_<epoch> <hex transcript-hash> <hex 32-byte key>
//	BMX3_R2I_TRAFFIC_<epoch> <hex transcript-hash> <hex 32-byte key>
//
// Capture format: newline-delimited JSON, one wire frame per line, tagged with
// the direction its sender used:
//
//	{"dir":"i2r"|"r2i","frame":{"seq":<n>,"ct":"<base64>"}}
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/axonibyte/bonemesh/gonode/transport"
)

// A key-log entry: one derived transport key for a direction and rekey epoch.
type keyEntry struct {
	dir   string // "i2r" or "r2i"
	epoch int
	key   []byte
}

func main() {
	f := flags(os.Args[1:])
	keylogPath := require(f, "keylog")
	capturePath := require(f, "capture")

	entries := parseKeylog(keylogPath)
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "no usable key-log entries")
		os.Exit(1)
	}
	// Per direction, try newest epoch first so a rekeyed stream's later frames
	// (seq resets to 0 each epoch) match their own key; the Poly1305 tag is the
	// real arbiter, so ordering is only an efficiency hint.
	byDir := map[string][]keyEntry{}
	for _, e := range entries {
		byDir[e.dir] = append(byDir[e.dir], e)
	}
	for _, es := range byDir {
		sort.SliceStable(es, func(i, j int) bool { return es[i].epoch > es[j].epoch })
	}

	in := openFile(capturePath)
	defer in.Close()
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 128*1024), 1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		emitFrame(out, line, byDir)
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func emitFrame(out *bufio.Writer, line []byte, byDir map[string][]keyEntry) {
	var rec struct {
		Dir   string `json:"dir"`
		Frame struct {
			Seq json.Number `json:"seq"`
			Ct  string      `json:"ct"`
		} `json:"frame"`
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	if err := dec.Decode(&rec); err != nil {
		fmt.Fprintf(os.Stderr, "skipping unparseable capture line: %v\n", err)
		return
	}
	seq, err := strconv.ParseUint(rec.Frame.Seq.String(), 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "skipping frame with bad seq %q\n", rec.Frame.Seq.String())
		return
	}
	ct, err := base64.StdEncoding.DecodeString(rec.Frame.Ct)
	if err != nil {
		fmt.Fprintf(os.Stderr, "skipping frame with bad ct base64\n")
		return
	}

	for _, e := range byDir[rec.Dir] {
		pt, ok := transport.OpenCiphertext(e.key, seq, ct)
		if !ok {
			continue
		}
		var inner map[string]any
		id := json.NewDecoder(bytes.NewReader(pt))
		id.UseNumber()
		if id.Decode(&inner) != nil {
			continue
		}
		blob, _ := json.Marshal(map[string]any{
			"dir": rec.Dir, "seq": seq, "epoch": e.epoch, "inner": inner,
		})
		out.Write(blob)
		out.WriteByte('\n')
		return
	}
	fmt.Fprintf(os.Stderr, "frame dir=%s seq=%d: no key opened it\n", rec.Dir, seq)
}

func parseKeylog(path string) []keyEntry {
	in := openFile(path)
	defer in.Close()
	var entries []keyEntry
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue // unknown label shape — ignore forward-compatibly
		}
		dir, epoch, ok := parseLabel(fields[0])
		if !ok {
			continue
		}
		key, err := hex.DecodeString(fields[2])
		if err != nil || len(key) != 32 {
			continue
		}
		entries = append(entries, keyEntry{dir: dir, epoch: epoch, key: key})
	}
	return entries
}

// parseLabel splits "BMX3_I2R_TRAFFIC_<epoch>" into ("i2r", epoch, true).
func parseLabel(label string) (string, int, bool) {
	var dirTok string
	switch {
	case strings.HasPrefix(label, "BMX3_I2R_TRAFFIC_"):
		dirTok, label = "i2r", strings.TrimPrefix(label, "BMX3_I2R_TRAFFIC_")
	case strings.HasPrefix(label, "BMX3_R2I_TRAFFIC_"):
		dirTok, label = "r2i", strings.TrimPrefix(label, "BMX3_R2I_TRAFFIC_")
	default:
		return "", 0, false
	}
	epoch, err := strconv.Atoi(label)
	if err != nil {
		return "", 0, false
	}
	return dirTok, epoch, true
}

func openFile(path string) *os.File {
	fh, err := os.Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	return fh
}

func flags(args []string) map[string]string {
	f := map[string]string{}
	for i := 0; i+1 < len(args); i += 2 {
		if len(args[i]) > 2 && args[i][:2] == "--" {
			f[args[i][2:]] = args[i+1]
		}
	}
	return f
}

func require(f map[string]string, key string) string {
	v, ok := f[key]
	if !ok || v == "" {
		fmt.Fprintf(os.Stderr, "missing required --%s\n", key)
		os.Exit(2)
	}
	return v
}
