// Command interop_node is the Go driver for the language-agnostic interop
// harness (interop/). It implements the neutral driver contract (keygen /
// listen / connect) over shared, implementation-independent key and certificate
// files, so the harness pairs it with any other driver.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strconv"
	"time"

	"github.com/axonibyte/bonemesh/gonode/crypto"
	"github.com/axonibyte/bonemesh/gonode/node"
)

func main() {
	if len(os.Args) < 2 {
		os.Stderr.WriteString("usage: interop_node <keygen|listen|connect> [--flag value ...]\n")
		os.Exit(2)
	}
	f := flags(os.Args[2:])
	switch os.Args[1] {
	case "keygen":
		keygen(f)
	case "listen":
		listen(f)
	case "connect":
		connect(f)
	default:
		os.Exit(2)
	}
}

func keygen(f map[string]string) {
	pub, priv := crypto.MLDSA65Generate()
	must(os.WriteFile(f["id-pub"], []byte(base64.StdEncoding.EncodeToString(pub)), 0o644))
	must(os.WriteFile(f["id-priv"], []byte(base64.StdEncoding.EncodeToString(priv)), 0o644))
}

func config(f map[string]string) node.Config {
	rootPub := decodeB64(read(f["root-pub"]))
	idPriv := decodeB64(read(f["id-priv"]))
	cert := loadCert(f["cert"])
	label, _ := cert["label"].(string)
	return node.Config{Label: label, Mesh: f["mesh"], RootPublic: rootPub, Cert: cert, IDPrivate: idPriv}
}

func listen(f map[string]string) {
	port, _ := strconv.Atoi(f["port"])
	seconds := seconds(f)
	n, err := node.Start(config(f), port)
	must(err)
	ch := n.AddListener()
	out := f["out"]
	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	for time.Now().Before(deadline) {
		select {
		case payload := <-ch:
			b, _ := json.Marshal(payload)
			appendLine(out, b)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func connect(f map[string]string) {
	n, err := node.Start(config(f), 0)
	must(err)
	port, _ := strconv.Atoi(f["port"])
	if _, err := n.Connect(f["host"], port); err != nil {
		os.Stderr.WriteString("connect: " + err.Error() + "\n")
		os.Exit(1)
	}
	payload := loadJSON(f["message"])
	deadline := time.Now().Add(time.Duration(seconds(f)) * time.Second)
	for time.Now().Before(deadline) {
		if n.Send(f["to"], payload) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	time.Sleep(1500 * time.Millisecond)
}

func loadCert(path string) map[string]any {
	dec := json.NewDecoder(bytes.NewReader([]byte(read(path))))
	dec.UseNumber()
	var m map[string]any
	must(dec.Decode(&m))
	return m
}

func loadJSON(path string) map[string]any {
	var m map[string]any
	must(json.Unmarshal([]byte(read(path)), &m))
	return m
}

func appendLine(path string, line []byte) {
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	must(err)
	defer fh.Close()
	fh.Write(append(line, '\n'))
}

func read(path string) string {
	b, err := os.ReadFile(path)
	must(err)
	return string(b)
}

func decodeB64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(trim(s))
	must(err)
	return b
}

func trim(s string) string {
	return string(bytes.TrimSpace([]byte(s)))
}

func flags(args []string) map[string]string {
	m := map[string]string{}
	for i := 0; i+1 < len(args); i += 2 {
		if len(args[i]) > 2 && args[i][:2] == "--" {
			m[args[i][2:]] = args[i+1]
		}
	}
	return m
}

func seconds(f map[string]string) int {
	if s, ok := f["seconds"]; ok {
		if v, err := strconv.Atoi(s); err == nil {
			return v
		}
	}
	return 10
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
