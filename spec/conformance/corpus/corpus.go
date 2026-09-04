// Package corpus locates and loads the language-agnostic conformance corpus
// that lives beside this Go module (../corpus relative to the module root).
package corpus

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Dir returns the absolute path to the corpus directory by walking up from the
// working directory until it finds a directory containing both "corpus" and
// "conformance" siblings. This works during `go test` (cwd is the package dir)
// and inside a reaper guest (paths are preserved by sync).
func Dir() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for dir := wd; ; {
		c := filepath.Join(dir, "corpus")
		if fi, err := os.Stat(c); err == nil && fi.IsDir() {
			if fi2, err := os.Stat(filepath.Join(dir, "conformance")); err == nil && fi2.IsDir() {
				return c, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("corpus: could not locate corpus/ above %s", wd)
		}
		dir = parent
	}
}

// LoadInto reads corpus file `name` and decodes it into v with UseNumber, so
// integers survive exactly.
func LoadInto(name string, v any) error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	return dec.Decode(v)
}
