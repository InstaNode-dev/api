// Command openapi-snapshot writes the production-rendered OpenAPI 3.1 spec
// to api/openapi.snapshot.json (or to the path given by -out).
//
// This is the source-of-truth artifact for cross-stack contract testing. The
// dashboard and instanode-web repos consume the committed snapshot to generate
// their typed API clients via openapi-typescript. If the snapshot drifts from
// what handlers.OpenAPISpecProduction returns (i.e. someone edited the spec
// const without regenerating), `make openapi-snapshot-check` fails CI with a
// clear "regenerate the snapshot" message.
//
// The snapshot is canonicalised before writing:
//   - parsed as JSON and re-marshalled with sorted map keys and 2-space indent
//
// so that whitespace-only edits to the const (re-flowed strings, added blank
// lines) do not falsely flip the snapshot. The only things that change the
// snapshot are real contract changes: new paths, changed schemas, renamed
// fields, removed responses.
//
// Usage:
//
//	go run ./cmd/openapi-snapshot              # writes ./openapi.snapshot.json
//	go run ./cmd/openapi-snapshot -out /tmp/x  # writes to /tmp/x
//	go run ./cmd/openapi-snapshot -stdout      # prints to stdout (CI diff)
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"instant.dev/internal/handlers"
)

const defaultOutPath = "openapi.snapshot.json"

func main() {
	out := flag.String("out", defaultOutPath, "destination file for the canonical snapshot")
	toStdout := flag.Bool("stdout", false, "write to stdout instead of -out (CI diff mode)")
	flag.Parse()

	canonical, err := canonicalise(handlers.OpenAPISpecProduction())
	if err != nil {
		fmt.Fprintf(os.Stderr, "openapi-snapshot: canonicalise: %v\n", err)
		os.Exit(2)
	}

	if *toStdout {
		if _, err := os.Stdout.Write(canonical); err != nil {
			fmt.Fprintf(os.Stderr, "openapi-snapshot: stdout: %v\n", err)
			os.Exit(2)
		}
		return
	}

	if err := os.WriteFile(*out, canonical, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "openapi-snapshot: write %s: %v\n", *out, err)
		os.Exit(2)
	}
	fmt.Fprintf(os.Stderr, "openapi-snapshot: wrote %d bytes to %s\n", len(canonical), *out)
}

// canonicalise parses the spec as JSON and re-emits it with sorted keys and
// 2-space indent so that the on-disk snapshot is deterministic and friendly
// to diff. encoding/json sorts map keys alphabetically by default.
func canonicalise(spec string) ([]byte, error) {
	var v any
	if err := json.Unmarshal([]byte(spec), &v); err != nil {
		return nil, fmt.Errorf("parse spec: %w", err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("re-emit spec: %w", err)
	}
	return buf.Bytes(), nil
}
