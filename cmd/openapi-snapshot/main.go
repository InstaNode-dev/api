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
	"io"
	"os"

	"instant.dev/internal/handlers"
)

const defaultOutPath = "openapi.snapshot.json"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the testable body of main. Returns the exit code. Splitting main
// from run lets the test suite invoke the binary's behaviour without
// shelling out to a subprocess.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("openapi-snapshot", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", defaultOutPath, "destination file for the canonical snapshot")
	toStdout := fs.Bool("stdout", false, "write to stdout instead of -out (CI diff mode)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	canonical, err := canonicalise(handlers.OpenAPISpecProduction())
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "openapi-snapshot: canonicalise: %v\n", err)
		return 2
	}

	if *toStdout {
		if _, err := stdout.Write(canonical); err != nil {
			_, _ = fmt.Fprintf(stderr, "openapi-snapshot: stdout: %v\n", err)
			return 2
		}
		return 0
	}

	if err := os.WriteFile(*out, canonical, 0o644); err != nil {
		_, _ = fmt.Fprintf(stderr, "openapi-snapshot: write %s: %v\n", *out, err)
		return 2
	}
	_, _ = fmt.Fprintf(stderr, "openapi-snapshot: wrote %d bytes to %s\n", len(canonical), *out)
	return 0
}

// canonicalise parses the spec as JSON and re-emits it with sorted keys and
// 2-space indent so that the on-disk snapshot is deterministic and friendly
// to diff. encoding/json sorts map keys alphabetically by default.
//
// Re-encoding a value produced by json.Unmarshal cannot fail (bytes.Buffer
// writes never error, and json.Marshal on interface{} produced from valid
// JSON is always defined), so we only surface the parse error.
func canonicalise(spec string) ([]byte, error) {
	var v any
	if err := json.Unmarshal([]byte(spec), &v); err != nil {
		return nil, fmt.Errorf("parse spec: %w", err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v) // see godoc: re-encoding a valid-JSON-derived value cannot fail
	return buf.Bytes(), nil
}
