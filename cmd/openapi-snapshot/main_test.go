package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"instant.dev/internal/handlers"
)

func TestCanonicalise_SortsKeysAnd2SpaceIndent(t *testing.T) {
	in := `{"z":1,"a":{"y":2,"b":3}}`
	got, err := canonicalise(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := string(got)

	if !strings.Contains(out, "  \"a\"") || !strings.Contains(out, "    \"b\"") {
		t.Errorf("expected 2-space indent on nested keys, got:\n%s", out)
	}
	idxA := strings.Index(out, "\"a\"")
	idxZ := strings.Index(out, "\"z\"")
	if idxA < 0 || idxZ < 0 || idxA > idxZ {
		t.Errorf("expected keys sorted alphabetically ('a' before 'z'), got:\n%s", out)
	}
	idxB := strings.Index(out, "\"b\"")
	idxY := strings.Index(out, "\"y\"")
	if idxB < 0 || idxY < 0 || idxB > idxY {
		t.Errorf("expected nested keys sorted ('b' before 'y'), got:\n%s", out)
	}
}

func TestCanonicalise_RejectsInvalidJSON(t *testing.T) {
	_, err := canonicalise("not json at all")
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "parse spec") {
		t.Errorf("expected wrapped 'parse spec' error, got: %v", err)
	}
}

func TestCanonicalise_DoesNotEscapeHTML(t *testing.T) {
	in := `{"url":"https://instanode.dev/deploy?env=production&plan=hobby"}`
	got, err := canonicalise(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(got)
	if !strings.Contains(s, `&plan=hobby`) {
		t.Errorf("expected literal '&' preserved (HTML escaping disabled), got:\n%s", s)
	}
	if strings.Contains(s, "\\u0026") {
		t.Errorf("expected '&' not to be escaped as backslash-u0026, got:\n%s", s)
	}
}

func TestRun_StdoutMode_WritesCanonicalSpec(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-stdout"}, &stdout, &stderr, handlers.OpenAPISpecProduction)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr: %s)", code, stderr.String())
	}
	if stdout.Len() == 0 {
		t.Fatal("expected non-empty stdout")
	}
	if !strings.HasPrefix(stdout.String(), "{") {
		t.Errorf("expected JSON object on stdout, got prefix: %q", stdout.String()[:min(40, stdout.Len())])
	}
}

func TestRun_FileMode_WritesToCustomOutPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "snap.json")
	var stdout, stderr bytes.Buffer
	code := run([]string{"-out", target}, &stdout, &stderr, handlers.OpenAPISpecProduction)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr: %s)", code, stderr.String())
	}
	stat, err := os.Stat(target)
	if err != nil {
		t.Fatalf("expected file at %s, got error: %v", target, err)
	}
	if stat.Size() == 0 {
		t.Errorf("expected non-empty file, got 0 bytes")
	}
	if !strings.Contains(stderr.String(), "wrote") {
		t.Errorf("expected stderr breadcrumb 'wrote N bytes to ...', got: %q", stderr.String())
	}
}

func TestRun_BadFlag_ReturnsExit2(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--no-such-flag"}, &stdout, &stderr, handlers.OpenAPISpecProduction)
	if code != 2 {
		t.Errorf("expected exit 2 for unknown flag, got %d", code)
	}
}

func TestRun_FileMode_UnwritableOutPath_ReturnsExit2(t *testing.T) {
	// Portable: write into a path whose parent directory doesn't exist.
	// os.WriteFile returns ENOENT on both macOS + Linux for this.
	dir := t.TempDir()
	target := filepath.Join(dir, "does", "not", "exist", "snap.json")
	var stdout, stderr bytes.Buffer
	code := run([]string{"-out", target}, &stdout, &stderr, handlers.OpenAPISpecProduction)
	if code != 2 {
		t.Errorf("expected exit 2 for unwritable -out, got %d (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "openapi-snapshot: write") {
		t.Errorf("expected stderr to mention the write failure, got: %q", stderr.String())
	}
}

// TestMain_DispatchesViaExitFn covers the main() entry-point line by
// swapping exitFn for a capture closure. os.Args[1:] in test context is
// the test framework's flag set, which flag.Parse rejects → run returns 2.
// We assert exitFn received that value (proving main correctly forwards
// run's return code), not the specific number.
func TestMain_DispatchesViaExitFn(t *testing.T) {
	var captured int = -1
	orig := exitFn
	exitFn = func(code int) { captured = code }
	defer func() { exitFn = orig }()
	main()
	if captured < 0 {
		t.Errorf("expected exitFn to be invoked, got captured=%d", captured)
	}
}

func TestRun_BadSpecSource_ReturnsExit2(t *testing.T) {
	var stdout, stderr bytes.Buffer
	badSpec := func() string { return "not json at all" }
	code := run([]string{"-stdout"}, &stdout, &stderr, badSpec)
	if code != 2 {
		t.Errorf("expected exit 2 when specSource is malformed, got %d", code)
	}
	if !strings.Contains(stderr.String(), "not valid JSON") {
		t.Errorf("expected stderr to mention 'not valid JSON', got: %q", stderr.String())
	}
}

// failingWriter implements io.Writer and always returns an error. Used to
// drive the stdout-write-error branch of run().
type failingWriter struct{ err error }

func (w failingWriter) Write(_ []byte) (int, error) { return 0, w.err }

func TestRun_StdoutMode_WriteError_ReturnsExit2(t *testing.T) {
	stdout := failingWriter{err: errors.New("simulated stdout write failure")}
	var stderr bytes.Buffer
	code := run([]string{"-stdout"}, stdout, &stderr, handlers.OpenAPISpecProduction)
	if code != 2 {
		t.Errorf("expected exit 2 for stdout write failure, got %d (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "simulated stdout write failure") {
		t.Errorf("expected stderr to wrap the write error, got: %q", stderr.String())
	}
}
