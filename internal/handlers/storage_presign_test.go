package handlers

// storage_presign_test.go — unit tests for the broker-mode presign endpoint.
//
// The handler-level path-traversal sanitisation is exercised directly via
// sanitisePresignKey. The full HTTP round-trip is covered by
// storage_test.go's app-level tests in the _test package; those depend on
// MinIO being available, and skip when it isn't.

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSanitisePresignKey verifies the path-traversal trim used by the
// presign handler. Any tenant-supplied "../" component would let a leaked
// URL escape the resource's prefix; the sanitiser must drop those.
func TestSanitisePresignKey(t *testing.T) {
	cases := map[string]string{
		"":                   "",
		"file.txt":           "file.txt",
		"/file.txt":          "file.txt",          // leading slash stripped
		"//file.txt":         "file.txt",
		"dir/file.txt":       "dir/file.txt",
		"dir//file.txt":      "dir/file.txt",      // empty components dropped
		"../etc/passwd":      "etc/passwd",        // .. dropped
		"./file.txt":         "file.txt",          // . dropped
		"a/./b/../c":         "a/b/c",
		"../../escape":       "escape",            // can't escape
		"valid-key.bin":      "valid-key.bin",
		"path/with spaces":   "path/with spaces",  // spaces are fine
	}
	for in, want := range cases {
		got := sanitisePresignKey(in)
		assert.Equal(t, want, got, "sanitisePresignKey(%q)", in)
	}
}
