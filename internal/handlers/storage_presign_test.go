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

// TestIsSafePresignKey covers the B17-P0 hard-reject contract. Pre-B17
// the handler silently stripped "../" segments — the new contract is to
// 400 path_unsafe on any traversal token, so the sanitiser becomes pure
// defense-in-depth. isSafePresignKey is the boolean gate that drives the
// rejection.
func TestIsSafePresignKey(t *testing.T) {
	cases := map[string]bool{
		"":                false, // empty key is invalid (separate invalid_key gate, but isSafe is also false)
		"file.txt":        true,
		"a/b/c":           true,
		"a/b/c.bin":       true,
		"valid-key.bin":   true,
		"path/with-dash":  true,
		"path with space": true, // spaces are fine in S3 keys
		"deep/nested/path/with/many/segments/file.txt": true,

		"/file.txt":    false, // leading slash is rejected
		"//file.txt":   false,
		"../etc":       false, // ".." segment
		"../../escape": false,
		"a/../b":       false, // ".." anywhere
		"./file.txt":   false, // "." segment
		"a/./b":        false,
		"a//b":         false, // empty segment (double slash)
		"trailing/":    false, // trailing slash = empty trailing segment
	}
	for in, want := range cases {
		got := isSafePresignKey(in)
		assert.Equalf(t, want, got, "isSafePresignKey(%q)", in)
	}
}

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
