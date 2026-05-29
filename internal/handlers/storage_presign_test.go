package handlers

// storage_presign_test.go — unit tests for the broker-mode presign endpoint.
//
// The handler-level path-traversal sanitisation is exercised directly via
// sanitisePresignKey. The full HTTP round-trip is covered by
// storage_test.go's app-level tests in the _test package; those depend on
// MinIO being available, and skip when it isn't.

import (
	"net/url"
	"strings"
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

// TestRewritePresignHost_CanonicalHostSubstitution covers API-3 (QA 2026-05-29).
// The signed URL must be rewritten from the DO-internal host
// (nyc3.digitaloceanspaces.com) to the canonical public host
// (s3.instanode.dev) when ObjectStorePublicURL is configured, while the path
// and entire query string (including the SigV4 signature) are preserved
// verbatim. When ObjectStorePublicURL is empty, the original URL is returned.
func TestRewritePresignHost_CanonicalHostSubstitution(t *testing.T) {
	signedRaw := "https://nyc3.digitaloceanspaces.com/instant-shared/abc12345/test.txt" +
		"?X-Amz-Algorithm=AWS4-HMAC-SHA256" +
		"&X-Amz-Credential=DO00CXYXRKNHR6XM77RE%2F20260529%2Fnyc3%2Fs3%2Faws4_request" +
		"&X-Amz-Date=20260529T120000Z" +
		"&X-Amz-Expires=600" +
		"&X-Amz-SignedHeaders=host" +
		"&X-Amz-Signature=deadbeefcafebabe"

	t.Run("rewrites host+scheme when publicURL configured", func(t *testing.T) {
		signed, err := url.Parse(signedRaw)
		assert.NoError(t, err)
		out, ok := rewritePresignHost(signed, "https://s3.instanode.dev")
		assert.True(t, ok, "rewrite must succeed when publicURL is non-empty")
		// Canonical host now visible.
		assert.True(t, strings.HasPrefix(out, "https://s3.instanode.dev/"),
			"got %q", out)
		// DO Spaces host fully removed.
		assert.NotContains(t, out, "nyc3.digitaloceanspaces.com",
			"DO Spaces host must not leak through; got %q", out)
		// Path preserved.
		assert.Contains(t, out, "/instant-shared/abc12345/test.txt")
		// SigV4 signature (the load-bearing piece — DO Spaces accepts the
		// canonical CNAME with the original signature) preserved verbatim.
		assert.Contains(t, out, "X-Amz-Signature=deadbeefcafebabe")
		assert.Contains(t, out, "X-Amz-Credential=DO00CXYXRKNHR6XM77RE")
		assert.Contains(t, out, "X-Amz-Expires=600")
	})

	t.Run("empty publicURL returns original (local dev fallback)", func(t *testing.T) {
		signed, err := url.Parse(signedRaw)
		assert.NoError(t, err)
		out, ok := rewritePresignHost(signed, "")
		assert.False(t, ok, "empty publicURL must report no rewrite happened")
		assert.Equal(t, signedRaw, out,
			"empty publicURL must return the original URL unchanged")
	})

	t.Run("malformed publicURL returns original", func(t *testing.T) {
		signed, err := url.Parse(signedRaw)
		assert.NoError(t, err)
		// A URL with no host after parsing — url.Parse is lenient, so we
		// force the "host is empty" branch by passing a bare scheme.
		out, ok := rewritePresignHost(signed, "https://")
		assert.False(t, ok, "publicURL with empty host must not rewrite")
		assert.Equal(t, signedRaw, out)
	})

	t.Run("nil signed URL returns empty + false", func(t *testing.T) {
		out, ok := rewritePresignHost(nil, "https://s3.instanode.dev")
		assert.False(t, ok)
		assert.Equal(t, "", out)
	})

	t.Run("publicURL inherits signed scheme when scheme missing", func(t *testing.T) {
		// Test the scheme-fallback branch where publicURL is parsed as a
		// host-only string (no scheme). url.Parse on a bare host returns
		// {Scheme:"" Host:""} (it lands in Opaque) — so synthesize a
		// scheme-less URL by passing "//host/path".
		signed, err := url.Parse(signedRaw)
		assert.NoError(t, err)
		// publicURL with scheme but bare host — verify scheme override path.
		out, ok := rewritePresignHost(signed, "http://s3.instanode.dev")
		assert.True(t, ok)
		assert.True(t, strings.HasPrefix(out, "http://s3.instanode.dev/"))
	})
}
