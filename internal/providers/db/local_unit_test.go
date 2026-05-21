package db

// Pure-unit coverage for the no-network helpers in local.go: the URL
// surgery (`extractHost` / `buildDBURL` / `buildAdminNewDBURL`), the
// `indexOf` byte-scan, `generatePassword`'s charset + length invariants,
// and `newLocalBackend`'s default-URL substitution. None of these touch
// Postgres — they exercise the helper layer that lives between
// `Provision` and the wire.

import (
	"strings"
	"testing"
)

// Test_newLocalBackend_DefaultURL — passing "" must substitute the
// package-level default so callers running outside k8s don't accidentally
// connect to nothing.
func Test_newLocalBackend_DefaultURL(t *testing.T) {
	b := newLocalBackend("")
	if b.customersURL != defaultCustomersURL {
		t.Fatalf("empty input: got %q want %q", b.customersURL, defaultCustomersURL)
	}

	custom := "postgres://x:y@host:1234/db?sslmode=disable"
	b2 := newLocalBackend(custom)
	if b2.customersURL != custom {
		t.Fatalf("custom input: got %q want %q", b2.customersURL, custom)
	}
}

// Test_generatePassword_LengthAndCharset — output is exactly n bytes long
// and every byte is in `alphanumChars`. n=0 is permitted (empty string).
func Test_generatePassword_LengthAndCharset(t *testing.T) {
	for _, n := range []int{0, 1, 8, 16, 64} {
		got, err := generatePassword(n)
		if err != nil {
			t.Fatalf("generatePassword(%d): %v", n, err)
		}
		if len(got) != n {
			t.Fatalf("generatePassword(%d): len=%d want %d", n, len(got), n)
		}
		for i := 0; i < len(got); i++ {
			if !strings.ContainsRune(alphanumChars, rune(got[i])) {
				t.Fatalf("generatePassword(%d): byte %q at %d not in charset", n, got[i], i)
			}
		}
	}
}

// Test_generatePassword_RandomEnough — two consecutive 32-byte passwords
// must differ. Tiny smoke check, not a statistical test — the goal is
// only to prove crypto/rand was actually invoked.
func Test_generatePassword_RandomEnough(t *testing.T) {
	a, err := generatePassword(32)
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := generatePassword(32)
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if a == b {
		t.Fatalf("two 32-byte passwords collided — crypto/rand not invoked? %q", a)
	}
}

// failingReader returns an error on every Read. Used to drive the
// `rand.Int` error branch in generatePassword without disturbing
// crypto/rand for other tests.
type failingReader struct{ err error }

func (f failingReader) Read(_ []byte) (int, error) { return 0, f.err }

// Test_generatePassword_RandErrorBranch — when the package-level
// randReader fails, generatePassword surfaces the error wrapped with
// the function name.
func Test_generatePassword_RandErrorBranch(t *testing.T) {
	orig := randReader
	t.Cleanup(func() { randReader = orig })
	randReader = failingReader{err: errFakeRand}

	got, err := generatePassword(8)
	if err == nil {
		t.Fatalf("want error, got %q", got)
	}
	if !strings.Contains(err.Error(), "generatePassword") {
		t.Fatalf("err=%v want generatePassword-wrapped", err)
	}
}

// errFakeRand is a sentinel passed into failingReader so tests can match
// it back via errors.Is if needed. Kept package-level so test files
// outside this one can reuse it.
var errFakeRand = &fakeRandError{msg: "fake rand failed"}

type fakeRandError struct{ msg string }

func (e *fakeRandError) Error() string { return e.msg }

// Test_indexOf_ByteScan — the package's own minimal `bytes.IndexByte`
// replacement. Cover both the hit (returns index) and miss (returns -1)
// branches.
func Test_indexOf_ByteScan(t *testing.T) {
	cases := []struct {
		s    string
		c    byte
		want int
	}{
		{"abcd", 'c', 2},
		{"abcd", 'a', 0},
		{"abcd", 'd', 3},
		{"abcd", 'z', -1},
		{"", 'x', -1},
		{"@", '@', 0},
	}
	for _, tc := range cases {
		if got := indexOf(tc.s, tc.c); got != tc.want {
			t.Errorf("indexOf(%q,%q)=%d want %d", tc.s, tc.c, got, tc.want)
		}
	}
}

// Test_extractHost_Cases — covers every branch in extractHost:
//   - prefix-trimmed input
//   - URL with user:pass@host:port/db
//   - URL with host only (no auth, no path)
//   - URL with no '/' after host (returns rest of string)
//   - empty string (returns empty)
//   - input shorter than the postgres:// prefix (defensive branch)
func Test_extractHost_Cases(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"postgres://user:pass@host:5432/db", "host:5432"},
		{"postgres://user:pass@host/db", "host"},
		{"postgres://host:5432/db", "host:5432"},
		{"postgres://host", "host"},
		{"postgres://user:pass@host:5432/db?sslmode=disable", "host:5432"},
		{"", ""},
		// Shorter than `postgres://` — defensive branch where the
		// prefix-trim is skipped.
		{"pg", "pg"},
	}
	for _, tc := range cases {
		if got := extractHost(tc.in); got != tc.want {
			t.Errorf("extractHost(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

// Test_buildDBURL_RoundtripsHost — buildDBURL composes a per-tenant
// user-facing URL by stripping the admin URL down to host:port and
// re-attaching the new credentials + database name.
func Test_buildDBURL_RoundtripsHost(t *testing.T) {
	b := &LocalBackend{customersURL: "postgres://admin:adminpw@db.internal:5432/instant_customers?sslmode=disable"}
	got := b.buildDBURL("usr_abc", "secret", "db_abc")
	want := "postgres://usr_abc:secret@db.internal:5432/db_abc"
	if got != want {
		t.Fatalf("buildDBURL: got %q want %q", got, want)
	}
}

// Test_buildAdminNewDBURL_SwapsTrailingDatabase — strips the trailing
// `/...` from the admin URL and re-attaches the new database name.
func Test_buildAdminNewDBURL_SwapsTrailingDatabase(t *testing.T) {
	cases := []struct {
		admin string
		db    string
		want  string
	}{
		{
			"postgres://admin:pw@host:5432/instant_customers",
			"db_xyz",
			"postgres://admin:pw@host:5432/db_xyz",
		},
		{
			"postgres://admin:pw@host:5432/instant_customers?sslmode=disable",
			// query-string lives AFTER the database name and is intentionally
			// truncated by the simple "find last '/'" rewrite. The agent-
			// visible URL uses sslmode=disable by default at the caller level;
			// this test pins the documented behaviour.
			"db_xyz",
			"postgres://admin:pw@host:5432/db_xyz",
		},
		{
			// Defensive branch: no '/' anywhere — fallback appends "/db_xyz".
			"postgres-no-slashes",
			"db_xyz",
			"postgres-no-slashes/db_xyz",
		},
	}
	for _, tc := range cases {
		b := &LocalBackend{customersURL: tc.admin}
		if got := b.buildAdminNewDBURL(tc.db); got != tc.want {
			t.Errorf("buildAdminNewDBURL(%q,%q)=%q want %q", tc.admin, tc.db, got, tc.want)
		}
	}
}
