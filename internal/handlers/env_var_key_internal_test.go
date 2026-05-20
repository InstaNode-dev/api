package handlers

// env_var_key_internal_test.go — unit-level tests for the
// package-private POSIX env-var key validator. T13 P2-T13-04 (BugHunt
// 2026-05-20). Runs without any external service so it stays green in
// the test-shy CI bucket.

import "testing"

func TestIsValidEnvKey_POSIX(t *testing.T) {
	cases := []struct {
		k    string
		want bool
	}{
		// Happy path.
		{"DATABASE_URL", true},
		{"PORT", true},
		{"X", true},
		{"_FOO", true},
		{"FOO_BAR_BAZ_1", true},
		// Disallowed shapes.
		{"", false},
		{"database_url", false}, // lowercase
		{"DB-URL", false},       // hyphen
		{"DB.URL", false},       // dot
		{"1FOO", false},         // leading digit
		{"FOO=BAR", false},      // equals
		{"FOO BAR", false},      // space
		{"FOO\nBAR", false},     // newline
		{"FOOé", false},    // non-ASCII letter (é)
		{"PATH\x00X", false},    // NUL byte
	}
	for _, c := range cases {
		got := isValidEnvKey(c.k)
		if got != c.want {
			t.Errorf("isValidEnvKey(%q)=%v want %v", c.k, got, c.want)
		}
	}
}

func TestValidateEnvVarKeys_SkipsUnderscorePrefix(t *testing.T) {
	// Internal `_`-prefixed keys are stripped by callers before the
	// k8s apply, so the validator must skip them. Otherwise the
	// internal deployNameEnvKey `_name` would itself fail validation.
	m := map[string]string{"_name": "x", "OK": "y"}
	if ok, bad := validateEnvVarKeys(m); !ok {
		t.Fatalf("validateEnvVarKeys should skip _name; rejected %q", bad)
	}
}

func TestValidateEnvVarKeys_NamesOffender(t *testing.T) {
	m := map[string]string{"DB-URL": "x"}
	ok, bad := validateEnvVarKeys(m)
	if ok {
		t.Fatalf("validateEnvVarKeys should reject DB-URL")
	}
	if bad != "DB-URL" {
		t.Fatalf("expected DB-URL, got %q", bad)
	}
}

func TestQuoteForError_EscapesAttackerInput(t *testing.T) {
	// quoteForError must JSON-quote control characters so an attacker
	// who supplies a key with a newline cannot inject a CRLF into the
	// 4xx body / log line.
	q := quoteForError("FOO\nBAR")
	want := `"FOO\nBAR"`
	if q != want {
		t.Fatalf("quoteForError: want %q got %q", want, q)
	}
}
