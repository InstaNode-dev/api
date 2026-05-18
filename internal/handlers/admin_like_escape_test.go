package handlers

import "testing"

// TestEscapeLikePattern pins the SQL LIKE-metacharacter escaping used by the
// admin customer search. Without it an admin search of "%" or "_" would be
// interpreted as a wildcard and return every customer. Regression for
// BugHunt 2026-05-18 P3 (admin search unescaped LIKE wildcards).
func TestEscapeLikePattern(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain text untouched", "founder", "founder"},
		{"percent escaped", "a%b", `a\%b`},
		{"underscore escaped", "a_b", `a\_b`},
		{"backslash escaped", `a\b`, `a\\b`},
		{"bare percent", "%", `\%`},
		{"bare underscore", "_", `\_`},
		{"combined", `%_\`, `\%\_\\`},
		{"empty string", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := escapeLikePattern(tc.in); got != tc.want {
				t.Errorf("escapeLikePattern(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
