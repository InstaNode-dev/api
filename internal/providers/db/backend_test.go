package db

import "testing"

// TestValidateExtensions_AllowedAndRejected — the extension allowlist is a
// security boundary: only "vector" may flow through to CREATE EXTENSION.
// Adding any new entry MUST be reviewed against tenant-isolation concerns.
func TestValidateExtensions_AllowedAndRejected(t *testing.T) {
	cases := []struct {
		name    string
		exts    []string
		wantErr bool
	}{
		{"nil", nil, false},
		{"empty", []string{}, false},
		{"vector_only", []string{"vector"}, false},
		{"unknown_extension", []string{"pg_stat_statements"}, true},
		{"vector_plus_unknown", []string{"vector", "postgis"}, true},
		{"injection_attempt", []string{"vector; DROP DATABASE foo"}, true},
		{"uppercase_not_allowed", []string{"VECTOR"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateExtensions(tc.exts)
			if tc.wantErr && err == nil {
				t.Fatalf("ValidateExtensions(%v) = nil; want error", tc.exts)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ValidateExtensions(%v) = %v; want nil", tc.exts, err)
			}
		})
	}
}
