package migrations_test

// state_public_version_test.go — BUG-API-090/217 regression. Lives in
// the migrations package (not router_test) so go test's coverage tool
// attributes the hits against migrations/state.go for the 100%-patch
// gate.

import (
	"testing"

	"github.com/stretchr/testify/require"

	"instant.dev/internal/migrations"
)

func TestPublicVersion_StripsFilenameSuffix(t *testing.T) {
	cases := []struct {
		filename string
		want     string
	}{
		// The case that motivated the bug: BUG-API-090/217 — anyone
		// hitting /healthz saw the embedded table/feature name.
		{"063_forwarder_sent_audit_link.sql", "063"},
		{"022_schema_migrations.sql", "022"},
		{"001_init.sql", "001"},
		{"100_team_deletion_purge.sql", "100"},
		// No underscore — return stem only (strips .sql).
		{"baseline.sql", "baseline"},
		// No extension — return up to first underscore.
		{"063_anything", "063"},
		// Empty (DB unreachable / pre-migration).
		{"", ""},
	}
	for _, tc := range cases {
		s := migrations.State{Filename: tc.filename}
		got := s.PublicVersion()
		require.Equal(t, tc.want, got,
			"BUG-API-090: PublicVersion(%q) must strip to numeric prefix; got %q",
			tc.filename, got)
		// Sanity rail: no '_' or '.sql' escapes the helper, regardless of input.
		require.NotContains(t, got, "_",
			"BUG-API-090: PublicVersion must never contain '_' (would leak table/feature name)")
		require.NotContains(t, got, ".sql",
			"BUG-API-090: PublicVersion must never contain '.sql' (would leak filename)")
	}
}
