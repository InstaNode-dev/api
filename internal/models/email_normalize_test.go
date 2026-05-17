package models_test

// email_normalize_test.go — P7 coverage: email canonicalisation.
//
// The /claim account-takeover guard does GetUserByEmail(body.Email). Before
// P7 that was an exact-match lookup with no normalisation, so "Victim@X.com"
// would not match the stored "victim@x.com" row — letting a duplicate-
// identity account slip past the Wave-1 takeover guard.
//
// TestNormalizeEmail runs without a DB. The case-insensitive-lookup +
// unique-index tests skip when TEST_DATABASE_URL is unset.

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// TestNormalizeEmail pins the canonicaliser: lower-case + trim.
func TestNormalizeEmail(t *testing.T) {
	cases := []struct{ in, want string }{
		{"victim@x.com", "victim@x.com"},
		{"Victim@X.com", "victim@x.com"},
		{"  victim@x.com  ", "victim@x.com"},
		{"\tVICTIM@X.COM\n", "victim@x.com"},
		{"", ""},
		{"   ", ""},
	}
	for _, c := range cases {
		if got := models.NormalizeEmail(c.in); got != c.want {
			t.Errorf("NormalizeEmail(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestGetUserByEmail_CaseInsensitive is the P7 coverage test: a user
// created with one casing must be found by GetUserByEmail regardless of
// the casing / whitespace of the lookup string. If this fails, the /claim
// account-takeover guard is bypassable again.
func TestGetUserByEmail_CaseInsensitive(t *testing.T) {
	requireDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	// Create the user with a mixed-case + padded email.
	canonical := "victim-" + uuid.NewString()[:8] + "@example.com"
	created, err := models.CreateUser(ctx, db, teamID, "  "+strings.ToUpper(canonical)+" ", "", "", "owner")
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM users WHERE id = $1`, created.ID)

	// CreateUser must have STORED the canonical (lower-cased, trimmed) form.
	assert.Equal(t, canonical, created.Email, "CreateUser must store the normalised email")

	// Every casing/whitespace variant must resolve to the same row — this
	// is what makes the /claim guard sound.
	for _, variant := range []string{
		canonical,
		strings.ToUpper(canonical),
		"  " + canonical + "  ",
		strings.Title(canonical), //nolint:staticcheck // intentional casing variant
	} {
		got, lookupErr := models.GetUserByEmail(ctx, db, variant)
		require.NoErrorf(t, lookupErr, "GetUserByEmail(%q) must find the user", variant)
		assert.Equalf(t, created.ID, got.ID, "GetUserByEmail(%q) must return the same user row", variant)
	}
}

// TestUsersEmailLowerUniqueIndex asserts migration 051's UNIQUE index on
// lower(email) is present and actually rejects a case-variant duplicate at
// the DB layer — the data-integrity backstop behind the handler fix.
func TestUsersEmailLowerUniqueIndex(t *testing.T) {
	requireDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	base := "dupe-" + uuid.NewString()[:8] + "@example.com"
	u1, err := models.CreateUser(ctx, db, teamID, base, "", "", "owner")
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM users WHERE id = $1`, u1.ID)

	// A raw INSERT with an upper-cased email must be rejected by the
	// unique lower(email) index — even though it bypasses the model layer.
	_, rawErr := db.ExecContext(ctx,
		`INSERT INTO users (team_id, email, role) VALUES ($1, $2, 'member')`,
		teamID, strings.ToUpper(base))
	require.Error(t, rawErr, "uq_users_email_lower must reject a case-variant duplicate")
	assert.Contains(t, strings.ToLower(rawErr.Error()), "uq_users_email_lower",
		"the rejection must come from the unique lower(email) index")
}
