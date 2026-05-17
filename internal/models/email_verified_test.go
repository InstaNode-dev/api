package models_test

// email_verified_test.go — coverage for the users.email_verified flag
// (migration 052) and its model-layer accessors.
//
// DECISION (2026-05-17): POST /claim mints a session for a brand-new-account
// email but does NOT prove inbox ownership, so /claim-created users are
// email_verified=false; magic-link + OAuth logins flip it true; billing
// actions are gated on the flag. These tests pin the model-layer half of
// that contract:
//   - CreateUser inserts every new row with email_verified=false.
//   - SetEmailVerified flips it true and is idempotent.
//   - The invitation-accept path creates verified=true users (the invitee
//     proved inbox control by receiving the invite email).
//
// All tests skip when TEST_DATABASE_URL is unset — they require a real DB.
// requireDB is shared with the other models_test files (resource_env_test.go).

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// TestCreateUser_EmailVerifiedDefaultsFalse pins the safe default: every row
// CreateUser writes starts unverified. This is the /claim contract — a
// claim-created account must NOT be able to skip the billing email gate.
func TestCreateUser_EmailVerifiedDefaultsFalse(t *testing.T) {
	requireDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "free"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	email := "claimuser-" + uuid.NewString()[:8] + "@example.com"
	u, err := models.CreateUser(ctx, db, teamID, email, "", "", "owner")
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM users WHERE id = $1`, u.ID)

	assert.False(t, u.EmailVerified,
		"CreateUser must return a user with email_verified=false")

	// Re-read from the DB to confirm the column itself, not just the struct.
	got, err := models.GetUserByID(ctx, db, u.ID)
	require.NoError(t, err)
	assert.False(t, got.EmailVerified,
		"a freshly created user row must have email_verified=false in the DB")
}

// TestSetEmailVerified_FlipsTrueAndIsIdempotent pins the verify path used by
// magic-link + OAuth logins: SetEmailVerified flips the flag true, and a
// second call is a harmless no-op.
func TestSetEmailVerified_FlipsTrueAndIsIdempotent(t *testing.T) {
	requireDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "free"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	email := "verifyme-" + uuid.NewString()[:8] + "@example.com"
	u, err := models.CreateUser(ctx, db, teamID, email, "", "", "owner")
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM users WHERE id = $1`, u.ID)
	require.False(t, u.EmailVerified, "precondition: starts unverified")

	require.NoError(t, models.SetEmailVerified(ctx, db, u.ID))
	got, err := models.GetUserByID(ctx, db, u.ID)
	require.NoError(t, err)
	assert.True(t, got.EmailVerified, "SetEmailVerified must flip the flag true")

	// Idempotent: a second call on an already-verified user must not error.
	require.NoError(t, models.SetEmailVerified(ctx, db, u.ID),
		"SetEmailVerified must be a harmless no-op on an already-verified user")
	got2, err := models.GetUserByID(ctx, db, u.ID)
	require.NoError(t, err)
	assert.True(t, got2.EmailVerified, "flag stays true after a repeat call")
}

// TestAcceptInvitation_CreatesVerifiedUser pins that the invitation-accept
// path creates email_verified=true users — the invitee proved inbox control
// by receiving the invitation email, so they clear the billing gate.
func TestAcceptInvitation_CreatesVerifiedUser(t *testing.T) {
	requireDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	// Seed an owner so the team has an inviter.
	owner, err := models.CreateUser(ctx, db, teamID,
		"owner-"+uuid.NewString()[:8]+"@example.com", "", "", "owner")
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM users WHERE id = $1`, owner.ID)

	inviteeEmail := "invitee-" + uuid.NewString()[:8] + "@example.com"
	inv, err := models.CreateRBACInvitation(ctx, db, teamID, inviteeEmail, "developer", owner.ID)
	require.NoError(t, err)

	user, _, err := models.AcceptRBACInvitationByToken(ctx, db, inv.Token)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM users WHERE id = $1`, user.ID)

	assert.True(t, user.EmailVerified,
		"a user created by accepting an invitation must be email_verified=true")
}
