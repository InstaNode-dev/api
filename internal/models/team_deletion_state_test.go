package models_test

// team_deletion_state_test.go — coverage for the team-deletion state
// machine helpers in team_deletion.go, with emphasis on the
// 'deletion_pending' intermediate status added by migration 054.
//
// Skips when TEST_DATABASE_URL is unset (requireDB) — the DB-connection-
// refused skip is the known-acceptable CI behaviour per the task brief.

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// TestMarkTeamDeletionPending_FlipsRequestedToPending asserts the worker's
// step-0 transition: a team in deletion_requested flips to deletion_pending,
// and the helper reports won=true exactly once.
func TestMarkTeamDeletionPending_FlipsRequestedToPending(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))

	// Move the team into deletion_requested first.
	require.NoError(t, models.RequestTeamDeletion(ctx, db, teamID))

	// First MarkTeamDeletionPending wins.
	won, err := models.MarkTeamDeletionPending(ctx, db, teamID)
	require.NoError(t, err)
	assert.True(t, won, "first MarkTeamDeletionPending must win")

	var status string
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT status FROM teams WHERE id = $1`, teamID).Scan(&status))
	assert.Equal(t, models.TeamStatusDeletionPending, status)

	// Second call is idempotent: 0 rows affected → won=false, no error.
	won2, err := models.MarkTeamDeletionPending(ctx, db, teamID)
	require.NoError(t, err)
	assert.False(t, won2, "re-running MarkTeamDeletionPending must report won=false (idempotent)")
}

// TestRestoreTeam_RefusesDeletionPending is the critical safety property:
// once destruction has begun (status='deletion_pending'), the restore
// endpoint must NOT resurrect the team — its customer DBs may already be
// dropped. RestoreTeam only matches status='deletion_requested', so a
// deletion_pending row returns ErrTeamNotPendingDeletion.
func TestRestoreTeam_RefusesDeletionPending(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))

	require.NoError(t, models.RequestTeamDeletion(ctx, db, teamID))
	won, err := models.MarkTeamDeletionPending(ctx, db, teamID)
	require.NoError(t, err)
	require.True(t, won)

	// Restore must refuse — destruction has started.
	err = models.RestoreTeam(ctx, db, teamID)
	require.Error(t, err, "RestoreTeam must refuse a deletion_pending team")
	assert.ErrorIs(t, err, models.ErrTeamNotPendingDeletion)

	// The team is still deletion_pending — restore did not flip it back.
	var status string
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT status FROM teams WHERE id = $1`, teamID).Scan(&status))
	assert.Equal(t, models.TeamStatusDeletionPending, status,
		"a refused restore must leave the team in deletion_pending")
}

// TestRequestTeamDeletion_Idempotent — a redelivered DELETE (retry storm,
// browser refresh) hits the WHERE status='active' guard and returns
// ErrTeamNotPendingDeletion rather than double-stamping the timestamp.
func TestRequestTeamDeletion_Idempotent(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))

	require.NoError(t, models.RequestTeamDeletion(ctx, db, teamID))
	// Second call — team is no longer 'active'.
	err := models.RequestTeamDeletion(ctx, db, teamID)
	assert.ErrorIs(t, err, models.ErrTeamNotPendingDeletion,
		"a redelivered RequestTeamDeletion must return ErrTeamNotPendingDeletion")
}
