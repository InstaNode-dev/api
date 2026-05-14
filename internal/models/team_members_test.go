package models_test

// team_members_test.go — model-level coverage for FIX-F's new helpers:
//
//   PromoteMemberToPrimary  — atomic + concurrency-safe transfer
//   UpdateMemberRole        — owner role refused, unknown role refused
//   RemoveMember            — is_primary protection (finding #49)
//
// Skips when TEST_DATABASE_URL is unset (matches users_is_primary_test.go).

import (
	"context"
	"database/sql"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

func requireDBMembers(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("team_members_test: TEST_DATABASE_URL not set — skipping integration test")
	}
}

func seedTeamWithOwner(t *testing.T, db *sql.DB) (uuid.UUID, uuid.UUID) {
	t.Helper()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	owner, err := models.CreateUser(context.Background(), db, teamID,
		testhelpers.UniqueEmail(t), "", "", "owner")
	require.NoError(t, err)
	return teamID, owner.ID
}

// ─────────────────────────────────────────────────────────────────────────
// PromoteMemberToPrimary — atomic transfer
// ─────────────────────────────────────────────────────────────────────────

func TestPromoteMemberToPrimary_AtomicTransfer(t *testing.T) {
	requireDBMembers(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	teamID, ownerID := seedTeamWithOwner(t, db)
	target, err := models.CreateUser(ctx, db, teamID, testhelpers.UniqueEmail(t), "", "", "admin")
	require.NoError(t, err)

	require.NoError(t, models.PromoteMemberToPrimary(ctx, db, teamID, target.ID))

	var primaryCount int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM users WHERE team_id = $1 AND is_primary = true`, teamID).Scan(&primaryCount))
	assert.Equal(t, 1, primaryCount)

	var role string
	var isPrimary bool
	require.NoError(t, db.QueryRow(`SELECT role, is_primary FROM users WHERE id = $1`, target.ID).Scan(&role, &isPrimary))
	assert.True(t, isPrimary)
	assert.Equal(t, "owner", role)

	require.NoError(t, db.QueryRow(`SELECT role, is_primary FROM users WHERE id = $1`, ownerID).Scan(&role, &isPrimary))
	assert.False(t, isPrimary)
	assert.Equal(t, "admin", role)
}

// TestPromoteMemberToPrimary_ConcurrentPromotesExactlyOneWins drives two
// goroutines racing to promote different targets. The partial unique index
// uq_users_one_primary_per_team plus the FOR UPDATE lock in the model
// guarantees the table never observes a two-primary state.
func TestPromoteMemberToPrimary_ConcurrentPromotesExactlyOneWins(t *testing.T) {
	requireDBMembers(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	teamID, _ := seedTeamWithOwner(t, db)
	t1, err := models.CreateUser(ctx, db, teamID, testhelpers.UniqueEmail(t), "", "", "admin")
	require.NoError(t, err)
	t2, err := models.CreateUser(ctx, db, teamID, testhelpers.UniqueEmail(t), "", "", "admin")
	require.NoError(t, err)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		errs[0] = models.PromoteMemberToPrimary(ctx, db, teamID, t1.ID)
	}()
	go func() {
		defer wg.Done()
		errs[1] = models.PromoteMemberToPrimary(ctx, db, teamID, t2.ID)
	}()
	wg.Wait()

	var primaryCount int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM users WHERE team_id = $1 AND is_primary = true`, teamID).Scan(&primaryCount))
	assert.Equal(t, 1, primaryCount, "exactly one primary per team is the load-bearing invariant")

	var primaryID uuid.UUID
	var primaryRole string
	require.NoError(t, db.QueryRow(`SELECT id, role FROM users WHERE team_id = $1 AND is_primary = true`, teamID).Scan(&primaryID, &primaryRole))
	assert.Contains(t, []uuid.UUID{t1.ID, t2.ID}, primaryID, "winner must be one of the two contenders")
	assert.Equal(t, "owner", primaryRole, "primary winner must also hold the owner role")

	_ = errs
}

func TestPromoteMemberToPrimary_TargetNotOnTeam(t *testing.T) {
	requireDBMembers(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	teamID, _ := seedTeamWithOwner(t, db)

	err := models.PromoteMemberToPrimary(ctx, db, teamID, uuid.New())
	assert.ErrorIs(t, err, models.ErrTargetNotOnTeam)
}

// ─────────────────────────────────────────────────────────────────────────
// UpdateMemberRole — guards
// ─────────────────────────────────────────────────────────────────────────

func TestUpdateMemberRole_RejectsOwnerAssignment(t *testing.T) {
	requireDBMembers(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	teamID, _ := seedTeamWithOwner(t, db)
	target, err := models.CreateUser(ctx, db, teamID, testhelpers.UniqueEmail(t), "", "", "developer")
	require.NoError(t, err)

	_, err = models.UpdateMemberRole(ctx, db, teamID, target.ID, "owner")
	assert.ErrorIs(t, err, models.ErrCannotAssignOwnerRole)
}

func TestUpdateMemberRole_RejectsUnknownRole(t *testing.T) {
	requireDBMembers(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	teamID, _ := seedTeamWithOwner(t, db)
	target, err := models.CreateUser(ctx, db, teamID, testhelpers.UniqueEmail(t), "", "", "developer")
	require.NoError(t, err)

	_, err = models.UpdateMemberRole(ctx, db, teamID, target.ID, "superadmin")
	assert.ErrorIs(t, err, models.ErrInvalidMemberRole)
}

func TestUpdateMemberRole_TargetNotOnTeam(t *testing.T) {
	requireDBMembers(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	teamID, _ := seedTeamWithOwner(t, db)

	_, err := models.UpdateMemberRole(ctx, db, teamID, uuid.New(), "admin")
	assert.ErrorIs(t, err, models.ErrTargetNotOnTeam)
}

// ─────────────────────────────────────────────────────────────────────────
// RemoveMember — primary protection (finding #49)
// ─────────────────────────────────────────────────────────────────────────

func TestRemoveMember_RefusesPrimary_EvenWhenRoleIsNotOwner(t *testing.T) {
	requireDBMembers(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	teamID, ownerID := seedTeamWithOwner(t, db)

	// Demote the primary's role to 'admin' but keep is_primary=true.
	_, err := db.Exec(`UPDATE users SET role = 'admin' WHERE id = $1`, ownerID)
	require.NoError(t, err)

	_, err = models.RemoveMember(ctx, db, teamID, ownerID)
	assert.ErrorIs(t, err, models.ErrCannotRemovePrimary)
}

func TestRemoveMember_ReturnsOrphanTeamID(t *testing.T) {
	requireDBMembers(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	teamID, _ := seedTeamWithOwner(t, db)
	target, err := models.CreateUser(ctx, db, teamID, testhelpers.UniqueEmail(t), "", "", "developer")
	require.NoError(t, err)

	orphan, err := models.RemoveMember(ctx, db, teamID, target.ID)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, orphan)

	var nowTeam uuid.UUID
	var role string
	var isPrimary bool
	require.NoError(t, db.QueryRow(`SELECT team_id, role, is_primary FROM users WHERE id = $1`, target.ID).Scan(&nowTeam, &role, &isPrimary))
	assert.Equal(t, orphan, nowTeam)
	assert.Equal(t, "owner", role)
	assert.True(t, isPrimary)
}
