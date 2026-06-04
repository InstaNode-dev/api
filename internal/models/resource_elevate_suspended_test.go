package models_test

// resource_elevate_suspended_test.go — regression coverage for the
// quota-suspend recovery trap (sweep finding #4, 2026-06-04).
//
// The worker's storage-quota enforcer flips a resource to status='suspended'
// when it exceeds its tier's storage cap. ElevateResourceTiersByTeam (called
// from the Razorpay subscription.charged webhook) previously filtered on
// status IN ('active','paused') — so a tier upgrade did NOT raise the cap on
// the suspended resource, making "upgrade to restore access" a no-op for the
// very row that tripped the limit. The fix adds 'suspended' to the filter so
// the upgrade lifts the suspended row to the new (higher-cap) tier.
//
// NOTE (worker follow-up #3): the actual unsuspend transition — flipping
// status back to 'active' and reversing the provider-side CONNECT/ACL REVOKE —
// lives in the worker, not the api. This test pins ONLY the api half: the
// suspended row's tier IS elevated.

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// insertSuspendedResourceForTest inserts a permanent (no TTL) team-owned
// resource pinned to status='suspended' so we can assert the elevation path
// reaches quota-suspended rows.
func insertSuspendedResourceForTest(t *testing.T, db *sql.DB, teamID uuid.UUID, tier string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, token, resource_type, tier, env, status, expires_at)
		VALUES ($1, $2, 'redis', $3, 'production', 'suspended', NULL)
		RETURNING id
	`, teamID, uuid.NewString(), tier).Scan(&id)
	require.NoError(t, err)
	t.Cleanup(func() { db.Exec(`DELETE FROM resources WHERE id = $1`, id) })
	return id
}

// TestElevate_Suspended_TierElevated reproduces the suspend@hobby-cap →
// upgrade-to-pro scenario: a resource the quota enforcer suspended at the
// hobby cap MUST have its tier raised to pro on upgrade, otherwise the new
// (larger) pro cap never applies to it.
func TestElevate_Suspended_TierElevated(t *testing.T) {
	requireDBElevate(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	// Resource was at hobby tier and got suspended for exceeding the hobby cap.
	resourceID := insertSuspendedResourceForTest(t, db, teamID, "hobby")

	err := models.ElevateResourceTiersByTeam(context.Background(), db, teamID, "pro")
	require.NoError(t, err)

	var tier, status string
	err = db.QueryRow(`SELECT tier, status FROM resources WHERE id = $1`, resourceID).
		Scan(&tier, &status)
	require.NoError(t, err)
	assert.Equal(t, "pro", tier,
		"a quota-suspended resource MUST be elevated to the new tier on upgrade")
	// The api elevation raises the cap only; the status flip back to 'active'
	// (and provider re-grant) is the worker's job (#3). Pin that the api does
	// NOT itself unsuspend — so a future api-side change to also flip status
	// is a deliberate decision, not an accident.
	assert.Equal(t, "suspended", status,
		"api elevation raises the tier only; the unsuspend status flip is the worker's job (#3)")
}

// TestElevate_SuspendedFilterIncludesSuspended is the registry-style guard for
// the status filter itself: it inserts one resource per relevant non-terminal
// status (active, paused, suspended) and asserts ALL THREE are elevated by a
// single ElevateResourceTiersByTeam call. If a future edit drops 'suspended'
// (or any of the three) from the filter, this fails — it pins the exact set
// the elevation must cover, not a hand-typed assertion on one row.
func TestElevate_SuspendedFilterIncludesSuspended(t *testing.T) {
	requireDBElevate(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))

	statuses := []string{"active", "paused", "suspended"}
	ids := make(map[string]uuid.UUID, len(statuses))
	for _, st := range statuses {
		var id uuid.UUID
		err := db.QueryRowContext(context.Background(), `
			INSERT INTO resources (team_id, token, resource_type, tier, env, status, expires_at)
			VALUES ($1, $2, 'redis', 'hobby', 'production', $3, NULL)
			RETURNING id
		`, teamID, uuid.NewString(), st).Scan(&id)
		require.NoError(t, err)
		ids[st] = id
		t.Cleanup(func() { db.Exec(`DELETE FROM resources WHERE id = $1`, id) })
	}

	err := models.ElevateResourceTiersByTeam(context.Background(), db, teamID, "pro")
	require.NoError(t, err)

	for _, st := range statuses {
		var tier string
		require.NoError(t, db.QueryRow(`SELECT tier FROM resources WHERE id = $1`, ids[st]).Scan(&tier))
		assert.Equalf(t, "pro", tier,
			"resource with status=%q must be elevated by ElevateResourceTiersByTeam", st)
	}
}
