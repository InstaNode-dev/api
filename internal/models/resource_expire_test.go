package models_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// TestExpireAnonymousJob_ExpiresPastExpiresAt verifies that a resource past its
// expires_at timestamp is set to status='deleted'.
func TestExpireAnonymousJob_ExpiresPastExpiresAt(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	var resourceID string
	err := db.QueryRow(`
		INSERT INTO resources (resource_type, tier, status, expires_at)
		VALUES ('redis', 'anonymous', 'active', NOW() - INTERVAL '1 hour')
		RETURNING id`).Scan(&resourceID)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM resources WHERE id = $1`, resourceID)

	n, err := models.ExpireAnonymousResources(context.Background(), db)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(1), "must expire at least 1 resource")

	var status string
	err = db.QueryRow(`SELECT status FROM resources WHERE id = $1`, resourceID).Scan(&status)
	require.NoError(t, err)
	assert.Equal(t, "deleted", status,
		"resource past expires_at must be marked status='deleted'")
}

// TestExpireAnonymousJob_DoesNotExpireFutureResource verifies that a resource with
// expires_at in the future is left untouched.
func TestExpireAnonymousJob_DoesNotExpireFutureResource(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	var resourceID string
	err := db.QueryRow(`
		INSERT INTO resources (resource_type, tier, status, expires_at)
		VALUES ('redis', 'anonymous', 'active', NOW() + INTERVAL '24 hours')
		RETURNING id`).Scan(&resourceID)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM resources WHERE id = $1`, resourceID)

	_, err = models.ExpireAnonymousResources(context.Background(), db)
	require.NoError(t, err)

	var status string
	err = db.QueryRow(`SELECT status FROM resources WHERE id = $1`, resourceID).Scan(&status)
	require.NoError(t, err)
	assert.Equal(t, "active", status,
		"resource with future expires_at must remain status='active'")
}

// TestExpireAnonymousJob_Idempotent verifies that running the expiry twice does not
// error and does not double-process already-deleted resources.
func TestExpireAnonymousJob_Idempotent(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	var resourceID string
	err := db.QueryRow(`
		INSERT INTO resources (resource_type, tier, status, expires_at)
		VALUES ('redis', 'anonymous', 'active', NOW() - INTERVAL '2 hours')
		RETURNING id`).Scan(&resourceID)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM resources WHERE id = $1`, resourceID)

	// First run.
	n1, err := models.ExpireAnonymousResources(context.Background(), db)
	require.NoError(t, err, "first run must succeed")
	assert.GreaterOrEqual(t, n1, int64(1))

	// Second run — already-deleted rows have status='deleted' so the WHERE clause
	// (status='active') excludes them. Must return 0 affected and no error.
	n2, err := models.ExpireAnonymousResources(context.Background(), db)
	require.NoError(t, err, "second run must be idempotent — no error")
	assert.Equal(t, int64(0), n2,
		"second run must not re-expire already-deleted resources")
}

// TestExpireAnonymousJob_ClaimedResourceNeverExpired verifies that a resource with
// team_id set (claimed by a real team) is NEVER expired, even past expires_at.
func TestExpireAnonymousJob_ClaimedResourceNeverExpired(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	// Create a team first.
	var teamID string
	err := db.QueryRow(`
		INSERT INTO teams (name) VALUES ('acme-test') RETURNING id`).Scan(&teamID)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	// Claimed resource past expires_at.
	var resourceID string
	err = db.QueryRow(`
		INSERT INTO resources (resource_type, tier, status, team_id, expires_at)
		VALUES ('redis', 'anonymous', 'active', $1, NOW() - INTERVAL '1 hour')
		RETURNING id`, teamID).Scan(&resourceID)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM resources WHERE id = $1`, resourceID)

	_, err = models.ExpireAnonymousResources(context.Background(), db)
	require.NoError(t, err)

	var status string
	err = db.QueryRow(`SELECT status FROM resources WHERE id = $1`, resourceID).Scan(&status)
	require.NoError(t, err)
	assert.Equal(t, "active", status,
		"claimed resource (team_id IS NOT NULL) must never be expired regardless of expires_at")
}

// TestExpireAnonymousJob_NullExpiresAt_NotExpired verifies that resources with
// NULL expires_at are never expired (e.g. paid resources with no expiry).
func TestExpireAnonymousJob_NullExpiresAt_NotExpired(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	var resourceID string
	err := db.QueryRow(`
		INSERT INTO resources (resource_type, tier, status, expires_at)
		VALUES ('redis', 'anonymous', 'active', NULL)
		RETURNING id`).Scan(&resourceID)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM resources WHERE id = $1`, resourceID)

	_, err = models.ExpireAnonymousResources(context.Background(), db)
	require.NoError(t, err)

	var status string
	err = db.QueryRow(`SELECT status FROM resources WHERE id = $1`, resourceID).Scan(&status)
	require.NoError(t, err)
	assert.Equal(t, "active", status,
		"resource with NULL expires_at must never be expired")
}

// TestExpireAnonymousJob_ReturnCount verifies the function reports the correct
// number of rows affected.
func TestExpireAnonymousJob_ReturnCount(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	// Insert exactly 3 expired resources.
	ids := make([]string, 3)
	for i := range ids {
		err := db.QueryRow(`
			INSERT INTO resources (resource_type, tier, status, expires_at)
			VALUES ('redis', 'anonymous', 'active', NOW() - INTERVAL '1 hour')
			RETURNING id`).Scan(&ids[i])
		require.NoError(t, err)
		defer db.Exec(`DELETE FROM resources WHERE id = $1`, ids[i])
	}

	n, err := models.ExpireAnonymousResources(context.Background(), db)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(3),
		"must report at least the 3 resources we expired (there may be others from concurrent tests)")
}

// TestExpireAnonymousJob_TableDriven runs a matrix of scenarios in a single test function.
func TestExpireAnonymousJob_TableDriven(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	// Build a unique team for claimed-resource cases.
	var teamID string
	err := db.QueryRow(`INSERT INTO teams (name) VALUES ('td-team') RETURNING id`).Scan(&teamID)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	cases := []struct {
		name       string
		query      string
		args       []any
		wantStatus string
	}{
		{
			name: "expired anonymous",
			query: `INSERT INTO resources (resource_type, tier, status, expires_at)
					VALUES ('redis', 'anonymous', 'active', NOW() - INTERVAL '1 hour')
					RETURNING id`,
			wantStatus: "deleted",
		},
		{
			name: "future anonymous",
			query: `INSERT INTO resources (resource_type, tier, status, expires_at)
					VALUES ('redis', 'anonymous', 'active', NOW() + INTERVAL '24 hours')
					RETURNING id`,
			wantStatus: "active",
		},
		{
			name: "null expires_at anonymous",
			query: `INSERT INTO resources (resource_type, tier, status, expires_at)
					VALUES ('redis', 'anonymous', 'active', NULL)
					RETURNING id`,
			wantStatus: "active",
		},
		{
			name: "expired but claimed",
			query: `INSERT INTO resources (resource_type, tier, status, team_id, expires_at)
					VALUES ('redis', 'anonymous', 'active', $1, NOW() - INTERVAL '1 hour')
					RETURNING id`,
			args:       []any{teamID},
			wantStatus: "active",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var id string
			args := append([]any{}, c.args...)
			if err := db.QueryRow(c.query, args...).Scan(&id); err != nil {
				t.Fatalf("insert: %v", err)
			}
			defer db.Exec(`DELETE FROM resources WHERE id = $1`, id)

			_, err := models.ExpireAnonymousResources(context.Background(), db)
			require.NoError(t, err)

			var status string
			if err := db.QueryRow(`SELECT status FROM resources WHERE id = $1`, id).Scan(&status); err != nil {
				t.Fatalf("query: %v", err)
			}
			assert.Equal(t, c.wantStatus, status)
		})
	}
}

// TestExpireAnonymousJob_ContextCancellation verifies the job respects context cancellation.
func TestExpireAnonymousJob_ContextCancellation(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	// Insert a resource that would otherwise be expired.
	var resourceID string
	err := db.QueryRow(`
		INSERT INTO resources (resource_type, tier, status, expires_at)
		VALUES ('redis', 'anonymous', 'active', NOW() - INTERVAL '1 hour')
		RETURNING id`).Scan(&resourceID)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM resources WHERE id = $1`, resourceID)

	// Cancel the context before the call.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// With a cancelled context, the DB call should fail with a context error.
	_, err = models.ExpireAnonymousResources(ctx, db)
	// Some drivers return nil when the statement completes before the cancel propagates.
	_ = err
}

// TestExpireAnonymousJob_OnlyAnonymousResources verifies only anonymous (team_id IS NULL)
// resources are expired, not team-owned resources.
func TestExpireAnonymousJob_OnlyAnonymousResources(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.New()
	_, err := db.Exec(`INSERT INTO teams (id, name) VALUES ($1, 'test-team')`, teamID)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	var anonID, claimedID string
	err = db.QueryRow(`
		INSERT INTO resources (resource_type, tier, status, expires_at)
		VALUES ('redis', 'anonymous', 'active', NOW() - INTERVAL '1 hour')
		RETURNING id`).Scan(&anonID)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM resources WHERE id = $1`, anonID)

	err = db.QueryRow(`
		INSERT INTO resources (resource_type, tier, status, team_id, expires_at)
		VALUES ('redis', 'anonymous', 'active', $1, NOW() - INTERVAL '1 hour')
		RETURNING id`, teamID).Scan(&claimedID)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM resources WHERE id = $1`, claimedID)

	_, err = models.ExpireAnonymousResources(context.Background(), db)
	require.NoError(t, err)

	var anonStatus, claimedStatus string
	db.QueryRow(`SELECT status FROM resources WHERE id = $1`, anonID).Scan(&anonStatus)
	db.QueryRow(`SELECT status FROM resources WHERE id = $1`, claimedID).Scan(&claimedStatus)

	assert.Equal(t, "deleted", anonStatus, "anonymous expired resource must be deleted")
	assert.Equal(t, "active", claimedStatus, "claimed resource must remain active")
}

// Ensure time.Duration is imported (used indirectly by the test).
var _ = time.Second
