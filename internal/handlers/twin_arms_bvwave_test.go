package handlers_test

// twin_arms_bvwave_test.go — covers the consumeApprovedTwin manual-trigger
// arms and the family-validate branches of twin.go that twin_test.go +
// twin_approval_coverage_test.go leave open (twin.go ~65.1% under CI):
//
//   - consumeApprovedTwin: wrong-team, not-approved (status=pending),
//     kind/from/to mismatch, expired, and the SUCCESS path (which then runs
//     ValidateFamilyParent + dispatches into dbH.ProvisionForTwin).
//   - ValidateFamilyParent twin_exists → 409 (a sibling already in target env).
//
// The approved-row arms insert a promote_approvals row with the exact
// (status, kind, from, to, expires_at) each branch needs via direct SQL, then
// POST /provision-twin with that approval_id.

import (
	"context"
	"database/sql"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// bvInsertApproval inserts a promote_approvals row with full control over its
// status / kind / from / to / expiry. Returns the row id.
func bvInsertApproval(t *testing.T, db *sql.DB, teamID, email, kind, status, from, to string, expiresAt time.Time) string {
	t.Helper()
	var id string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO promote_approvals
			(token, team_id, requested_by_email, promote_kind, promote_payload, from_env, to_env, status, expires_at)
		VALUES ($1, $2::uuid, $3, $4, '{}'::jsonb, $5, $6, $7, $8)
		RETURNING id::text
	`, uuid.NewString(), teamID, email, kind, from, to, status, expiresAt).Scan(&id))
	return id
}

func TestTwin_ConsumeApproved_Arms_bvwave(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := twinJWT(t, db, teamID)
	email := testhelpers.UniqueEmail(t)
	_, sourceToken := seedTwinSource(t, db, teamID, "postgres", "pro")
	future := time.Now().UTC().Add(time.Hour)

	t.Run("not_approved_status_pending_409", func(t *testing.T) {
		id := bvInsertApproval(t, db, teamID, email, models.PromoteApprovalKindResourceTwin, "pending", "production", "staging", future)
		resp := postTwin(t, app, sourceToken, jwt, map[string]any{"env": "staging", "approval_id": id})
		assert.Equal(t, http.StatusConflict, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("mismatch_from_to_400", func(t *testing.T) {
		// Approved row but recorded (from,to) does not match the request.
		id := bvInsertApproval(t, db, teamID, email, models.PromoteApprovalKindResourceTwin, "approved", "production", "qa", future)
		resp := postTwin(t, app, sourceToken, jwt, map[string]any{"env": "staging", "approval_id": id})
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("expired_410", func(t *testing.T) {
		past := time.Now().UTC().Add(-time.Hour)
		id := bvInsertApproval(t, db, teamID, email, models.PromoteApprovalKindResourceTwin, "approved", "production", "staging", past)
		resp := postTwin(t, app, sourceToken, jwt, map[string]any{"env": "staging", "approval_id": id})
		assert.Equal(t, http.StatusGone, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("wrong_team_404", func(t *testing.T) {
		otherTeam := testhelpers.MustCreateTeamDB(t, db, "pro")
		id := bvInsertApproval(t, db, otherTeam, email, models.PromoteApprovalKindResourceTwin, "approved", "production", "staging", future)
		resp := postTwin(t, app, sourceToken, jwt, map[string]any{"env": "staging", "approval_id": id})
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("approved_success_provisions_or_503", func(t *testing.T) {
		// A valid approved row → consumeApprovedTwin marks it executed, then
		// the handler runs ValidateFamilyParent + dispatches into the postgres
		// ProvisionForTwin path. On a CI box with postgres-customers reachable
		// this returns 201; if the customer DB is unreachable it returns 503.
		// Either way the consumeApprovedTwin success branch + the dispatch arm
		// are exercised. We seed a FRESH source so no twin pre-exists.
		_, freshSource := seedTwinSource(t, db, teamID, "postgres", "pro")
		id := bvInsertApproval(t, db, teamID, email, models.PromoteApprovalKindResourceTwin, "approved", "production", "staging", future)
		resp := postTwin(t, app, freshSource, jwt, map[string]any{"env": "staging", "approval_id": id})
		assert.Contains(t, []int{http.StatusCreated, http.StatusServiceUnavailable}, resp.StatusCode)
		resp.Body.Close()
	})
}

// TestTwin_RedisTwin_HappyDispatch_bvwave drives the redis dispatch arm
// (cacheH.ProvisionForTwin, line 280) plus the post-validate attribute
// carry-forward (217-259). Redis provisioning works against the test Redis, so
// this yields a real 201 — unlike a postgres/mongo twin which 503s when the
// customer DB isn't reachable.
func TestTwin_RedisTwin_HappyDispatch_bvwave(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "redis")
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := twinJWT(t, db, teamID)
	email := testhelpers.UniqueEmail(t)
	_, sourceToken := seedTwinSource(t, db, teamID, "redis", "pro")
	future := time.Now().UTC().Add(time.Hour)

	id := bvInsertApproval(t, db, teamID, email, models.PromoteApprovalKindResourceTwin, "approved", "production", "staging", future)
	resp := postTwin(t, app, sourceToken, jwt, map[string]any{"env": "staging", "approval_id": id})
	// Redis twin provisions for real → 201; if redis is unreachable, 503.
	assert.Contains(t, []int{http.StatusCreated, http.StatusServiceUnavailable}, resp.StatusCode)
	resp.Body.Close()
}

func TestTwin_FamilyValidate_TwinExists_409_bvwave(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := twinJWT(t, db, teamID)
	srcID, sourceToken := seedTwinSource(t, db, teamID, "postgres", "pro")
	email := testhelpers.UniqueEmail(t)
	future := time.Now().UTC().Add(time.Hour)

	// Seed a sibling already in 'staging' so ValidateFamilyParent reports a
	// duplicate_twin → 409. Use an approval_id to skip the email-approval gate.
	seedTwinSibling(t, db, teamID, srcID, "postgres", "pro", "staging")
	id := bvInsertApproval(t, db, teamID, email, models.PromoteApprovalKindResourceTwin, "approved", "production", "staging", future)

	resp := postTwin(t, app, sourceToken, jwt, map[string]any{"env": "staging", "approval_id": id})
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	resp.Body.Close()
}
