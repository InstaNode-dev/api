package handlers_test

// deploy_ttl_guards_test.go — bug-bash #3/#5/#6: SetTTL must refuse to flip a
// permanent deploy back to an expiring TTL (409 already_permanent) and refuse a
// terminal deploy (409 invalid_state); the model's WHERE-guard is the
// defense-in-depth backstop for the permanent case. Reuses the
// seedDeploy/patchEnvApp/requireCoverageDB harness in deploy_stack_coverage_test.go.

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// TestSetTTL_PermanentRejected: make a deploy permanent, then SetTTL → 409
// already_permanent, and the row stays permanent (expires_at NULL).
func TestSetTTL_PermanentRejected(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	deployID, _ := seedDeploy(t, db, teamID, "healthy", "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "ttlperm@example.com")
	app, _ := patchEnvApp(t, db)

	// Make it permanent first.
	mp := httptest.NewRequest(http.MethodPost, "/api/v1/deployments/"+deployID.String()+"/make-permanent", nil)
	mp.Header.Set("Authorization", "Bearer "+jwt)
	mpResp, err := app.Test(mp, 5000)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, mpResp.StatusCode)
	_ = mpResp.Body.Close()

	// SetTTL must now 409.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/deployments/"+deployID.String()+"/ttl",
		strings.NewReader(`{"hours":48}`))
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "SetTTL on a permanent deploy must 409")

	// Row stayed permanent.
	var policy string
	var expiresAt sql.NullTime
	require.NoError(t, db.QueryRow(`SELECT ttl_policy, expires_at FROM deployments WHERE id=$1`, deployID).Scan(&policy, &expiresAt))
	assert.Equal(t, "permanent", policy)
	assert.False(t, expiresAt.Valid, "expires_at must stay NULL")
}

// TestSetTTL_TerminalRejected: a terminal (expired) deploy → 409 invalid_state.
func TestSetTTL_TerminalRejected(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	deployID, _ := seedDeploy(t, db, teamID, "expired", "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "ttlterm@example.com")
	app, _ := patchEnvApp(t, db)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/deployments/"+deployID.String()+"/ttl",
		strings.NewReader(`{"hours":48}`))
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "SetTTL on a terminal deploy must 409")
}

// TestSetDeploymentTTL_PermanentGuard: the model WHERE-guard leaves a permanent
// row untouched even if called directly (the race backstop, #6).
func TestSetDeploymentTTL_PermanentGuard(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	deployID, _ := seedDeploy(t, db, teamID, "healthy", "pro")
	_, err := db.Exec(`UPDATE deployments SET ttl_policy='permanent', expires_at=NULL WHERE id=$1`, deployID)
	require.NoError(t, err)

	// Direct model call must NOT flip the permanent row.
	require.NoError(t, models.SetDeploymentTTL(context.Background(), db, deployID, 24))
	var policy string
	var expiresAt sql.NullTime
	require.NoError(t, db.QueryRow(`SELECT ttl_policy, expires_at FROM deployments WHERE id=$1`, deployID).Scan(&policy, &expiresAt))
	assert.Equal(t, "permanent", policy, "WHERE guard must leave a permanent deploy untouched")
	assert.False(t, expiresAt.Valid)
}
