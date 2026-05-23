package handlers_test

// internal_terminate_final_test.go — FINAL coverage pass for
// internal_terminate.go's Terminate DB-error arms + the invalid-team-id arm.
// Uses openFaultDB (staged failAfter) so the JWT-auth passes (no DB) and the
// targeted DB call is the one that errors.

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// invalid :id → invalid_team_id (internal_terminate.go:103).
func TestInternalTerminateFinal_BadTeamID_400(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := newTerminateTestApp(t, db, func(string) error { return nil })
	jwt := mintInternalTerminateJWT(t, testInternalTerminateSecret, "internal_terminate", uuid.NewString(), 0)
	resp := postTerminate(t, app, "not-a-uuid", jwt)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// GetTeamByID errors → db_failed (internal_terminate.go:134). failAfter=0.
func TestInternalTerminateFinal_TeamLookup_503(t *testing.T) {
	teamID := uuid.NewString()
	faultDB := openFaultDB(t, 0)
	app := newTerminateTestApp(t, faultDB, func(string) error { return nil })
	jwt := mintInternalTerminateJWT(t, testInternalTerminateSecret, "internal_terminate", teamID, 0)
	resp := postTerminate(t, app, teamID, jwt)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// HasTerminatedPaymentGracePeriod errors → db_failed (internal_terminate.go:143).
// team(1) succeeds, idempotency check(2) errors. failAfter=1. The team must
// EXIST so we seed it on the pooled DB and run the handler on a faultdb that
// shares the same underlying postgres.
func TestInternalTerminateFinal_IdempotencyCheck_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")

	faultDB := openFaultDB(t, 1)
	app := newTerminateTestApp(t, faultDB, func(string) error { return nil })
	jwt := mintInternalTerminateJWT(t, testInternalTerminateSecret, "internal_terminate", teamID, 0)
	resp := postTerminate(t, app, teamID, jwt)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// PauseAllTeamResources errors → db_failed (internal_terminate.go:166). team(1)
// + idempotency(2) succeed, pause(3) errors. failAfter=2.
func TestInternalTerminateFinal_PauseResources_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")

	faultDB := openFaultDB(t, 2)
	app := newTerminateTestApp(t, faultDB, func(string) error { return nil })
	jwt := mintInternalTerminateJWT(t, testInternalTerminateSecret, "internal_terminate", teamID, 0)
	resp := postTerminate(t, app, teamID, jwt)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}
