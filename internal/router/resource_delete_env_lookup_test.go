package router_test

// resource_delete_env_lookup_test.go — drives the DELETE /api/v1/resources/:id
// route through the REAL router so the WithEnvLookup closure wired in
// router.go (the `return handlers.ResourceEnvByTokenOrIDForMiddleware(c, db)`
// line) executes under unit coverage, not just E2E. Wave-2 A1 renamed that
// helper (token-or-id resolution); this test pins the wiring:
//
//   - an authenticated DELETE addressed by the resource's ROW ID resolves
//     through the env-lookup (id fallback) and soft-deletes the row, and
//   - a second DELETE on the same (now-deleted) row reports idempotent
//     success — proving the closure's fail-open path also routes through.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"instant.dev/internal/email"
	"instant.dev/internal/plans"
	"instant.dev/internal/router"
	"instant.dev/internal/testhelpers"
)

func TestRouter_ResourceDelete_ByRowID_EnvLookupWired(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	rdb, rdbClean := testhelpers.SetupTestRedis(t)
	defer rdbClean()

	cfg := newRouterTestConfig()
	app := router.New(cfg, db, rdb, nil, email.NewNoop(), plans.Default(), nil, nil)

	// Seed a team + user + an active resource owned by the team.
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, testhelpers.UniqueEmail(t)).Scan(&userID))
	jwt := testhelpers.MustSignSessionJWT(t, userID, teamID, "router-del@example.com")

	var rowID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO resources (team_id, resource_type, tier, env, status)
		 VALUES ($1::uuid, 'webhook', 'pro', 'staging', 'active')
		 RETURNING id::text`, teamID).Scan(&rowID))

	doDelete := func() *http.Response {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/resources/"+rowID, nil)
		req.Header.Set("Authorization", "Bearer "+jwt)
		resp, err := app.Test(req, 15000)
		require.NoError(t, err)
		return resp
	}

	// DELETE by ROW ID through the real router: env-policy middleware runs
	// the token-or-id env lookup, then the handler resolves + deletes.
	resp := doDelete()
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"DELETE by row id through the real router must succeed")

	var status string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT status FROM resources WHERE id = $1::uuid`, rowID).Scan(&status))
	require.Equal(t, "deleted", status)

	// Idempotent retry: the row is now 'deleted'; the env lookup still runs
	// (resolves the deleted row) and the handler reports already_deleted.
	resp2 := doDelete()
	defer resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode,
		"repeat DELETE must be idempotent success")
}
