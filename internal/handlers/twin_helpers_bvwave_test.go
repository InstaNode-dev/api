package handlers_test

// twin_helpers_bvwave_test.go — covers the cheap-but-uncovered twin.go arms:
//   - NewTwinHandler nil-arg panic (62)
//   - beginTwinApproval missing-email 400 (417): a JWT with no email claim
//     reaching the non-dev-env approval gate.
//
// The ProvisionForTwin dispatch arms (267/280/293) require a fully-wired
// provisioner (real customer DB) and are covered by the live twin happy-path
// suite when postgres-customers is reachable; under the redis-only test app
// they 503 before the success branch, the same limitation the existing
// twin_test.go happy path documents.

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/testhelpers"
)

func TestNewTwinHandler_NilArgsPanic_bvwave(t *testing.T) {
	assert.Panics(t, func() {
		handlers.NewTwinHandler(nil, nil, nil)
	})
}

func TestTwin_BeginApproval_MissingEmail_400_bvwave(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	// JWT with an EMPTY email claim → beginTwinApproval's requestedBy=="" arm.
	var userID string
	require.NoError(t, db.QueryRow(
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id`,
		teamID, testhelpers.UniqueEmail(t)).Scan(&userID))
	jwt := testhelpers.MustSignSessionJWT(t, userID, teamID, "") // no email

	_, sourceToken := seedTwinSource(t, db, teamID, "postgres", "pro")

	// Non-dev env, no approval_id → approval gate → beginTwinApproval →
	// missing email → 400 missing_email.
	resp := postTwin(t, app, sourceToken, jwt, map[string]any{"env": "staging"})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}
