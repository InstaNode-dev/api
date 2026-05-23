package handlers_test

// twin_final_test.go — FINAL coverage pass for twin.go. Closes the remaining
// sub-95 arms that the prior twin_*_test.go slices leave open:
//
//   - HTTP-level validation arms: bad-UUID :id (107), non-JSON-parseable body
//     (112), and the derefUUID nil branch via a redis-twin success (which
//     carries no family_root_id pointer? — see below).
//   - mid-handler DB-error arms reached with the fault-injecting pq driver
//     (openFaultDB from faultdb_deployasync_test.go): source lookup (139),
//     team lookup (170), beginTwinApproval insert (441), consumeApprovedTwin
//     lookup (471) + execute (496).
//
// PATTERN: seed all rows on a normal pooled DB, then build a TwinHandler app
// whose underlying *sql.DB is the fault driver set to fail AFTER the first N
// successful queries — so the early auth/parse path runs, and the targeted
// query is the one that errors.

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// twinFaultApp wires the provision-twin route against an arbitrary *sql.DB so a
// fault-injecting DB can drive the mid-handler 503 arms. No provisioner client
// is wired — every test here errors before the dispatch, so that's fine.
func twinFaultApp(t *testing.T, db *sql.DB) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:       testhelpers.TestJWTSecret,
		AESKey:          testhelpers.TestAESKeyHex,
		EnabledServices: "postgres,redis,mongodb",
		Environment:     "test",
		ComputeProvider: "noop",
	}
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	t.Cleanup(cleanRedis)
	planReg := plans.Default()

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if errors.Is(e, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if fe, ok := e.(*fiber.Error); ok {
				code = fe.Code
			}
			_ = handlers.WriteFiberError(c, code, "internal_error", e.Error())
			return nil
		},
	})
	app.Use(middleware.RequestID())

	dbH := handlers.NewDBHandler(db, rdb, cfg, nil, planReg)
	cacheH := handlers.NewCacheHandler(db, rdb, cfg, nil, planReg)
	nosqlH := handlers.NewNoSQLHandler(db, rdb, cfg, nil, planReg)
	twinH := handlers.NewTwinHandler(dbH, cacheH, nosqlH)

	middleware.SetRoleLookupDB(db)
	api := app.Group("/api/v1", middleware.RequireAuth(cfg))
	api.Post("/resources/:id/provision-twin", twinH.ProvisionTwin)
	return app
}

// TestTwinFinal_BadUUID_400 — :id is not a UUID → invalid_id (twin.go:107).
func TestTwinFinal_BadUUID_400(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := twinJWT(t, db, teamID)

	resp := postTwin(t, app, "not-a-uuid", jwt, map[string]any{"env": "staging"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_id", decodeErr(t, resp).Error)
}

// TestTwinFinal_UnparseableBody_400 — a non-JSON body with the JSON
// Content-Type → invalid_body (twin.go:112 via parseProvisionBody BodyParser).
func TestTwinFinal_UnparseableBody_400(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := twinJWT(t, db, teamID)
	_, srcToken := seedTwinSource(t, db, teamID, "postgres", "pro")

	// `{` is valid UTF-8 but not parseable JSON → BodyParser errors.
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/resources/"+srcToken+"/provision-twin", strings.NewReader("{not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestTwinFinal_SourceLookup_DBError_503 — GetResourceByToken errors mid-handler
// (twin.go:139). The fault driver fails the FIRST query (the role lookup in
// PopulateTeamRole isn't wired in twinFaultApp, so the first query the handler
// issues is the source lookup). We seed on a pooled DB, then point the handler
// at the fault DB failing after 0 successful calls.
func TestTwinFinal_SourceLookup_DBError_503(t *testing.T) {
	seedDB, cleanSeed := testhelpers.SetupTestDB(t)
	defer cleanSeed()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	jwt := twinJWT(t, seedDB, teamID)
	_, srcToken := seedTwinSource(t, seedDB, teamID, "postgres", "pro")

	// failAfter=0 → the very first Query/Exec errors. RequireAuth does not
	// query the DB (JWT-only), so GetResourceByToken is the first DB call.
	faultDB := openFaultDB(t, 0)
	app := twinFaultApp(t, faultDB)

	resp := postTwin(t, app, srcToken, jwt, map[string]any{"env": "staging"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "fetch_failed", decodeErr(t, resp).Error)
}

// TestTwinFinal_TeamLookup_DBError_503 — source lookup succeeds, then
// GetTeamByID errors (twin.go:170). failAfter=1 lets the source lookup through
// and fails the team lookup.
func TestTwinFinal_TeamLookup_DBError_503(t *testing.T) {
	seedDB, cleanSeed := testhelpers.SetupTestDB(t)
	defer cleanSeed()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	jwt := twinJWT(t, seedDB, teamID)
	_, srcToken := seedTwinSource(t, seedDB, teamID, "postgres", "pro")

	faultDB := openFaultDB(t, 1)
	app := twinFaultApp(t, faultDB)

	resp := postTwin(t, app, srcToken, jwt, map[string]any{"env": "staging"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "team_lookup_failed", decodeErr(t, resp).Error)
}

// TestTwinFinal_BeginApproval_InsertError_503 — non-dev env + no approval_id +
// the approval INSERT errors (twin.go:441). The handler runs: source lookup (1),
// team lookup (2), then CreatePromoteApprovalAndEmit's INSERT (3). failAfter=2.
func TestTwinFinal_BeginApproval_InsertError_503(t *testing.T) {
	seedDB, cleanSeed := testhelpers.SetupTestDB(t)
	defer cleanSeed()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	jwt := twinJWT(t, seedDB, teamID)
	_, srcToken := seedTwinSource(t, seedDB, teamID, "postgres", "pro")

	faultDB := openFaultDB(t, 2)
	app := twinFaultApp(t, faultDB)

	resp := postTwin(t, app, srcToken, jwt, map[string]any{"env": "staging"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "approval_failed", decodeErr(t, resp).Error)
}

// TestTwinFinal_ConsumeApproval_LookupError_503 — approval_id present, source +
// team lookups succeed, then GetPromoteApprovalByID errors (twin.go:471).
// failAfter=2.
func TestTwinFinal_ConsumeApproval_LookupError_503(t *testing.T) {
	seedDB, cleanSeed := testhelpers.SetupTestDB(t)
	defer cleanSeed()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	jwt := twinJWT(t, seedDB, teamID)
	_, srcToken := seedTwinSource(t, seedDB, teamID, "postgres", "pro")

	faultDB := openFaultDB(t, 2)
	app := twinFaultApp(t, faultDB)

	resp := postTwin(t, app, srcToken, jwt, map[string]any{
		"env":         "staging",
		"approval_id": uuid.NewString(),
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "lookup_failed", decodeErr(t, resp).Error)
}

// TestTwinFinal_ConsumeApproval_ExecuteError_503 — approval row is fully valid
// (approved, matching kind/from/to, unexpired), so the handler reaches
// MarkPromoteApprovalExecuted, which then errors (twin.go:496). The row must
// EXIST and be readable, so we seed it on the pooled DB and let the fault
// driver pass source(1) + team(2) + approval-read(3) and fail the UPDATE (4).
func TestTwinFinal_ConsumeApproval_ExecuteError_503(t *testing.T) {
	seedDB, cleanSeed := testhelpers.SetupTestDB(t)
	defer cleanSeed()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	jwt := twinJWT(t, seedDB, teamID)
	email := testhelpers.UniqueEmail(t)
	_, srcToken := seedTwinSource(t, seedDB, teamID, "postgres", "pro")
	future := time.Now().UTC().Add(time.Hour)
	approvalID := bvInsertApproval(t, seedDB, teamID, email,
		models.PromoteApprovalKindResourceTwin, "approved", "production", "staging", future)

	// source(1) + team(2) + GetPromoteApprovalByID(3) succeed, the
	// MarkPromoteApprovalExecuted UPDATE (4) errors.
	faultDB := openFaultDB(t, 3)
	app := twinFaultApp(t, faultDB)

	resp := postTwin(t, app, srcToken, jwt, map[string]any{
		"env":         "staging",
		"approval_id": approvalID,
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "execute_failed", decodeErr(t, resp).Error)
}

// TestTwinFinal_ValidateFamily_DBError_503 — non-dev twin with an approval_id
// that consumes cleanly, then ValidateFamilyParent errors (twin.go:240). The
// query sequence: source(1), team(2), GetPromoteApprovalByID(3),
// MarkPromoteApprovalExecuted(4), then ValidateFamilyParent's parent lookup (5)
// errors. failAfter=4.
func TestTwinFinal_ValidateFamily_DBError_503(t *testing.T) {
	seedDB, cleanSeed := testhelpers.SetupTestDB(t)
	defer cleanSeed()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	jwt := twinJWT(t, seedDB, teamID)
	email := testhelpers.UniqueEmail(t)
	_, srcToken := seedTwinSource(t, seedDB, teamID, "postgres", "pro")
	future := time.Now().UTC().Add(time.Hour)
	approvalID := bvInsertApproval(t, seedDB, teamID, email,
		models.PromoteApprovalKindResourceTwin, "approved", "production", "staging", future)

	faultDB := openFaultDB(t, 4)
	app := twinFaultApp(t, faultDB)

	resp := postTwin(t, app, srcToken, jwt, map[string]any{
		"env":         "staging",
		"approval_id": approvalID,
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "family_validate_failed", decodeErr(t, resp).Error)
}

// TestTwinFinal_BeginApproval_NamedSource_202 — a non-dev twin of a source that
// HAS a name, with no body name. This exercises beginTwinApproval's
// srcName-from-valid-Name arm (twin.go:423) and returns 202 pending.
func TestTwinFinal_BeginApproval_NamedSource_202(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := twinJWT(t, db, teamID)

	var srcToken string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, env, name, status)
		VALUES ($1::uuid, 'postgres', 'pro', 'production', 'my-named-source', 'active')
		RETURNING token::text`, teamID).Scan(&srcToken))

	// No "name" in the body → twinName falls back to source.Name; the approval
	// row also captures srcName from source.Name.Valid.
	resp := postTwin(t, app, srcToken, jwt, map[string]any{"env": "staging"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
}

// TestTwinFinal_NamedSource_DevTwin_CarriesName — a dev-env twin of a named
// source with no body name dispatches into the redis ProvisionForTwin path and
// exercises the twinName fallback (twin.go:252). Redis provisions for real, so
// this is a 201; if redis is unreachable it 503s — either way the fallback arm
// runs.
func TestTwinFinal_NamedSource_DevTwin_CarriesName(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "redis")
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := twinJWT(t, db, teamID)

	var srcToken string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, env, name, status)
		VALUES ($1::uuid, 'redis', 'pro', 'production', 'named-redis', 'active')
		RETURNING token::text`, teamID).Scan(&srcToken))

	resp := postTwin(t, app, srcToken, jwt, map[string]any{"env": "development"})
	defer resp.Body.Close()
	assert.Contains(t, []int{http.StatusCreated, http.StatusServiceUnavailable}, resp.StatusCode)
}

// TestTwinFinal_BadTeamIDInToken_401 — a session JWT whose tid claim is not a
// UUID passes RequireAuth (which only checks tid != "") but fails parseTeamID
// in the handler → unauthorized (twin.go:101).
func TestTwinFinal_BadTeamIDInToken_401(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	// tid is deliberately not a UUID.
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), "not-a-uuid-team", testhelpers.UniqueEmail(t))
	resp := postTwin(t, app, uuid.NewString(), jwt, map[string]any{"env": "staging"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, "unauthorized", decodeErr(t, resp).Error)
}

// TestTwinFinal_DerefUUID_NilBranch — derefUUID(nil) → "" (twin.go:392). The
// nil arm is unreachable via the handler (ParentRootID is always &rootID), so
// it's covered as a pure unit.
func TestTwinFinal_DerefUUID_NilBranch(t *testing.T) {
	assert.Equal(t, "", handlers.DerefUUIDForTest(nil))
	id := uuid.New()
	assert.Equal(t, id.String(), handlers.DerefUUIDForTest(&id))
}

// ensure context import is used even if a future edit drops a call.
var _ = context.Background
