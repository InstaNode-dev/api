package handlers_test

// billing_apikeys_audit_block_integration_test.go — W3 done-bar closure for the
// billing / api-keys / audit route triage.
//
// These three subsystems each already carry handler-coverage suites
// (api_keys_coverage_test.go, billing_portal_arms_bvwave_test.go,
// billing_usage_test.go, billing_promotion_test.go, audit_export_test.go), but
// a subset of those run the handler behind a SYNTHETIC team-id shim
// (app.Use(set LocalKeyTeamID)) or a sqlmock DB rather than the PRODUCTION auth
// chain. This file closes the remaining real gaps that the done-bar route guard
// (internal/router/route_donebar_guard_test.go) cares about:
//
//   - The full PRODUCTION auth chain — middleware.RequireAuth(cfg) +
//     PopulateTeamRole + RequireWritable, exactly as router.go's /api/v1 group —
//     driven with REAL session JWTs (testhelpers.MustSignSessionJWT) against a
//     REAL migrated Postgres (testhelpers.SetupTestDB) and REAL Redis
//     (testhelpers.SetupTestRedis). No team-id shim.
//   - CROSS-TEAM ISOLATION for the routes whose existing suites omit it:
//     api-keys (team A must NOT see or revoke team B's key) and billing/usage
//     (team A's aggregate must reflect team A's rows only).
//   - The owner/member authz axis: a non-owner member of the SAME team can
//     read its own audit log / api-keys / usage (these routes carry no
//     RequireRole — any authenticated, writable team member is allowed).
//   - The unauthenticated 401 contract straight out of RequireAuth.
//
// The state-change + provider-arm contracts for change-plan / invoices /
// update-payment / promotion-validate live in the existing portal-arms +
// promotion suites (the Razorpay external leg is faked via
// handlers.SetBillingPortalForTestPortal — a real Razorpay call is deferred to
// the live-cluster e2e); the done-bar map points those rows at the existing
// tests. This file is the NEW production-chain + isolation layer.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// baaSkipNoDB skips a test when no test Postgres is configured. These are
// real-backend integration assertions over actual rows in
// teams/users/api_keys/audit_log — a missing DB is a loud skip, never a false
// green.
func baaSkipNoDB(t *testing.T) bool {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") != "" {
		return false
	}
	t.Skip("billing/api-keys/audit integration: TEST_DATABASE_URL not set")
	return true
}

// baaApp builds a Fiber app that wires the billing-usage + api-keys + audit
// routes under the PRODUCTION /api/v1 auth chain — RequireAuth(cfg) +
// PopulateTeamRole + RequireWritable, identical to internal/router/router.go.
// The caller drives it with a real session JWT minted by
// testhelpers.MustSignSessionJWT, so the team/user scope comes from a validated
// token, not a synthetic Locals shim.
//
// SetRoleLookupDB points PopulateTeamRole at the real test DB so the role axis
// resolves from the seeded users.role column exactly as production.
func baaApp(t *testing.T, db *sql.DB, rdb *redis.Client) *fiber.App {
	t.Helper()

	cfg := &config.Config{
		JWTSecret: testhelpers.TestJWTSecret,
		AESKey:    testhelpers.TestAESKeyHex,
	}

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error", "message": err.Error()})
		},
	})

	app.Use(middleware.RequestID())
	middleware.SetRoleLookupDB(db)

	api := app.Group("/api/v1",
		middleware.RequireAuth(cfg),
		middleware.PopulateTeamRole(),
		middleware.RequireWritable(),
	)

	usageH := handlers.NewBillingUsageHandler(db, rdb, plans.Default())
	api.Get("/billing/usage", usageH.GetUsage)

	apiKeysH := handlers.NewAPIKeysHandler(db)
	api.Post("/auth/api-keys", apiKeysH.Create)
	api.Get("/auth/api-keys", apiKeysH.List)
	api.Delete("/auth/api-keys/:id", apiKeysH.Revoke)

	auditH := handlers.NewAuditHandler(db)
	api.Get("/audit", auditH.List)
	api.Get("/audit.csv", auditH.ListCSV)

	return app
}

// baaTeamWithUser seeds a team at the given tier plus a user with the given
// role, returns (teamID, userID, jwt), and registers cleanup. The JWT carries
// the seeded identity so the production RequireAuth chain validates it.
func baaTeamWithUser(t *testing.T, db *sql.DB, tier, role string) (teamID, userID, jwt string) {
	t.Helper()
	teamID = testhelpers.MustCreateTeamDB(t, db, tier)
	teamUUID := uuid.MustParse(teamID)
	emailAddr := testhelpers.UniqueEmail(t)
	u, err := models.CreateUser(context.Background(), db, teamUUID, emailAddr, "", "", role)
	require.NoError(t, err)
	t.Cleanup(func() {
		db.Exec(`DELETE FROM api_keys WHERE team_id = $1::uuid`, teamID)
		db.Exec(`DELETE FROM audit_log WHERE team_id = $1::uuid`, teamID)
		db.Exec(`DELETE FROM users WHERE team_id = $1::uuid`, teamID)
		db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	})
	jwt = testhelpers.MustSignSessionJWT(t, u.ID.String(), teamID, emailAddr)
	return teamID, u.ID.String(), jwt
}

// baaDo issues a request with an optional bearer JWT and returns the response.
func baaDo(t *testing.T, app *fiber.App, method, path, jwt, body string) *http.Response {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

func baaDecode(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out
}

// ── api-keys: cross-team isolation through the production auth chain ──────────

// TestBAAApiKeys_CrossTeamIsolation_BCannotSeeOrRevokeAsKey is the gap the
// existing api_keys_coverage_test.go leaves open: it proves a single team's
// CRUD round-trip but never that team B is walled off from team A's keys.
//
// Team A creates a key. Team B (a DIFFERENT validated session) must:
//   - NOT see A's key in its own list (list is team-scoped), and
//   - get 404 — not 200 — when it tries to revoke A's key by id
//     (RevokeAPIKey is WHERE team_id = caller, so a cross-team id never matches).
//
// 404 (not 403) is the deliberate contract — the same shape the audit/vault
// blocks use so a cross-team probe can't even confirm the id exists.
func TestBAAApiKeys_CrossTeamIsolation_BCannotSeeOrRevokeAsKey(t *testing.T) {
	if baaSkipNoDB(t) {
		return
	}
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app := baaApp(t, db, rdb)

	_, _, jwtA := baaTeamWithUser(t, db, "pro", "owner")
	teamBID, _, jwtB := baaTeamWithUser(t, db, "pro", "owner")
	_ = teamBID

	// A creates a key.
	resp := baaDo(t, app, http.MethodPost, "/api/v1/auth/api-keys", jwtA, `{"name":"a-laptop","scopes":["read"]}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	created := baaDecode(t, resp)
	keyID, _ := created["id"].(string)
	require.NotEmpty(t, keyID)

	// B lists — must NOT see A's key.
	resp = baaDo(t, app, http.MethodGet, "/api/v1/auth/api-keys", jwtB, "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	bList := baaDecode(t, resp)
	items, _ := bList["items"].([]any)
	assert.Empty(t, items, "team B must not see team A's API keys")

	// B tries to revoke A's key by id — 404, not a silent success.
	resp = baaDo(t, app, http.MethodDelete, "/api/v1/auth/api-keys/"+keyID, jwtB, "")
	require.Equal(t, http.StatusNotFound, resp.StatusCode,
		"team B revoking team A's key id must 404 (cross-team isolation), not 200")
	resp.Body.Close()

	// And the key is STILL active for A (B's attempt didn't revoke it).
	resp = baaDo(t, app, http.MethodGet, "/api/v1/auth/api-keys", jwtA, "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	aList := baaDecode(t, resp)
	aItems, _ := aList["items"].([]any)
	require.Len(t, aItems, 1)
	first, _ := aItems[0].(map[string]any)
	assert.Equal(t, false, first["revoked"], "team A's key must remain active after team B's failed revoke")
}

// TestBAAApiKeys_Member_CanManageOwnTeamKeys proves the api-keys routes carry
// NO RequireRole — a non-owner member (role 'developer') of the SAME team may
// create + list its own team's keys. (admin-scope minting is separately gated
// by reauth; this exercises the read/write default scope a member is allowed.)
func TestBAAApiKeys_Member_CanManageOwnTeamKeys(t *testing.T) {
	if baaSkipNoDB(t) {
		return
	}
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app := baaApp(t, db, nil)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	t.Cleanup(func() {
		db.Exec(`DELETE FROM api_keys WHERE team_id = $1::uuid`, teamID)
		db.Exec(`DELETE FROM users WHERE team_id = $1::uuid`, teamID)
		db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	})
	// Owner first (a team must have one), then the member who acts.
	_, err := models.CreateUser(context.Background(), db, uuid.MustParse(teamID), testhelpers.UniqueEmail(t), "", "", "owner")
	require.NoError(t, err)
	memberEmail := testhelpers.UniqueEmail(t)
	member, err := models.CreateUser(context.Background(), db, uuid.MustParse(teamID), memberEmail, "", "", "developer")
	require.NoError(t, err)
	jwt := testhelpers.MustSignSessionJWT(t, member.ID.String(), teamID, memberEmail)

	resp := baaDo(t, app, http.MethodPost, "/api/v1/auth/api-keys", jwt, `{"name":"member-key","scopes":["read","write"]}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "a non-owner member may create a read/write API key")
	resp.Body.Close()

	resp = baaDo(t, app, http.MethodGet, "/api/v1/auth/api-keys", jwt, "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := baaDecode(t, resp)
	items, _ := body["items"].([]any)
	require.Len(t, items, 1)
}

// TestBAAApiKeys_Unauthenticated_401 — the RequireAuth boundary. No bearer →
// 401 on each api-keys verb.
func TestBAAApiKeys_Unauthenticated_401(t *testing.T) {
	if baaSkipNoDB(t) {
		return
	}
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app := baaApp(t, db, nil)

	for _, m := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/v1/auth/api-keys", `{"name":"x"}`},
		{http.MethodGet, "/api/v1/auth/api-keys", ""},
		{http.MethodDelete, "/api/v1/auth/api-keys/" + uuid.NewString(), ""},
	} {
		resp := baaDo(t, app, m.method, m.path, "", m.body)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "%s %s without a JWT must 401", m.method, m.path)
		resp.Body.Close()
	}
}

// ── billing/usage: production-chain happy path + cross-team isolation ─────────

// TestBAAUsage_HappyPath_RealDB drives GET /billing/usage through the full
// production auth chain against a REAL migrated Postgres (the existing
// billing_usage_test.go uses sqlmock + a team-id shim). Asserts the documented
// §10.20.2 shape: ok + freshness_seconds + as_of + the seven usage metrics.
func TestBAAUsage_HappyPath_RealDB(t *testing.T) {
	if baaSkipNoDB(t) {
		return
	}
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app := baaApp(t, db, rdb)

	_, _, jwt := baaTeamWithUser(t, db, "pro", "owner")

	resp := baaDo(t, app, http.MethodGet, "/api/v1/billing/usage", jwt, "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "private, max-age=30, stale-while-revalidate=60", resp.Header.Get("Cache-Control"))
	body := baaDecode(t, resp)
	assert.Equal(t, true, body["ok"])
	assert.Equal(t, float64(30), body["freshness_seconds"])
	assert.NotEmpty(t, body["as_of"])
	usage, ok := body["usage"].(map[string]any)
	require.True(t, ok, "usage object must be present; body=%v", body)
	for _, k := range []string{"postgres", "redis", "mongodb", "deployments", "webhooks", "vault", "members"} {
		_, exists := usage[k]
		assert.Truef(t, exists, "usage[%s] must be present", k)
	}
}

// TestBAAUsage_CrossTeamIsolation_AReflectsOnlyOwnRows proves the aggregate is
// team-scoped end-to-end: team A with one active postgres resource reports a
// non-zero member/aggregate scoped to A, while team B (no resources) reports
// its own zeroed aggregate. Two distinct validated sessions, two distinct
// cache keys (billing:usage:<team_id>), zero bleed.
func TestBAAUsage_CrossTeamIsolation_AReflectsOnlyOwnRows(t *testing.T) {
	if baaSkipNoDB(t) {
		return
	}
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app := baaApp(t, db, rdb)

	teamAID, _, jwtA := baaTeamWithUser(t, db, "pro", "owner")
	_, _, jwtB := baaTeamWithUser(t, db, "pro", "owner")

	// Team A gets a webhook resource so its webhooks count is 1.
	teamAUUID := uuid.MustParse(teamAID)
	_, err := db.Exec(`
		INSERT INTO resources (team_id, resource_type, tier, status)
		VALUES ($1::uuid, 'webhook', 'pro', 'active')`, teamAID)
	require.NoError(t, err)
	t.Cleanup(func() { db.Exec(`DELETE FROM resources WHERE team_id = $1::uuid`, teamAID) })
	_ = teamAUUID

	// A's aggregate: webhooks count == 1.
	respA := baaDo(t, app, http.MethodGet, "/api/v1/billing/usage", jwtA, "")
	require.Equal(t, http.StatusOK, respA.StatusCode)
	bodyA := baaDecode(t, respA)
	usageA := bodyA["usage"].(map[string]any)
	whA := usageA["webhooks"].(map[string]any)
	assert.Equal(t, float64(1), whA["count"], "team A's webhook resource must count toward A's aggregate")

	// B's aggregate: webhooks count is absent/0 — A's row must not leak.
	respB := baaDo(t, app, http.MethodGet, "/api/v1/billing/usage", jwtB, "")
	require.Equal(t, http.StatusOK, respB.StatusCode)
	bodyB := baaDecode(t, respB)
	usageB := bodyB["usage"].(map[string]any)
	whB, _ := usageB["webhooks"].(map[string]any)
	// usageMetric uses omitempty, so count:0 serialises as an empty object.
	var bCount float64
	if whB != nil {
		bCount, _ = whB["count"].(float64)
	}
	assert.Equal(t, float64(0), bCount, "team B's aggregate must not include team A's webhook resource")
}

// TestBAAUsage_Member_CanRead — usage carries no RequireRole; a non-owner
// member of the team can read its own aggregate.
func TestBAAUsage_Member_CanRead(t *testing.T) {
	if baaSkipNoDB(t) {
		return
	}
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app := baaApp(t, db, rdb)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	t.Cleanup(func() {
		db.Exec(`DELETE FROM users WHERE team_id = $1::uuid`, teamID)
		db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	})
	_, err := models.CreateUser(context.Background(), db, uuid.MustParse(teamID), testhelpers.UniqueEmail(t), "", "", "owner")
	require.NoError(t, err)
	memberEmail := testhelpers.UniqueEmail(t)
	member, err := models.CreateUser(context.Background(), db, uuid.MustParse(teamID), memberEmail, "", "", "developer")
	require.NoError(t, err)
	jwt := testhelpers.MustSignSessionJWT(t, member.ID.String(), teamID, memberEmail)

	resp := baaDo(t, app, http.MethodGet, "/api/v1/billing/usage", jwt, "")
	require.Equal(t, http.StatusOK, resp.StatusCode, "a non-owner member may read the team usage aggregate")
	resp.Body.Close()
}

// ── audit: production-chain member read + cross-team isolation ────────────────
//
// audit_export_test.go already covers the happy path, tier gate, pagination,
// redaction, admin.* exclusion, and cross-team isolation through NewTestApp's
// production chain. These two add the explicit non-owner-member authz axis and
// the CSV cross-team axis behind the SAME RequireAuth chain this file builds, so
// the done-bar rows for /audit + /audit.csv have a contract-complete home.

// TestBAAAudit_Member_CanReadOwnTeam — a non-owner member can read the audit
// log of its own team (no RequireRole on /audit).
func TestBAAAudit_Member_CanReadOwnTeam(t *testing.T) {
	if baaSkipNoDB(t) {
		return
	}
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app := baaApp(t, db, nil)

	// Pro tier so the lookback gate (anonymous/free → 402) is satisfied.
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	t.Cleanup(func() {
		db.Exec(`DELETE FROM audit_log WHERE team_id = $1::uuid`, teamID)
		db.Exec(`DELETE FROM users WHERE team_id = $1::uuid`, teamID)
		db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	})
	_, err := models.CreateUser(context.Background(), db, uuid.MustParse(teamID), testhelpers.UniqueEmail(t), "", "", "owner")
	require.NoError(t, err)
	memberEmail := testhelpers.UniqueEmail(t)
	member, err := models.CreateUser(context.Background(), db, uuid.MustParse(teamID), memberEmail, "", "", "developer")
	require.NoError(t, err)
	jwt := testhelpers.MustSignSessionJWT(t, member.ID.String(), teamID, memberEmail)

	// Seed one non-admin audit row.
	_, err = db.Exec(`INSERT INTO audit_log (team_id, actor, kind, summary)
		VALUES ($1::uuid, 'agent', 'resource.created', 'seeded for member-read test')`, teamID)
	require.NoError(t, err)

	resp := baaDo(t, app, http.MethodGet, "/api/v1/audit", jwt, "")
	require.Equal(t, http.StatusOK, resp.StatusCode, "a non-owner member may read its own team's audit log")
	body := baaDecode(t, resp)
	assert.Equal(t, true, body["ok"])
	items, _ := body["items"].([]any)
	assert.GreaterOrEqual(t, len(items), 1, "the seeded row must be visible to the member")
}

// TestBAAAuditCSV_CrossTeamIsolation — team B's CSV export must not contain
// team A's audit rows, behind the production RequireAuth chain.
func TestBAAAuditCSV_CrossTeamIsolation(t *testing.T) {
	if baaSkipNoDB(t) {
		return
	}
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app := baaApp(t, db, nil)

	teamAID, _, _ := baaTeamWithUser(t, db, "pro", "owner")
	_, _, jwtB := baaTeamWithUser(t, db, "pro", "owner")

	// Seed a distinctive row on team A.
	marker := "marker-" + uuid.NewString()
	_, err := db.Exec(`INSERT INTO audit_log (team_id, actor, kind, summary)
		VALUES ($1::uuid, 'agent', 'resource.created', $2)`, teamAID, marker)
	require.NoError(t, err)

	// B requests the CSV — A's marker must be absent.
	resp := baaDo(t, app, http.MethodGet, "/api/v1/audit.csv", jwtB, "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/csv")
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), marker, "team B's audit CSV must not contain team A's rows")
}
