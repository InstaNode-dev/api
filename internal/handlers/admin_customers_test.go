package handlers_test

// admin_customers_test.go — integration coverage for the /api/v1/admin/*
// surface. Drives the production handler set behind a fake-auth shim that
// injects email/team/user IDs into Fiber locals (so we don't have to mint
// real JWTs in every test). Real DB writes against TEST_DATABASE_URL.
//
// What we're asserting:
//   1. RequireAdmin middleware is closed-by-default: empty / unset
//      ADMIN_EMAILS rejects every caller on every admin endpoint (403).
//   2. Non-admin JWT email → 403 with the canonical agent_action populated.
//   3. Admin JWT email → 200 / 201 on list / detail / tier-change / promo-issue.
//   4. List sorts by mrr_monthly correctly (higher tier first).
//   5. Tier change updates team.plan_tier AND elevates resources AND writes
//      an audit_log row with the expected metadata shape.
//   6. Promo issue returns a unique code, expires_at, and writes an audit row.
//   7. Email substring search returns the matching team.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// ─────────────────────────────────────────────────────────────────────────────
// Test scaffolding
// ─────────────────────────────────────────────────────────────────────────────

// adminCallerEmail is the email injected for an "admin" caller. The
// surrounding TestMain isn't used; instead each test that needs admin
// access calls t.Setenv("ADMIN_EMAILS", adminCallerEmail).
const adminCallerEmail = "founder@instanode.dev"

// adminNonAdminEmail is the email injected for a "regular user" caller.
// Used to assert the rejection path returns 403 + agent_action.
const adminNonAdminEmail = "alice@example.com"

// adminAppNeedsDB skips the test when TEST_DATABASE_URL is not configured.
func adminAppNeedsDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("admin_customers_test: TEST_DATABASE_URL not set — skipping integration test")
	}
	return testhelpers.SetupTestDB(t)
}

// adminApp builds a Fiber app wired to the real admin handler behind a
// fake-auth middleware. callerEmail is what the test wants the caller's
// JWT email to be ("" → no email, simulating an unauthenticated caller —
// which still doesn't reach RequireAdmin because in production a missing
// Authorization header is rejected upstream by RequireAuth; in this test
// rig we bypass that and pin the email directly so RequireAdmin sees it).
//
// Routes mirror what router.go installs:
//
//	GET    /api/v1/admin/customers
//	GET    /api/v1/admin/customers/:team_id
//	POST   /api/v1/admin/customers/:team_id/tier
//	POST   /api/v1/admin/customers/:team_id/promo
func adminApp(t *testing.T, db *sql.DB, callerEmail string) *fiber.App {
	t.Helper()
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

	// Fake auth: inject email + a dummy team/user pair so the handler can
	// read GetEmail() / GetTeamID() / GetUserID(). The team ID here is
	// only used for upstream middleware that calls GetTeamID — admin
	// handlers themselves read team_id from the URL param, not Locals.
	fakeAuth := func(c *fiber.Ctx) error {
		if callerEmail != "" {
			c.Locals(middleware.LocalKeyEmail, callerEmail)
		}
		c.Locals(middleware.LocalKeyUserID, uuid.NewString())
		c.Locals(middleware.LocalKeyTeamID, uuid.NewString())
		return c.Next()
	}

	planReg := plans.Default()
	adminH := handlers.NewAdminCustomersHandler(db, planReg)

	adminGroup := app.Group("/api/v1/admin", fakeAuth, middleware.RequireAdmin())
	adminGroup.Get("/customers", adminH.List)
	adminGroup.Get("/customers/:team_id", adminH.Detail)
	adminGroup.Post("/customers/:team_id/tier", adminH.ChangeTier)
	adminGroup.Post("/customers/:team_id/promo", adminH.IssuePromo)

	return app
}

// adminSeedTeam inserts a team + a single owner user + (optionally) an
// active permanent resource so list/detail aggregates have something to
// chew on. Returns (teamID, ownerEmail).
func adminSeedTeam(t *testing.T, db *sql.DB, tier string) (uuid.UUID, string) {
	t.Helper()
	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, tier))
	email := testhelpers.UniqueEmail(t)
	_, err := models.CreateUser(ctx, db, teamID, email, "", "", "owner")
	require.NoError(t, err)
	// Insert one active permanent resource (no expires_at) so storage_bytes
	// and last_active are non-zero. Token is a UUID to satisfy UNIQUE(token).
	_, err = db.ExecContext(ctx, `
		INSERT INTO resources (team_id, token, resource_type, tier, env, status, storage_bytes)
		VALUES ($1, $2, 'redis', $3, 'production', 'active', 1024)
	`, teamID, uuid.NewString(), tier)
	require.NoError(t, err)
	t.Cleanup(func() {
		db.Exec(`DELETE FROM resources WHERE team_id = $1`, teamID)
		db.Exec(`DELETE FROM users WHERE team_id = $1`, teamID)
		db.Exec(`DELETE FROM audit_log WHERE team_id = $1`, teamID)
		db.Exec(`DELETE FROM admin_promo_codes WHERE team_id = $1`, teamID)
		db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)
	})
	return teamID, email
}

// adminDoJSON sends a JSON request and returns the parsed body. Closes
// the response body on the test's cleanup.
func adminDoJSON(t *testing.T, app *fiber.App, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req := httptest.NewRequest(method, path, &buf)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		out = map[string]any{}
	}
	return resp.StatusCode, out
}

// ─────────────────────────────────────────────────────────────────────────────
// RequireAdmin gate
// ─────────────────────────────────────────────────────────────────────────────

// TestRequireAdmin_ClosedByDefault asserts the safety property: an unset
// or empty ADMIN_EMAILS rejects every caller, on every admin endpoint,
// regardless of what email is on the JWT. This is the most important
// invariant in this whole feature — getting it wrong silently exposes the
// admin surface to anyone with a logged-in session.
func TestRequireAdmin_ClosedByDefault(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()

	// ADMIN_EMAILS deliberately not set. t.Setenv("ADMIN_EMAILS", "")
	// would do the same — explicit unset is the production reality.
	t.Setenv("ADMIN_EMAILS", "")

	// Try with an email that LOOKS like a founder address; it must still
	// be rejected, because the allowlist is empty.
	app := adminApp(t, db, adminCallerEmail)

	teamID, _ := adminSeedTeam(t, db, "hobby")

	cases := []struct {
		method, path string
		body         any
	}{
		{"GET", "/api/v1/admin/customers", nil},
		{"GET", "/api/v1/admin/customers/" + teamID.String(), nil},
		{"POST", "/api/v1/admin/customers/" + teamID.String() + "/tier", map[string]any{"tier": "pro", "reason": "comp"}},
		{"POST", "/api/v1/admin/customers/" + teamID.String() + "/promo", map[string]any{"kind": "percent_off", "value": 10, "valid_for_days": 30}},
	}
	for _, tc := range cases {
		status, body := adminDoJSON(t, app, tc.method, tc.path, tc.body)
		assert.Equal(t, http.StatusForbidden, status, "%s %s — empty ADMIN_EMAILS must reject", tc.method, tc.path)
		assert.Equal(t, "forbidden", body["error"], "%s %s — error code must be forbidden", tc.method, tc.path)
		// agent_action is THE contract — verbatim sentence the agent
		// re-articulates to the human. Drop here = silent regression.
		aa, _ := body["agent_action"].(string)
		assert.Contains(t, aa, "Tell the user this endpoint requires platform-admin access",
			"%s %s — agent_action must be populated", tc.method, tc.path)
	}
}

// TestRequireAdmin_NonAdminEmail_Rejected — JWT email present but not on
// the allowlist. Distinct from the empty-allowlist case so a regression
// in the allowlist-parsing path is caught separately from the
// closed-by-default invariant.
func TestRequireAdmin_NonAdminEmail_Rejected(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)

	app := adminApp(t, db, adminNonAdminEmail)
	teamID, _ := adminSeedTeam(t, db, "hobby")

	status, body := adminDoJSON(t, app, "GET", "/api/v1/admin/customers/"+teamID.String(), nil)
	assert.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, "forbidden", body["error"])
	aa, _ := body["agent_action"].(string)
	assert.Contains(t, aa, "platform-admin access")
}

// TestRequireAdmin_CaseInsensitive — ADMIN_EMAILS matching is
// case-insensitive on both sides (env var value and JWT claim). Founders
// don't reliably sign in with the same capitalization across providers
// (GitHub vs Google vs magic-link); case-sensitive matching would silently
// lock them out.
func TestRequireAdmin_CaseInsensitive(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", "Founder@Instanode.DEV")

	app := adminApp(t, db, "FOUNDER@instanode.dev")
	teamID, _ := adminSeedTeam(t, db, "hobby")
	status, _ := adminDoJSON(t, app, "GET", "/api/v1/admin/customers/"+teamID.String(), nil)
	assert.Equal(t, http.StatusOK, status)
}

// TestAdminEmailAllowlist_ParsesCommaList exercises the parser directly so
// a regression in the env-var split logic surfaces without spinning up a
// Fiber app.
func TestAdminEmailAllowlist_ParsesCommaList(t *testing.T) {
	t.Setenv("ADMIN_EMAILS", "  a@x.com, b@Y.COM  ,, c@z.com ")
	allow := middleware.AdminEmailAllowlist()
	require.NotNil(t, allow)
	assert.True(t, allow["a@x.com"])
	assert.True(t, allow["b@y.com"])
	assert.True(t, allow["c@z.com"])
	assert.False(t, allow["d@x.com"])

	t.Setenv("ADMIN_EMAILS", "")
	assert.Nil(t, middleware.AdminEmailAllowlist())

	t.Setenv("ADMIN_EMAILS", "   ")
	assert.Nil(t, middleware.AdminEmailAllowlist())
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/v1/admin/customers — list
// ─────────────────────────────────────────────────────────────────────────────

// TestAdminList_AdminUserSees200 — happy path: an admin caller sees the
// canonical response shape.
func TestAdminList_AdminUserSees200(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminApp(t, db, adminCallerEmail)

	teamID, email := adminSeedTeam(t, db, "pro")

	status, body := adminDoJSON(t, app, "GET", "/api/v1/admin/customers?limit=100", nil)
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, true, body["ok"])
	customers, ok := body["customers"].([]any)
	require.True(t, ok, "customers must be an array")
	found := false
	for _, c := range customers {
		row, _ := c.(map[string]any)
		if row["team_id"] == teamID.String() {
			found = true
			assert.Equal(t, email, row["primary_email"])
			assert.Equal(t, "pro", row["tier"])
			// MRR: pro tier monthly price (from plans Registry). Asserting
			// > 0 rather than the exact dollar amount so the test doesn't
			// break when pricing changes — but does break if MRR is
			// accidentally zeroed out for paying customers.
			mrr, _ := row["mrr_monthly"].(float64)
			assert.Greater(t, mrr, float64(0), "pro tier must have positive monthly MRR")
		}
	}
	assert.True(t, found, "seeded team must appear in customers list")
}

// TestAdminList_SortByMRR_HigherTierFirst — list ordering by MRR puts
// 'team' before 'pro' before 'hobby'. This is the founder's first useful
// view: who's paying the most.
//
// We can't `?sort_by=mrr` and just look at the first three results — the
// test DB may carry stale teams from other test files (different test
// packages may have left rows behind), so we instead pull the full sorted
// list and compare the relative ORDER of the seeded team IDs. The cross-
// test pollution is irrelevant as long as our three teams appear in the
// expected relative order.
func TestAdminList_SortByMRR_HigherTierFirst(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminApp(t, db, adminCallerEmail)

	hobbyID, _ := adminSeedTeam(t, db, "hobby")
	proID, _ := adminSeedTeam(t, db, "pro")
	teamTierID, _ := adminSeedTeam(t, db, "team")

	// Pull every page until we've seen all three. Some test DBs carry
	// thousands of rows from other packages.
	rank := map[string]int{}
	seen := 0
	offset := 0
	for offset < 5000 {
		status, body := adminDoJSON(t, app, "GET",
			"/api/v1/admin/customers?sort_by=mrr&limit=500&offset="+itoa(offset), nil)
		require.Equal(t, http.StatusOK, status)
		customers, _ := body["customers"].([]any)
		if len(customers) == 0 {
			break
		}
		for i, c := range customers {
			row, _ := c.(map[string]any)
			id, _ := row["team_id"].(string)
			if id == hobbyID.String() || id == proID.String() || id == teamTierID.String() {
				rank[id] = offset + i
				seen++
			}
		}
		if seen == 3 {
			break
		}
		offset += 500
	}
	require.Equal(t, 3, seen, "all three seeded teams must appear in paged results")
	assert.Less(t, rank[teamTierID.String()], rank[proID.String()], "team-tier must rank before pro")
	assert.Less(t, rank[proID.String()], rank[hobbyID.String()], "pro must rank before hobby")
}

// itoa converts an int to a base-10 string. Avoids importing strconv just
// for one call in this file.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// TestAdminList_QueryByEmail_FindsMatchingTeam — substring search on
// users.email returns the matching team.
//
// We use the UUID portion of the seeded email (UniqueEmail format:
// "test+<8-hex>@instant.dev") so the q match is unique to THIS test —
// other tests in this package or sibling packages share the "test+"
// prefix and would otherwise pollute the result set above the default
// page limit.
func TestAdminList_QueryByEmail_FindsMatchingTeam(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminApp(t, db, adminCallerEmail)

	teamID, email := adminSeedTeam(t, db, "hobby")
	// Extract the UUID-prefix portion (after "test+", before "@") — this
	// gives a 6-char hex token that's vanishingly unlikely to collide with
	// any other seeded email in the database.
	// email shape: "test+ab12cd34@instant.dev"
	uniq := email
	if idx := indexByte(uniq, '+'); idx >= 0 {
		uniq = uniq[idx+1:]
	}
	if idx := indexByte(uniq, '@'); idx >= 0 {
		uniq = uniq[:idx]
	}
	require.NotEmpty(t, uniq, "extracted unique portion must be non-empty")

	status, body := adminDoJSON(t, app, "GET", "/api/v1/admin/customers?q="+uniq, nil)
	require.Equal(t, http.StatusOK, status)
	customers, _ := body["customers"].([]any)
	found := false
	for _, c := range customers {
		row, _ := c.(map[string]any)
		if row["team_id"] == teamID.String() {
			found = true
		}
	}
	assert.True(t, found, "q=%q must surface the seeded team", uniq)
}

// indexByte returns the index of c in s, or -1.
func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// TestAdminList_InvalidSortBy_400 — unknown sort_by produces a structured
// 400 rather than blowing up the SQL.
func TestAdminList_InvalidSortBy_400(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminApp(t, db, adminCallerEmail)
	status, body := adminDoJSON(t, app, "GET", "/api/v1/admin/customers?sort_by=evil%20DROP%20TABLE", nil)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_sort_by", body["error"])
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/v1/admin/customers/:team_id — detail
// ─────────────────────────────────────────────────────────────────────────────

func TestAdminDetail_AdminUserSees200(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminApp(t, db, adminCallerEmail)

	teamID, email := adminSeedTeam(t, db, "pro")

	status, body := adminDoJSON(t, app, "GET", "/api/v1/admin/customers/"+teamID.String(), nil)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	cust, _ := body["customer"].(map[string]any)
	require.NotNil(t, cust)
	assert.Equal(t, teamID.String(), cust["team_id"])
	assert.Equal(t, "pro", cust["tier"])

	users, _ := cust["users"].([]any)
	require.Len(t, users, 1)
	u, _ := users[0].(map[string]any)
	assert.Equal(t, email, u["email"])
	assert.Equal(t, "owner", u["role"])
}

func TestAdminDetail_UnknownTeamID_404(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminApp(t, db, adminCallerEmail)
	status, body := adminDoJSON(t, app, "GET", "/api/v1/admin/customers/"+uuid.NewString(), nil)
	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "team_not_found", body["error"])
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/v1/admin/customers/:team_id/tier — tier change
// ─────────────────────────────────────────────────────────────────────────────

// TestAdminTierChange_HobbyToPro_UpdatesTeamElevatesResourcesWritesAudit
// is the full integration assertion: the request must update three
// things atomically (the team.plan_tier column, every active permanent
// resource's tier, and one audit_log row with structured metadata) and
// emit an agent_action sentence so the caller can relay the result.
func TestAdminTierChange_HobbyToPro_UpdatesTeamElevatesResourcesWritesAudit(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminApp(t, db, adminCallerEmail)

	teamID, _ := adminSeedTeam(t, db, "hobby")

	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/"+teamID.String()+"/tier",
		map[string]any{"tier": "pro", "reason": "comp for early adopter"})
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, "hobby", body["from"])
	assert.Equal(t, "pro", body["to"])
	aa, _ := body["agent_action"].(string)
	assert.Contains(t, aa, "pro")

	// 1. teams.plan_tier was updated.
	team, err := models.GetTeamByID(context.Background(), db, teamID)
	require.NoError(t, err)
	assert.Equal(t, "pro", team.PlanTier)

	// 2. Active resources were elevated.
	var resTier string
	err = db.QueryRowContext(context.Background(),
		`SELECT tier FROM resources WHERE team_id = $1 LIMIT 1`, teamID).Scan(&resTier)
	require.NoError(t, err)
	assert.Equal(t, "pro", resTier)

	// 3. An audit_log row was written with structured metadata.
	var (
		kind, summary string
		metaRaw       sql.NullString
	)
	err = db.QueryRowContext(context.Background(), `
		SELECT kind, summary, metadata::text
		FROM audit_log
		WHERE team_id = $1 AND kind = $2
		ORDER BY created_at DESC LIMIT 1
	`, teamID, handlers.AuditKindAdminTierChanged).Scan(&kind, &summary, &metaRaw)
	require.NoError(t, err)
	assert.Equal(t, handlers.AuditKindAdminTierChanged, kind)
	require.True(t, metaRaw.Valid)
	var meta map[string]any
	require.NoError(t, json.Unmarshal([]byte(metaRaw.String), &meta))
	assert.Equal(t, "hobby", meta["from"])
	assert.Equal(t, "pro", meta["to"])
	assert.Equal(t, adminCallerEmail, meta["by_admin_email"])
	assert.Equal(t, "comp for early adopter", meta["reason"])
}

func TestAdminTierChange_MissingReason_400(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminApp(t, db, adminCallerEmail)
	teamID, _ := adminSeedTeam(t, db, "hobby")
	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/"+teamID.String()+"/tier",
		map[string]any{"tier": "pro"})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "missing_reason", body["error"])
}

func TestAdminTierChange_SameTier_409(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminApp(t, db, adminCallerEmail)
	teamID, _ := adminSeedTeam(t, db, "pro")
	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/"+teamID.String()+"/tier",
		map[string]any{"tier": "pro", "reason": "test"})
	assert.Equal(t, http.StatusConflict, status)
	assert.Equal(t, "tier_unchanged", body["error"])
}

func TestAdminTierChange_InvalidTier_400(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminApp(t, db, adminCallerEmail)
	teamID, _ := adminSeedTeam(t, db, "hobby")
	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/"+teamID.String()+"/tier",
		map[string]any{"tier": "platinum", "reason": "x"})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_tier", body["error"])
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/v1/admin/customers/:team_id/promo — issue promo
// ─────────────────────────────────────────────────────────────────────────────

// TestAdminIssuePromo_ReturnsCodeAndWritesAudit asserts the canonical
// happy path: a single-use promo code is generated, persisted, and the
// audit-log row carries enough metadata for a future redemption check
// to reconstruct what was offered.
func TestAdminIssuePromo_ReturnsCodeAndWritesAudit(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminApp(t, db, adminCallerEmail)

	teamID, _ := adminSeedTeam(t, db, "hobby")

	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/"+teamID.String()+"/promo",
		map[string]any{"kind": "percent_off", "value": 25, "valid_for_days": 30})
	require.Equal(t, http.StatusCreated, status, "body=%v", body)
	code, _ := body["code"].(string)
	require.NotEmpty(t, code)
	assert.Equal(t, 8, len(code), "promo code must be 8 chars")
	expiresAt, _ := body["expires_at"].(string)
	require.NotEmpty(t, expiresAt)
	parsed, err := time.Parse(time.RFC3339Nano, expiresAt)
	require.NoError(t, err)
	assert.True(t, parsed.After(time.Now().Add(20*24*time.Hour)),
		"expires_at must be ~30 days out")

	// DB row exists and is wired to the team.
	var dbCode, dbKind, dbIssuedBy string
	var dbValue int
	err = db.QueryRowContext(context.Background(), `
		SELECT code, kind, value, issued_by_email
		FROM admin_promo_codes
		WHERE team_id = $1
		ORDER BY created_at DESC LIMIT 1
	`, teamID).Scan(&dbCode, &dbKind, &dbValue, &dbIssuedBy)
	require.NoError(t, err)
	assert.Equal(t, code, dbCode)
	assert.Equal(t, "percent_off", dbKind)
	assert.Equal(t, 25, dbValue)
	assert.Equal(t, adminCallerEmail, dbIssuedBy)

	// Audit row.
	var auditKind, metaRaw string
	err = db.QueryRowContext(context.Background(), `
		SELECT kind, metadata::text
		FROM audit_log
		WHERE team_id = $1 AND kind = $2
		ORDER BY created_at DESC LIMIT 1
	`, teamID, handlers.AuditKindAdminPromoIssued).Scan(&auditKind, &metaRaw)
	require.NoError(t, err)
	var meta map[string]any
	require.NoError(t, json.Unmarshal([]byte(metaRaw), &meta))
	assert.Equal(t, code, meta["code"])
	assert.Equal(t, "percent_off", meta["kind"])
	assert.Equal(t, float64(25), meta["value"])
}

func TestAdminIssuePromo_InvalidKind_400(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminApp(t, db, adminCallerEmail)
	teamID, _ := adminSeedTeam(t, db, "hobby")
	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/"+teamID.String()+"/promo",
		map[string]any{"kind": "free_money", "value": 100, "valid_for_days": 30})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_kind", body["error"])
}

func TestAdminIssuePromo_PercentOffOutOfRange_400(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminApp(t, db, adminCallerEmail)
	teamID, _ := adminSeedTeam(t, db, "hobby")
	// 150% off must be rejected — the agent could read body["value"] back
	// and compute a negative invoice.
	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/"+teamID.String()+"/promo",
		map[string]any{"kind": "percent_off", "value": 150, "valid_for_days": 30})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_value", body["error"])
}

func TestAdminIssuePromo_UnknownTeam_404(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminApp(t, db, adminCallerEmail)
	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/"+uuid.NewString()+"/promo",
		map[string]any{"kind": "first_month_free", "valid_for_days": 30})
	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "team_not_found", body["error"])
}
