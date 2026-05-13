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
	"strings"
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

// adminSeedTeamWithEmail seeds a team at the given tier with a caller-
// supplied owner email (rather than the random UniqueEmail one). Needed
// for the substring-search tests below where we assert specific tokens
// like "fou" against "founder@…" — UniqueEmail's UUID prefix can't drive
// that. Returns the teamID.
func adminSeedTeamWithEmail(t *testing.T, db *sql.DB, tier, email string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, tier))
	_, err := models.CreateUser(ctx, db, teamID, email, "", "", "owner")
	require.NoError(t, err)
	t.Cleanup(func() {
		db.Exec(`DELETE FROM resources WHERE team_id = $1`, teamID)
		db.Exec(`DELETE FROM users WHERE team_id = $1`, teamID)
		db.Exec(`DELETE FROM audit_log WHERE team_id = $1`, teamID)
		db.Exec(`DELETE FROM admin_promo_codes WHERE team_id = $1`, teamID)
		db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)
	})
	return teamID
}

// uniqueTagForTest returns a short hex token unique to this test run.
// We splice it into the seeded email so q=<tag> only matches THIS test's
// team — keeps the substring-search assertions stable against pollution
// from sibling tests in the same DB.
func uniqueTagForTest(t *testing.T) string {
	t.Helper()
	return uuid.NewString()[:6]
}

// TestAdminList_QueryByEmail_SubstringPrefixMatches asserts the "?q=fou
// matches founder@…" semantics — i.e. that the WHERE clause uses
// substring matching (LIKE '%q%'), not equality. The existing
// TestAdminList_QueryByEmail_FindsMatchingTeam covers substring matching
// against a UUID-derived token; this test specifically pins the
// human-readable prefix case the founder will actually type into the
// dashboard search box.
func TestAdminList_QueryByEmail_SubstringPrefixMatches(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminApp(t, db, adminCallerEmail)

	// "<tag>founder@x.com" — the tag prefixes the email so the substring
	// "<tag>fou" is a contiguous slice of the actual stored email. This
	// isolates the team from sibling tests that may also seed
	// "founder"-prefixed emails (the tag is unique per test run). If
	// we put the tag AFTER "founder" the substring "fou<tag>" wouldn't
	// be contiguous in the stored email — LIKE '%fou<tag>%' would miss.
	tag := uniqueTagForTest(t)
	email := tag + "founder@x.com"
	teamID := adminSeedTeamWithEmail(t, db, "hobby", email)

	// "<tag>fou" → contiguous substring of "<tag>founder@x.com".
	status, body := adminDoJSON(t, app, "GET",
		"/api/v1/admin/customers?q="+tag+"fou", nil)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	customers, _ := body["customers"].([]any)
	found := false
	for _, c := range customers {
		row, _ := c.(map[string]any)
		if row["team_id"] == teamID.String() {
			found = true
			assert.Equal(t, email, row["primary_email"])
		}
	}
	assert.True(t, found, "q=%sfou must match seeded email %q", tag, email)
}

// TestAdminList_QueryByEmail_CaseInsensitive asserts q=FOUNDER matches
// "founder@x.com". The handler lowercases both sides (q and email column
// via lower(email)), and migration 023 adds an idx_users_email_lower
// functional index to make this cheap. The migration index is required
// for production scale; this test only asserts the semantics, not the
// EXPLAIN plan.
func TestAdminList_QueryByEmail_CaseInsensitive(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminApp(t, db, adminCallerEmail)

	tag := uniqueTagForTest(t)
	email := tag + "founder@x.com"
	teamID := adminSeedTeamWithEmail(t, db, "hobby", email)

	// Upper-case the query — should still match the lower-case stored email.
	// The tag prefixes the literal substring so it's a contiguous slice.
	status, body := adminDoJSON(t, app, "GET",
		"/api/v1/admin/customers?q="+strings.ToUpper(tag)+"FOUNDER", nil)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	customers, _ := body["customers"].([]any)
	found := false
	for _, c := range customers {
		row, _ := c.(map[string]any)
		if row["team_id"] == teamID.String() {
			found = true
		}
	}
	assert.True(t, found, "case-insensitive q=%sFOUNDER must match %q",
		strings.ToUpper(tag), email)
}

// TestAdminList_MultiTierFilter_ReturnsBothTiers asserts that
// ?tier=hobby,pro produces a WHERE plan_tier IN ('hobby','pro') —
// returning both seeded teams while excluding a third 'team'-tier seed.
//
// The dashboard's filter-pills UI sends the selected pills as a
// comma-joined list in one request; the handler must OR them.
func TestAdminList_MultiTierFilter_ReturnsBothTiers(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminApp(t, db, adminCallerEmail)

	hobbyID, _ := adminSeedTeam(t, db, "hobby")
	proID, _ := adminSeedTeam(t, db, "pro")
	teamTierID, _ := adminSeedTeam(t, db, "team")

	// Page through (the test DB may carry stale rows; we walk pages
	// until we've seen the seeded IDs we care about — same pattern as
	// TestAdminList_SortByMRR_HigherTierFirst above).
	sawHobby := false
	sawPro := false
	sawTeam := false
	offset := 0
	for offset < 5000 {
		status, body := adminDoJSON(t, app, "GET",
			"/api/v1/admin/customers?tier=hobby,pro&limit=500&offset="+itoa(offset), nil)
		require.Equal(t, http.StatusOK, status)
		customers, _ := body["customers"].([]any)
		if len(customers) == 0 {
			break
		}
		for _, c := range customers {
			row, _ := c.(map[string]any)
			id, _ := row["team_id"].(string)
			tier, _ := row["tier"].(string)
			// Every returned row must be hobby OR pro — never team.
			assert.Contains(t, []string{"hobby", "pro"}, tier,
				"tier=hobby,pro filter must exclude tier=%s row %s", tier, id)
			switch id {
			case hobbyID.String():
				sawHobby = true
			case proID.String():
				sawPro = true
			case teamTierID.String():
				sawTeam = true
			}
		}
		offset += 500
	}
	assert.True(t, sawHobby, "seeded hobby team must appear under tier=hobby,pro")
	assert.True(t, sawPro, "seeded pro team must appear under tier=hobby,pro")
	assert.False(t, sawTeam, "seeded team-tier team must NOT appear under tier=hobby,pro")
}

// TestAdminList_BogusTierValue_ReturnsEmptyList — UI-stable contract: a
// typo'd or stale-build tier value (e.g. ?tier=platinum) must return an
// empty list with 200, not a 400 error. The dashboard filter pills are
// "OR a set of values"; an unknown pill should render "no results" not
// an error banner.
//
// Note this is a deliberate behavior change vs the PR #48 baseline,
// which 400'd on `tier=platinum`. Multi-tier callers (tier=hobby,pro)
// keep the valid tiers and silently drop unknowns — only the all-unknown
// case short-circuits to empty.
func TestAdminList_BogusTierValue_ReturnsEmptyList(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminApp(t, db, adminCallerEmail)

	// Seed something so we can assert it does NOT come back.
	_, _ = adminSeedTeam(t, db, "pro")

	status, body := adminDoJSON(t, app, "GET",
		"/api/v1/admin/customers?tier=platinum", nil)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, true, body["ok"])
	customers, ok := body["customers"].([]any)
	require.True(t, ok, "customers must be an array even when empty")
	assert.Empty(t, customers, "unknown tier value must return empty list")
	// total mirrors the empty page — 0, not the count of all teams.
	total, _ := body["total"].(float64)
	assert.Equal(t, float64(0), total)
}

// TestAdminList_Pagination_LimitAndOffset asserts that limit + offset
// produce non-overlapping pages and that the cumulative pages cover the
// full sorted result without duplicates. This is the regression guard:
// a future change that breaks the LIMIT/OFFSET parameter binding (e.g.
// off-by-one in the $N counter when args were appended for q + tier)
// would silently return overlapping pages.
func TestAdminList_Pagination_LimitAndOffset(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminApp(t, db, adminCallerEmail)

	// Seed three teams with a shared, unique email tag so we can scope
	// the pagination assertion to ONLY these three rows. Without the
	// tag, sibling tests pollute the result set and we can't make a
	// deterministic page-equality assertion.
	tag := uniqueTagForTest(t)
	idA := adminSeedTeamWithEmail(t, db, "hobby", "alpha"+tag+"@x.com")
	idB := adminSeedTeamWithEmail(t, db, "pro", "bravo"+tag+"@x.com")
	idC := adminSeedTeamWithEmail(t, db, "team", "charlie"+tag+"@x.com")

	// Page 1: limit=2, offset=0 → 2 rows.
	status, body := adminDoJSON(t, app, "GET",
		"/api/v1/admin/customers?q="+tag+"&limit=2&offset=0", nil)
	require.Equal(t, http.StatusOK, status)
	page1, _ := body["customers"].([]any)
	require.Len(t, page1, 2, "page 1 must contain exactly limit=2 rows (body=%v)", body)
	total, _ := body["total"].(float64)
	assert.Equal(t, float64(3), total, "total must reflect the full filtered count, not the page size")

	// Page 2: limit=2, offset=2 → 1 row (the remaining one).
	status, body = adminDoJSON(t, app, "GET",
		"/api/v1/admin/customers?q="+tag+"&limit=2&offset=2", nil)
	require.Equal(t, http.StatusOK, status)
	page2, _ := body["customers"].([]any)
	require.Len(t, page2, 1, "page 2 must contain the single remaining row")

	// Union of page1 + page2 must equal all three seeded IDs, no dupes.
	seen := map[string]bool{}
	for _, c := range page1 {
		row, _ := c.(map[string]any)
		id, _ := row["team_id"].(string)
		seen[id] = true
	}
	for _, c := range page2 {
		row, _ := c.(map[string]any)
		id, _ := row["team_id"].(string)
		assert.False(t, seen[id], "page 2 row %s must not also appear on page 1", id)
		seen[id] = true
	}
	assert.True(t, seen[idA.String()], "team A must appear across the two pages")
	assert.True(t, seen[idB.String()], "team B must appear across the two pages")
	assert.True(t, seen[idC.String()], "team C must appear across the two pages")
	assert.Equal(t, 3, len(seen), "exactly 3 distinct team_ids across the two pages")
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

// ─────────────────────────────────────────────────────────────────────────────
// Razorpay subscription cancellation on admin demote
// ─────────────────────────────────────────────────────────────────────────────
//
// Track B follow-up to PR #48: when admin demotes a paying customer
// (pro → hobby, team → pro, etc.) the customer's Razorpay subscription
// must be canceled out-of-band — otherwise we keep charging them at the
// old tier indefinitely. Promotions are unchanged (comp-tier flow).
//
// The handler indirects through AdminCustomersHandler.CancelSubscription;
// these tests substitute a tracking fake to assert (a) when it's called,
// (b) with what subscription_id, and (c) that failures don't surface a
// 500 to the admin caller.

// adminAppWithCancel mirrors adminApp but lets the test inject a fake
// CancelSubscription. Returns both the Fiber app and the underlying
// handler so the test can inspect call-counts on the handler-owned fake.
func adminAppWithCancel(t *testing.T, db *sql.DB, callerEmail string, cancelFn func(string) error) (*fiber.App, *handlers.AdminCustomersHandler) {
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
	if cancelFn != nil {
		adminH.CancelSubscription = cancelFn
	}

	adminGroup := app.Group("/api/v1/admin", fakeAuth, middleware.RequireAdmin())
	adminGroup.Post("/customers/:team_id/tier", adminH.ChangeTier)
	return app, adminH
}

// adminSeedTeamWithSub seeds a team at the given tier + a unique
// Razorpay subscription_id on file. Returns (teamID, subID).
func adminSeedTeamWithSub(t *testing.T, db *sql.DB, tier string) (uuid.UUID, string) {
	t.Helper()
	teamID, _ := adminSeedTeam(t, db, tier)
	subID := "sub_test_demote_" + uuid.NewString()
	require.NoError(t, models.UpdateRazorpaySubscriptionID(context.Background(), db, teamID, subID))
	return teamID, subID
}

// adminLatestAuditMeta returns the metadata blob of the most recent
// audit_log row for (teamID, kind). Test helper to keep the assertion
// blocks short.
func adminLatestAuditMeta(t *testing.T, db *sql.DB, teamID uuid.UUID, kind string) map[string]any {
	t.Helper()
	var raw sql.NullString
	err := db.QueryRowContext(context.Background(), `
		SELECT metadata::text
		FROM audit_log
		WHERE team_id = $1 AND kind = $2
		ORDER BY created_at DESC LIMIT 1
	`, teamID, kind).Scan(&raw)
	require.NoError(t, err, "audit row with kind=%s must exist for team_id=%s", kind, teamID)
	require.True(t, raw.Valid, "audit row metadata must be non-NULL")
	var out map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw.String), &out))
	return out
}

// TestAdminTierChange_DemoteProToHobby_CancelsSubscription is the headline
// case: a paying Pro team with an active Razorpay subscription gets
// demoted by admin → the Razorpay cancel fires + the canceled_by_admin
// audit row carries cancel_succeeded=true + the subscription_id.
//
// Both audit rows must be emitted: admin.tier_changed (the existing PR #48
// behavior) AND subscription.canceled_by_admin (new). Brevo / Loops keys
// on the new kind to fire the "your subscription was canceled by support"
// template — the old kind keeps existing consumers untouched.
func TestAdminTierChange_DemoteProToHobby_CancelsSubscription(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)

	teamID, subID := adminSeedTeamWithSub(t, db, "pro")

	var cancelCalls []string
	cancelFn := func(s string) error {
		cancelCalls = append(cancelCalls, s)
		return nil
	}
	app, _ := adminAppWithCancel(t, db, adminCallerEmail, cancelFn)

	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/"+teamID.String()+"/tier",
		map[string]any{"tier": "hobby", "reason": "customer requested downgrade — support ticket #1042"})
	require.Equal(t, http.StatusOK, status, "demote must succeed: body=%v", body)
	assert.Equal(t, "pro", body["from"])
	assert.Equal(t, "hobby", body["to"])

	// 1. Razorpay cancel was called exactly once with the right subscription_id.
	require.Equal(t, 1, len(cancelCalls), "CancelSubscription must be called exactly once on demote")
	assert.Equal(t, subID, cancelCalls[0], "cancel must be called with the team's stored subscription_id")

	// 2. team.plan_tier was actually demoted in DB.
	team, err := models.GetTeamByID(context.Background(), db, teamID)
	require.NoError(t, err)
	assert.Equal(t, "hobby", team.PlanTier)

	// 3. The admin.tier_changed audit row exists (preserves Track A behavior).
	tierMeta := adminLatestAuditMeta(t, db, teamID, handlers.AuditKindAdminTierChanged)
	assert.Equal(t, "pro", tierMeta["from"])
	assert.Equal(t, "hobby", tierMeta["to"])

	// 4. The subscription.canceled_by_admin audit row exists with the
	//    expected provider-agnostic shape — Brevo / Loops keys on the
	//    kind string + reads cancel_succeeded to decide template copy.
	cancelMeta := adminLatestAuditMeta(t, db, teamID, models.AuditKindSubscriptionCanceledByAdmin)
	assert.Equal(t, "pro", cancelMeta["from_tier"])
	assert.Equal(t, "hobby", cancelMeta["to_tier"])
	assert.Equal(t, adminCallerEmail, cancelMeta["by_admin_email"])
	assert.Equal(t, subID, cancelMeta["subscription_id"])
	assert.Equal(t, true, cancelMeta["cancel_attempted"])
	assert.Equal(t, true, cancelMeta["cancel_succeeded"])
	// cancel_error is omitempty — must be absent on success.
	_, hasErr := cancelMeta["cancel_error"]
	assert.False(t, hasErr, "cancel_error must be omitted when cancel succeeded")
}

// TestAdminTierChange_DemoteTeamToHobby_CancelsSubscription covers the
// "biggest customer downgrades all the way" case. Same shape as the
// pro→hobby test but exercises the rank delta of 2+ to defend against a
// regression where the demote check assumes adjacent tiers only.
func TestAdminTierChange_DemoteTeamToHobby_CancelsSubscription(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)

	teamID, subID := adminSeedTeamWithSub(t, db, "team")
	var cancelCalls []string
	cancelFn := func(s string) error {
		cancelCalls = append(cancelCalls, s)
		return nil
	}
	app, _ := adminAppWithCancel(t, db, adminCallerEmail, cancelFn)

	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/"+teamID.String()+"/tier",
		map[string]any{"tier": "hobby", "reason": "team requested full downgrade"})
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	require.Equal(t, 1, len(cancelCalls))
	assert.Equal(t, subID, cancelCalls[0])
	cancelMeta := adminLatestAuditMeta(t, db, teamID, models.AuditKindSubscriptionCanceledByAdmin)
	assert.Equal(t, "team", cancelMeta["from_tier"])
	assert.Equal(t, "hobby", cancelMeta["to_tier"])
	assert.Equal(t, true, cancelMeta["cancel_succeeded"])
}

// TestAdminTierChange_DemoteWithoutSubscriptionID_NoRazorpayCall — paying
// tier with no subscription_id (operator comp-promoted, then later demoted)
// must NOT call Razorpay but must still emit the audit row, with
// cancel_attempted=false so Brevo doesn't claim we canceled anything.
//
// Defensive: catches the "loud failure if subID empty" regression where a
// future refactor decides empty subID is a bug and returns 5xx.
func TestAdminTierChange_DemoteWithoutSubscriptionID_NoRazorpayCall(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)

	// Seed on Pro but DO NOT set a subscription_id — simulating a
	// comp-promoted team being later demoted.
	teamID, _ := adminSeedTeam(t, db, "pro")

	var cancelCalls []string
	cancelFn := func(s string) error {
		cancelCalls = append(cancelCalls, s)
		return nil
	}
	app, _ := adminAppWithCancel(t, db, adminCallerEmail, cancelFn)

	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/"+teamID.String()+"/tier",
		map[string]any{"tier": "hobby", "reason": "comp expired"})
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, 0, len(cancelCalls), "no subscription_id → Razorpay must NOT be called")

	cancelMeta := adminLatestAuditMeta(t, db, teamID, models.AuditKindSubscriptionCanceledByAdmin)
	assert.Equal(t, "pro", cancelMeta["from_tier"])
	assert.Equal(t, "hobby", cancelMeta["to_tier"])
	assert.Equal(t, "", cancelMeta["subscription_id"])
	assert.Equal(t, false, cancelMeta["cancel_attempted"])
	assert.Equal(t, false, cancelMeta["cancel_succeeded"])
}

// TestAdminTierChange_PromoteHobbyToPro_NoRazorpayCall guards the comp-flow
// invariant: promotes must not touch Razorpay (they're free upgrades from
// the operator). A regression that fires the cancel on promote would
// silently break every "comp this beta tester to pro" workflow.
//
// Also asserts NO subscription.canceled_by_admin audit row gets written —
// promotes are pure admin.tier_changed (existing PR #48 behavior).
func TestAdminTierChange_PromoteHobbyToPro_NoRazorpayCall(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)

	teamID, _ := adminSeedTeamWithSub(t, db, "hobby")
	var cancelCalls []string
	cancelFn := func(s string) error {
		cancelCalls = append(cancelCalls, s)
		return nil
	}
	app, _ := adminAppWithCancel(t, db, adminCallerEmail, cancelFn)

	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/"+teamID.String()+"/tier",
		map[string]any{"tier": "pro", "reason": "comp"})
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, 0, len(cancelCalls), "promote must NOT call Razorpay cancel")

	// No subscription.canceled_by_admin audit row must exist for this team.
	var count int
	err := db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM audit_log WHERE team_id = $1 AND kind = $2
	`, teamID, models.AuditKindSubscriptionCanceledByAdmin).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "promote must NOT emit subscription.canceled_by_admin")
}

// TestAdminTierChange_DemoteRazorpayCancelFails_StillReturns200 is the
// fail-open assertion: Razorpay returning 5xx must NOT block the admin
// demote. The team is already on the new tier in our DB, the audit row
// records cancel_succeeded=false + the error, and the operator reconciles
// manually in the Razorpay dashboard. Returning 5xx here would leave the
// admin UI in an ambiguous state (did the demote take?) — worse UX than
// the audit-flag-and-move-on path.
func TestAdminTierChange_DemoteRazorpayCancelFails_StillReturns200(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)

	teamID, subID := adminSeedTeamWithSub(t, db, "pro")
	cancelFn := func(s string) error {
		return errors.New("razorpay 500: BAD_REQUEST_ERROR — server unreachable")
	}
	app, _ := adminAppWithCancel(t, db, adminCallerEmail, cancelFn)

	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/"+teamID.String()+"/tier",
		map[string]any{"tier": "hobby", "reason": "downgrade despite razorpay flake"})
	require.Equal(t, http.StatusOK, status,
		"Razorpay cancel failure must not block the admin demote (fail-open). body=%v", body)
	assert.Equal(t, "hobby", body["to"])

	// DB demote actually happened.
	team, err := models.GetTeamByID(context.Background(), db, teamID)
	require.NoError(t, err)
	assert.Equal(t, "hobby", team.PlanTier)

	// Audit row records the failure so the operator (and Brevo) knows
	// nothing was actually canceled in Razorpay.
	cancelMeta := adminLatestAuditMeta(t, db, teamID, models.AuditKindSubscriptionCanceledByAdmin)
	assert.Equal(t, subID, cancelMeta["subscription_id"])
	assert.Equal(t, true, cancelMeta["cancel_attempted"])
	assert.Equal(t, false, cancelMeta["cancel_succeeded"])
	errMsg, _ := cancelMeta["cancel_error"].(string)
	assert.Contains(t, errMsg, "razorpay 500",
		"cancel_error must surface the underlying Razorpay error so the operator can debug")
}

// TestAdminTierChange_SameTier_409_NoRazorpayCall is the idempotency
// assertion: re-running the same demote yields the existing same-tier 409
// (preserves PR #48 behavior) and MUST NOT make a duplicate Razorpay
// cancel call. The first demote already canceled the subscription;
// re-canceling would either 404 or no-op upstream, and either way we
// don't want to log a spurious "we canceled" audit row.
func TestAdminTierChange_SameTier_409_NoRazorpayCall(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)

	teamID, _ := adminSeedTeamWithSub(t, db, "hobby")
	var cancelCalls []string
	cancelFn := func(s string) error {
		cancelCalls = append(cancelCalls, s)
		return nil
	}
	app, _ := adminAppWithCancel(t, db, adminCallerEmail, cancelFn)

	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/"+teamID.String()+"/tier",
		map[string]any{"tier": "hobby", "reason": "re-run"})
	assert.Equal(t, http.StatusConflict, status)
	assert.Equal(t, "tier_unchanged", body["error"])
	assert.Equal(t, 0, len(cancelCalls), "same-tier 409 must NOT call Razorpay cancel")
}
