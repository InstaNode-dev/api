package handlers_test

// approve_block_helpers_test.go — shared helpers for the W4 deploy-approval
// block integration suite (approve_block_routes_test.go). These cover the
// public email-link approval landing — GET /approve/:token — from
// USER-FLOW-INVENTORY-AND-TEST-MATRIX.md §W4, which prior to this suite sat in
// internal/router/route_donebar_guard_test.go's routeCoverageExemptions with a
// "TODO: matrix W4 deploy-approval flow" pointer and NO mapped test.
//
// Mirrors the established W3 vault-block / team-block convention
// (vault_block_helpers_test.go): a thin SetupTestDB wrapper + a loud
// skip-when-no-DB guard + DB-backed seed helpers. Helpers here are prefixed
// approveBlock* so they do NOT collide with — and do NOT redefine — the
// existing miniRedis / doJSON / decodeBody helpers (which this suite reuses
// verbatim) or the white-box daApp / daSeedApproval helpers in
// promote_approval_deployasync_test.go (those live in package handlers; this
// suite is package handlers_test).
//
// Why a dedicated app builder rather than NewTestAppWithServices: that shared
// test app does NOT register the approve route. approveBlockApp registers the
// route through the SAME wiring internal/router/router.go installs —
// handlers.NewPromoteApprovalHandler(db, rdb) + app.Get("/approve/:token",
// h.Approve) — against the real migrated test DB and a real (miniredis) Redis,
// so the suite exercises the public token-IS-the-credential contract end-to-end:
// the per-IP rate limit, the four token branches (invalid / expired /
// already-used / valid), the persisted status flip, and the 302→dashboard
// redirect. The token is the only credential — there is NO RequireAuth on this
// route by design (the email URL must work for an anonymous click), so no JWT is
// minted here.

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// approveBlockSkipNoDB skips a W4 deploy-approval test when no test Postgres is
// configured. The approve block is a real-backend integration surface — these
// tests assert on actual rows in promote_approvals (status flip from 'pending'
// to 'approved'/'expired') and on the rendered HTML / redirect contract, so a
// missing DB is a loud skip, never a false green. Mirrors vaultBlockSkipNoDB.
func approveBlockSkipNoDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("W4 deploy-approval integration: TEST_DATABASE_URL not set")
	}
}

// approveBlockDB opens a fresh migrated test DB and returns it with its cleanup.
// Thin wrapper over testhelpers.SetupTestDB so every W4 approve-block test reads
// the same way.
func approveBlockDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	return testhelpers.SetupTestDB(t)
}

// approveBlockApp builds a Fiber app that registers the public approve route
// through the SAME wiring production uses (internal/router/router.go line ~599):
// handlers.NewPromoteApprovalHandler(db, rdb) then
// app.Get("/approve/:token", h.Approve). There is NO auth middleware — the route
// is public by design (the token IS the credential), matching router.go where
// this route is wired ABOVE the /api/v1 RequireAuth group. rdb drives the
// per-IP rate limit (pass a real miniredis client to exercise it; pass nil to
// exercise the rate-limit-fails-open posture).
func approveBlockApp(t *testing.T, db *sql.DB, rdb *redis.Client) *fiber.App {
	t.Helper()
	// ProxyHeader mirrors router.New so c.IP() reads X-Forwarded-For — the
	// per-IP rate-limit key the handler builds.
	app := fiber.New(fiber.Config{ProxyHeader: "X-Forwarded-For"})
	h := handlers.NewPromoteApprovalHandler(db, rdb)
	app.Get("/approve/:token", h.Approve)
	return app
}

// approveBlockSeedTeam inserts a 'pro'-tier team and returns its id, registering
// cleanup of its promote_approvals + the team row. promote_approvals.team_id has
// a NOT NULL FK to teams, so every seeded approval needs a real team.
func approveBlockSeedTeam(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	require.NoError(t,
		db.QueryRow(`INSERT INTO teams (plan_tier) VALUES ('pro') RETURNING id`).Scan(&id),
		"seed approve-block team")
	t.Cleanup(func() {
		db.Exec(`DELETE FROM promote_approvals WHERE team_id = $1`, id)
		db.Exec(`DELETE FROM audit_log WHERE team_id = $1`, id)
		db.Exec(`DELETE FROM teams WHERE id = $1`, id)
	})
	return id
}

// approveBlockSeedApproval inserts a promote_approvals row for teamID at the
// given status, with expiry `expiresIn` from now. A NEGATIVE expiresIn forces an
// already-expired row (CreatePromoteApproval coerces a non-positive TTL to the
// 24h default, so we set expires_at directly in that case — same trick as the
// white-box daSeedApproval). Returns the row (carrying the plaintext token to
// click). Built on the real models.CreatePromoteApproval so the row shape
// matches what the production CreatePromoteApprovalAndEmit writes.
func approveBlockSeedApproval(t *testing.T, db *sql.DB, teamID uuid.UUID, status string, expiresIn time.Duration) *models.PromoteApproval {
	t.Helper()
	tok, err := models.GeneratePromoteApprovalToken()
	require.NoError(t, err, "gen approve token")

	ttl := expiresIn
	if ttl <= 0 {
		// CreatePromoteApproval would coerce this to the default; pass a small
		// positive TTL, then force expires_at into the past below.
		ttl = time.Hour
	}
	row, err := models.CreatePromoteApproval(context.Background(), db, models.CreatePromoteApprovalParams{
		Token:            tok,
		TeamID:           teamID,
		RequestedByEmail: "approver-" + uuid.NewString()[:8] + "@example.com",
		PromoteKind:      models.PromoteApprovalKindStack,
		PromotePayload:   []byte(`{"from":"staging","to":"production"}`),
		FromEnv:          "staging",
		ToEnv:            "production",
		TTL:              ttl,
	})
	require.NoError(t, err, "create approve-block approval")

	if status != models.PromoteApprovalStatusPending {
		_, err = db.Exec(`UPDATE promote_approvals SET status=$1 WHERE id=$2`, status, row.ID)
		require.NoError(t, err, "set approval status")
		row.Status = status
	}
	if expiresIn < 0 {
		_, err = db.Exec(`UPDATE promote_approvals SET expires_at = now() - interval '1 hour' WHERE id=$1`, row.ID)
		require.NoError(t, err, "force-expire approval")
		row.ExpiresAt = time.Now().UTC().Add(-time.Hour)
	}
	return row
}

// approveBlockGet issues a GET /approve/:token through the test app and returns
// the *http.Response WITHOUT following the redirect (fiber's app.Test does not
// auto-follow), so the caller can assert on the 302 + Location header. The
// X-Forwarded-For header pins the per-IP rate-limit bucket so each test gets a
// fresh budget regardless of test ordering. Body is left open for the caller to
// read + close.
func approveBlockGet(t *testing.T, app *fiber.App, token, clientIP string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/approve/"+token, nil)
	if clientIP != "" {
		req.Header.Set("X-Forwarded-For", clientIP)
	}
	resp, err := app.Test(req, 5000)
	require.NoError(t, err, "GET /approve/%s", token)
	return resp
}

// approveBlockStatusOf reads the persisted status of a promote_approvals row by
// id — the source-of-truth assertion that the handler's state change actually
// landed in Postgres (not merely that it returned a 302).
func approveBlockStatusOf(t *testing.T, db *sql.DB, id uuid.UUID) string {
	t.Helper()
	var status string
	require.NoError(t,
		db.QueryRow(`SELECT status FROM promote_approvals WHERE id=$1`, id).Scan(&status),
		"read approval status")
	return status
}
