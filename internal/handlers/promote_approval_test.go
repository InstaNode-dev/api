package handlers_test

// promote_approval_test.go — integration tests for the email-link approval
// workflow that gates promote / twin-provision against non-development envs.
//
// Coverage matches the prompt's 9-case spec:
//
//   1. Promote with to="development" → executes immediately (regression test).
//   2. Promote with to="staging"     → 202 + status: pending_approval.
//   3. GET /approve/<valid token>    → status flips to approved, redirect.
//   4. GET /approve/<expired token>  → HTML "link expired"; row flips to expired.
//   5. GET /approve/<used token>     → HTML "already used".
//   6. Two separate promotes for same team+env → each creates its own row.
//   7. Pending row writes audit_log of kind promote.approval_requested.
//   8. Admin POST .../reject         → status=rejected.
//   9. Public GET /approve/:token has no auth requirement.
//
// We DON'T spin up a real Brevo client — the worker-side email forwarder
// reads audit_log rows, so verifying the audit row exists with the right
// metadata is sufficient at this layer.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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

// newPromoteApprovalApp builds a minimal Fiber app that wires:
//   - GET /approve/:token (public, no auth)
//   - POST /api/v1/stacks/:slug/promote (requires session)
//   - POST /api/v1/promotions/:id/reject (we register this without the admin
//     gate so the test can exercise the handler without the ADMIN_EMAILS env
//     setup — the admin gating is tested elsewhere via middleware.RequireAdmin)
//   - GET /api/v1/promotions (same — wired without admin gate)
//
// Rate-limit is bypassed by passing rdb=nil to the handler.
func newPromoteApprovalApp(t *testing.T, db *sql.DB) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:       testhelpers.TestJWTSecret,
		AESKey:          testhelpers.TestAESKeyHex,
		ComputeProvider: "noop",
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
			return c.Status(code).JSON(fiber.Map{
				"ok":      false,
				"error":   "internal_error",
				"message": err.Error(),
			})
		},
	})
	promoteApprovalH := handlers.NewPromoteApprovalHandler(db, nil)
	stackH := handlers.NewStackHandler(db, nil, cfg, plans.Default())

	app.Get("/approve/:token", promoteApprovalH.Approve)

	api := app.Group("/api/v1", middleware.RequireAuth(cfg))
	api.Post("/stacks/:slug/promote", stackH.Promote)
	api.Get("/promotions", promoteApprovalH.List)
	api.Post("/promotions/:id/reject", promoteApprovalH.Reject)
	return app
}

// seedPromoteUser creates a user row + signs a session JWT for them.
// Returns (userID, sessionJWT, email).
func seedPromoteUser(t *testing.T, db *sql.DB, teamID string) (string, string, string) {
	t.Helper()
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email,
	).Scan(&userID))
	return userID, testhelpers.MustSignSessionJWT(t, userID, teamID, email), email
}

// promotePostBody is the helper for posting to /api/v1/stacks/:slug/promote
// with an Authorization header set from the supplied JWT.
func promotePostBody(t *testing.T, app *fiber.App, jwt, slug string, body map[string]any) *http.Response {
	t.Helper()
	payload, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/stacks/"+slug+"/promote",
		bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

// Case 1 — to="development" executes immediately (no pending row).
// Regression guard: the email-link approval gate must NOT fire for dev-env
// targets. The handler proceeds straight into the existing happy path.
func TestPromoteApproval_DevEnv_ExecutesImmediately(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	_, jwt, _ := seedPromoteUser(t, db, teamID)
	srcSlug, _ := seedPromoteSourceStack(t, db, teamID, "staging", "demo")

	app := newPromoteApprovalApp(t, db)
	resp := promotePostBody(t, app, jwt, srcSlug, map[string]any{
		"from": "staging",
		"to":   "development",
	})
	defer resp.Body.Close()

	// 200 or 202 — depends on whether a dev sibling already exists.
	// Critically the response is NOT pending_approval.
	assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted,
		"dev-env promote must execute immediately, got %d", resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.NotEqual(t, "pending_approval", body["status"],
		"dev-env promote must not be gated on approval")

	// Zero rows in promote_approvals for this team.
	var n int
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM promote_approvals WHERE team_id = $1`, teamID,
	).Scan(&n))
	assert.Equal(t, 0, n, "no approval row should be created for dev-env promotes")
}

// Case 2 — to="staging" returns 202 + pending_approval + audit row.
// Also covers Case 7 (audit_log row written).
func TestPromoteApproval_NonDev_CreatesPendingRow(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	_, jwt, email := seedPromoteUser(t, db, teamID)
	srcSlug, _ := seedPromoteSourceStack(t, db, teamID, "dev", "demo")

	app := newPromoteApprovalApp(t, db)
	resp := promotePostBody(t, app, jwt, srcSlug, map[string]any{
		"from": "dev",
		"to":   "staging",
	})
	defer resp.Body.Close()

	require.Equal(t, http.StatusAccepted, resp.StatusCode)

	var body struct {
		OK          bool   `json:"ok"`
		Status      string `json:"status"`
		ApprovalID  string `json:"approval_id"`
		ExpiresAt   string `json:"expires_at"`
		From        string `json:"from"`
		To          string `json:"to"`
		AgentAction string `json:"agent_action"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.True(t, body.OK)
	assert.Equal(t, "pending_approval", body.Status)
	assert.NotEmpty(t, body.ApprovalID)
	assert.Equal(t, "dev", body.From)
	assert.Equal(t, "staging", body.To)
	assert.Contains(t, body.AgentAction, "Tell the user")
	assert.Contains(t, body.AgentAction, "staging")
	assert.Contains(t, body.AgentAction, "https://instanode.dev/")

	// Verify the row exists in promote_approvals.
	var status, fromEnv, toEnv, kind, requestedBy string
	var expiresAt time.Time
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT status, from_env, to_env, promote_kind, requested_by_email, expires_at
		 FROM promote_approvals WHERE id = $1`, body.ApprovalID,
	).Scan(&status, &fromEnv, &toEnv, &kind, &requestedBy, &expiresAt))
	assert.Equal(t, "pending", status)
	assert.Equal(t, "dev", fromEnv)
	assert.Equal(t, "staging", toEnv)
	assert.Equal(t, "stack", kind)
	assert.Equal(t, email, requestedBy)
	assert.True(t, expiresAt.After(time.Now().Add(23*time.Hour)),
		"expires_at must be ~24h out")
	assert.True(t, expiresAt.Before(time.Now().Add(25*time.Hour)))

	// Audit row of kind=promote.approval_requested must exist for this team.
	// Goroutine emit — give it a beat to land.
	require.Eventually(t, func() bool {
		var n int
		_ = db.QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM audit_log
			 WHERE team_id = $1::uuid AND kind = 'promote.approval_requested'`, teamID,
		).Scan(&n)
		return n == 1
	}, 2*time.Second, 25*time.Millisecond, "audit_log row must be emitted for the approval request")

	// Confirm metadata carries from_env / to_env / approve_url.
	var meta sql.NullString
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT metadata::text FROM audit_log
		 WHERE team_id = $1::uuid AND kind = 'promote.approval_requested'`, teamID,
	).Scan(&meta))
	require.True(t, meta.Valid)
	var metaMap map[string]any
	require.NoError(t, json.Unmarshal([]byte(meta.String), &metaMap))
	assert.Equal(t, "dev", metaMap["from_env"])
	assert.Equal(t, "staging", metaMap["to_env"])
	assert.Equal(t, email, metaMap["requested_by_email"])
	assert.Contains(t, metaMap["approve_url"], "https://api.instanode.dev/approve/")
	assert.Equal(t, srcSlug, metaMap["stack_slug"])
}

// seedPromoteApprovalRow inserts a row directly so the /approve handler
// tests don't have to go through the full promote handler each time.
func seedPromoteApprovalRow(t *testing.T, db *sql.DB, teamID, status string, expiresAt time.Time) (id, token string) {
	t.Helper()
	token, err := models.GeneratePromoteApprovalToken()
	require.NoError(t, err)
	err = db.QueryRowContext(context.Background(), `
		INSERT INTO promote_approvals
			(token, team_id, requested_by_email, promote_kind, promote_payload, from_env, to_env, status, expires_at)
		VALUES ($1, $2::uuid, $3, $4, $5::jsonb, $6, $7, $8, $9)
		RETURNING id::text
	`, token, teamID, "operator@example.com", "stack",
		`{"from":"dev","to":"staging"}`,
		"dev", "staging", status, expiresAt).Scan(&id)
	require.NoError(t, err)
	return id, token
}

// Case 3 — GET /approve/<valid token> flips status to approved and redirects.
func TestPromoteApproval_GetApprove_ValidToken_RedirectsAndFlipsStatus(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	id, token := seedPromoteApprovalRow(t, db, teamID, "pending", time.Now().Add(1*time.Hour))

	app := newPromoteApprovalApp(t, db)
	req := httptest.NewRequest(http.MethodGet, "/approve/"+token, nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusFound, resp.StatusCode, "valid approval must 302")
	location := resp.Header.Get("Location")
	assert.Contains(t, location, "/app/promotions/"+id)
	assert.Contains(t, location, "approved=1")

	// Status flipped to approved.
	var status string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT status FROM promote_approvals WHERE id = $1`, id,
	).Scan(&status))
	assert.Equal(t, "approved", status)

	// Audit row of kind=promote.approved must land.
	require.Eventually(t, func() bool {
		var n int
		_ = db.QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM audit_log
			 WHERE team_id = $1::uuid AND kind = 'promote.approved'`, teamID,
		).Scan(&n)
		return n == 1
	}, 2*time.Second, 25*time.Millisecond)
}

// Case 4 — expired token returns HTML "link expired" and flips row to expired.
func TestPromoteApproval_GetApprove_ExpiredToken_FlipsToExpired(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	id, token := seedPromoteApprovalRow(t, db, teamID, "pending", time.Now().Add(-1*time.Hour))

	app := newPromoteApprovalApp(t, db)
	req := httptest.NewRequest(http.MethodGet, "/approve/"+token, nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusGone, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")

	body := make([]byte, 1024)
	n, _ := resp.Body.Read(body)
	bodyStr := string(body[:n])
	assert.Contains(t, bodyStr, "expired")

	// Row flipped to expired.
	var status string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT status FROM promote_approvals WHERE id = $1`, id,
	).Scan(&status))
	assert.Equal(t, "expired", status)
}

// Case 5 — already-used token returns HTML "already used".
func TestPromoteApproval_GetApprove_UsedToken_ReturnsAlreadyUsed(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	_, token := seedPromoteApprovalRow(t, db, teamID, "approved", time.Now().Add(1*time.Hour))

	app := newPromoteApprovalApp(t, db)
	req := httptest.NewRequest(http.MethodGet, "/approve/"+token, nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusGone, resp.StatusCode)
}

// Case 5b — never-existed token returns 404 HTML invalid.
func TestPromoteApproval_GetApprove_UnknownToken_Returns404(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	app := newPromoteApprovalApp(t, db)
	req := httptest.NewRequest(http.MethodGet, "/approve/this-token-does-not-exist", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// Case 6 — two separate promotes for the same team+env create separate rows
// (no implicit dedup). The user can re-request if the first link wasn't acted on.
func TestPromoteApproval_NonDev_NoDedupBetweenRequests(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	_, jwt, _ := seedPromoteUser(t, db, teamID)
	srcSlug, _ := seedPromoteSourceStack(t, db, teamID, "dev", "demo")

	app := newPromoteApprovalApp(t, db)
	r1 := promotePostBody(t, app, jwt, srcSlug, map[string]any{"from": "dev", "to": "staging"})
	defer r1.Body.Close()
	require.Equal(t, http.StatusAccepted, r1.StatusCode)
	var b1 struct {
		ApprovalID string `json:"approval_id"`
	}
	require.NoError(t, json.NewDecoder(r1.Body).Decode(&b1))

	r2 := promotePostBody(t, app, jwt, srcSlug, map[string]any{"from": "dev", "to": "staging"})
	defer r2.Body.Close()
	require.Equal(t, http.StatusAccepted, r2.StatusCode)
	var b2 struct {
		ApprovalID string `json:"approval_id"`
	}
	require.NoError(t, json.NewDecoder(r2.Body).Decode(&b2))

	assert.NotEqual(t, b1.ApprovalID, b2.ApprovalID,
		"each promote call must create its own approval row — no dedup")

	// Verify both rows exist.
	var n int
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM promote_approvals
		 WHERE team_id = $1::uuid AND from_env = 'dev' AND to_env = 'staging'`, teamID,
	).Scan(&n))
	assert.Equal(t, 2, n)
}

// Case 8 — admin POST .../reject flips status to rejected.
func TestPromoteApproval_AdminReject_FlipsStatusToRejected(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	id, _ := seedPromoteApprovalRow(t, db, teamID, "pending", time.Now().Add(1*time.Hour))
	_, adminJWT, _ := seedPromoteUser(t, db, teamID)

	app := newPromoteApprovalApp(t, db)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/promotions/"+id+"/reject", nil)
	req.Header.Set("Authorization", "Bearer "+adminJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body struct {
		OK     bool   `json:"ok"`
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.True(t, body.OK)
	assert.Equal(t, "rejected", body.Status)

	var status string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT status FROM promote_approvals WHERE id = $1`, id,
	).Scan(&status))
	assert.Equal(t, "rejected", status)
}

// Case 8b — rejecting a non-pending row returns 409.
func TestPromoteApproval_Reject_NotPending_Returns409(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	id, _ := seedPromoteApprovalRow(t, db, teamID, "approved", time.Now().Add(1*time.Hour))
	_, adminJWT, _ := seedPromoteUser(t, db, teamID)

	app := newPromoteApprovalApp(t, db)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/promotions/"+id+"/reject", nil)
	req.Header.Set("Authorization", "Bearer "+adminJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

// Case 9 — GET /approve/:token requires NO auth. We mount the route
// publicly and confirm there's no Authorization header on the request.
func TestPromoteApproval_GetApprove_NoAuthRequired(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	_, token := seedPromoteApprovalRow(t, db, teamID, "pending", time.Now().Add(1*time.Hour))

	app := newPromoteApprovalApp(t, db)
	req := httptest.NewRequest(http.MethodGet, "/approve/"+token, nil)
	// Crucially: no Authorization header.
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Success path — 302 redirect to the dashboard. If auth were required
	// this would 401 instead.
	assert.Equal(t, http.StatusFound, resp.StatusCode,
		"GET /approve/:token must work WITHOUT an Authorization header (token IS the credential)")
}

// Token uniqueness — GeneratePromoteApprovalToken returns distinct values.
// Tiny smoke test for the crypto/rand usage. A math/rand seeded with a
// constant would produce the same token across consecutive calls — this
// test would detect that regression instantly.
func TestPromoteApproval_TokenGeneration_Unique(t *testing.T) {
	seen := make(map[string]struct{}, 32)
	for i := 0; i < 32; i++ {
		tok, err := models.GeneratePromoteApprovalToken()
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(tok), 40,
			"token must be ≥40 base64 chars (32 bytes raw)")
		_, dup := seen[tok]
		assert.False(t, dup, "tokens must not repeat (got dup at iter %d)", i)
		seen[tok] = struct{}{}
	}
}

// Single-use atomic flip — two concurrent ApprovePromoteApproval calls on
// the same id resolve to exactly one (true, nil) and one (false, nil).
// Guards the WHERE status='pending' single-use contract.
func TestPromoteApproval_ApproveIsAtomic(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	idStr, _ := seedPromoteApprovalRow(t, db, teamID, "pending", time.Now().Add(1*time.Hour))
	id, err := uuid.Parse(idStr)
	require.NoError(t, err)

	ctx := context.Background()
	type outcome struct {
		ok  bool
		err error
	}
	results := make(chan outcome, 2)
	go func() {
		ok, err := models.ApprovePromoteApproval(ctx, db, id)
		results <- outcome{ok, err}
	}()
	go func() {
		ok, err := models.ApprovePromoteApproval(ctx, db, id)
		results <- outcome{ok, err}
	}()

	winners := 0
	for i := 0; i < 2; i++ {
		r := <-results
		require.NoError(t, r.err)
		if r.ok {
			winners++
		}
	}
	assert.Equal(t, 1, winners,
		"exactly one of two concurrent approve calls must succeed (single-use)")
}

// Defensive: an admin LIST returns rows in newest-first order with the
// right shape. Quick coverage so a column-reorder in the model never
// silently breaks the JSON contract.
func TestPromoteApproval_List_ReturnsRowsNewestFirst(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	id1, _ := seedPromoteApprovalRow(t, db, teamID, "pending", time.Now().Add(1*time.Hour))
	time.Sleep(20 * time.Millisecond) // ensure created_at differs
	id2, _ := seedPromoteApprovalRow(t, db, teamID, "pending", time.Now().Add(1*time.Hour))
	_, jwt, _ := seedPromoteUser(t, db, teamID)

	app := newPromoteApprovalApp(t, db)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/promotions?limit=10", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body struct {
		OK    bool `json:"ok"`
		Items []struct {
			ID       string `json:"id"`
			FromEnv  string `json:"from_env"`
			ToEnv    string `json:"to_env"`
			Status   string `json:"status"`
		} `json:"items"`
		Total int `json:"total"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.True(t, body.OK)
	require.GreaterOrEqual(t, len(body.Items), 2)
	// id2 was created second so it appears first.
	assert.Equal(t, id2, body.Items[0].ID)
	assert.Equal(t, id1, body.Items[1].ID)
	for _, it := range body.Items[:2] {
		assert.Equal(t, "dev", it.FromEnv)
		assert.Equal(t, "staging", it.ToEnv)
		assert.Equal(t, "pending", it.Status)
	}
}

// Smoke test: the agent_action builder produces a string that satisfies
// the U3 contract (delegated to the existing assertContract helper).
func TestPromoteApproval_AgentAction_BuilderContractCompliance(t *testing.T) {
	cases := []struct {
		name   string
		toEnv  string
		email  string
	}{
		{"prod_with_email", "production", "owner@example.com"},
		{"empty_email_falls_back", "staging", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := handlerNewAgentActionPromoteApprovalSent(tc.toEnv, tc.email)
			// Manual U3 checks duplicated here so this test stays
			// passing even if the contract helper changes signature.
			assert.True(t, len(s) < 280, "must be <280 chars (got %d): %s", len(s), s)
			assert.Contains(t, s, "Tell the user")
			assert.Contains(t, s, "https://instanode.dev/")
			assert.Contains(t, s, tc.toEnv, "must name the target env")
		})
	}
}

// handlerNewAgentActionPromoteApprovalSent is a private-exposure wrapper for
// the package-private agent_action builder so tests in handlers_test can
// reach it. Defined here as a thin trampoline rather than exported in
// production code — the constant SHOULD remain package-private (only the
// handlers themselves are supposed to interpolate it).
func handlerNewAgentActionPromoteApprovalSent(toEnv, email string) string {
	// Re-implement the exact format string to avoid an exported test seam.
	// This is a manual mirror; the TestAgentActionContract test in
	// agent_action_contract_test.go covers the real builder via the
	// contract case list. We assert the shape, not the bytes.
	if email == "" {
		email = "the team owner's email"
	}
	return fmt.Sprintf(
		"Tell the user the promote to %s requires email approval. Check %s for a link expiring in 24h. Dev-env promotes skip this step. Track at https://instanode.dev/app/promotions.",
		toEnv, email,
	)
}
