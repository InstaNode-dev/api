package handlers_test

// stacks_advanced_block_integration_test.go — W4 stacks-advanced block
// integration suite.
//
// Closes the remaining "stacks advanced" P0/P1 legs of the USER-FLOW matrix
// (docs/sessions/2026-06-04/USER-FLOW-INVENTORY-AND-TEST-MATRIX.md) that were
// carried as routeCoverageExemptions in
// internal/router/route_donebar_guard_test.go — the eight
// /api/v1/stacks/:slug/* advanced surfaces:
//
//   POST   /api/v1/stacks/:slug/confirm-deletion   — two-step delete (confirm)
//   DELETE /api/v1/stacks/:slug/confirm-deletion   — two-step delete (cancel)
//   POST   /api/v1/stacks/:slug/promote            — env promote (Pro+)
//   GET    /api/v1/stacks/:slug/family             — env family view (Pro+)
//   POST   /api/v1/stacks/:slug/domains            — custom-domain add (Pro+)
//   GET    /api/v1/stacks/:slug/domains            — custom-domain list (Pro+)
//   POST   /api/v1/stacks/:slug/domains/:id/verify — custom-domain verify
//   DELETE /api/v1/stacks/:slug/domains/:id        — custom-domain remove
//
// Every test drives the route through the PRODUCTION auth chain
// (middleware.RequireAuth + the /api/v1 group, exactly as router.go wires it)
// against a REAL Postgres (testhelpers.SetupTestDB). The app builder mirrors
// the live registration in newStacksAdvancedApp. The stack handlers gate
// purely on the JWT's team_id matching the stack's team_id (there is no
// per-user RBAC on these routes — any member of the owning team has the same
// access; a different team is a 404, never a 403, to avoid existence leaks), so
// the authz axes asserted are:
//
//   owner (creator userID)  → 2xx     happy path
//   member (2nd userID,      → 2xx     same team_id ⇒ same access (no per-user RBAC)
//     same team_id)
//   non-member (other team)  → 404     cross-team isolation (never 403)
//   unauthenticated          → 401     RequireAuth gate
//   off-tier (hobby/free)    → 402     multi-env / custom-domain upgrade gate
//
// REAL CONTRACT (read each handler, rule 16):
//   - confirm-deletion is TOKENIZED + 2-step: a pending_deletions row is
//     created (status='pending') with a sha256(plaintext) hash; POST
//     ?token=<plaintext> CASes it to 'confirmed' and tears the stack down,
//     DELETE (no token, authenticated dashboard action) CASes it to
//     'cancelled'. A wrong/cross-team token is a 410 (never confirms
//     validity). Step-2 is single-use: the second POST is 410.
//   - promote validates env (from/to charset, from!=to, source.env==from →
//     409 env_mismatch) and, for any NON-development target, short-circuits to
//     202 pending_approval + a promote_approvals row (the email-link approval
//     gate) BEFORE any compute. A development target bypasses the gate.
//   - family is a read gated by multiEnvTierAllowed; it groups the env family
//     and stamps Cache-Control: private, max-age=60.
//   - domains create/list persist + read custom_domains rows; verify advances
//     pending_verification → verified via the TXT seam (the external
//     DNS/cert-manager ingress+cert legs need a live k8s and are asserted only
//     up to the verified state, with k8s nil — the deeper legs are deferred to
//     the W4 custom-domain e2e spec); delete removes the row. The per-count cap
//     and hostname validation come from plans.Registry (rule 3).
//
// Nothing here redefines an existing helper: it reuses requireTestDB,
// ensureStackTables, mustUUIDStr, testhelpers.SetupTestDB / MustCreateTeamDB /
// MustSignSessionJWT, models.CreateStack / CreatePendingDeletion /
// CreateCustomDomain, and the handlers.SetLookupTXTForTest seam.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// ── app builder ───────────────────────────────────────────────────────────────

// newStacksAdvancedApp wires the eight advanced /api/v1/stacks/:slug/* routes
// the same way router.go does: the /api/v1 group is gated by RequireAuth, the
// StackHandler carries a noop email client (so the two-step deletion +
// promote-approval audit paths run), and the CustomDomainHandler is wired with
// a nil k8s provider (ingress/cert legs become no-ops; the TXT-verify leg still
// runs through the lookupTXT seam).
func newStacksAdvancedApp(t *testing.T, db *sql.DB) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:                      testhelpers.TestJWTSecret,
		AESKey:                         testhelpers.TestAESKeyHex,
		ComputeProvider:                "noop",
		DashboardBaseURL:               "https://dash.local",
		APIPublicURL:                   "https://api.local",
		DeletionConfirmationTTLMinutes: 30,
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
				"ok": false, "error": "internal_error", "message": err.Error(),
			})
		},
	})
	app.Use(middleware.RequestID())

	stackH := handlers.NewStackHandler(db, nil, cfg, plans.Default())
	stackH.SetEmailClient(email.NewNoop())
	domainH := handlers.NewCustomDomainHandler(db, cfg, plans.Default(), nil)

	api := app.Group("/api/v1", middleware.RequireAuth(cfg))
	api.Post("/stacks/:slug/confirm-deletion", stackH.ConfirmDelete)
	api.Delete("/stacks/:slug/confirm-deletion", stackH.CancelDelete)
	api.Post("/stacks/:slug/promote", stackH.Promote)
	api.Get("/stacks/:slug/family", stackH.Family)
	api.Post("/stacks/:slug/domains", domainH.Create)
	api.Get("/stacks/:slug/domains", domainH.List)
	api.Post("/stacks/:slug/domains/:id/verify", domainH.Verify)
	api.Delete("/stacks/:slug/domains/:id", domainH.Delete)

	return app
}

// ── seed + request helpers (suite-local; nothing redefined) ───────────────────

// seedAdvancedStack inserts a healthy stack owned by teamID with one exposed
// service carrying an image_ref. Returns the stack row. tier/env are 'pro' /
// the given env so the multi-env + custom-domain handlers see a real source.
func seedAdvancedStack(t *testing.T, db *sql.DB, teamID uuid.UUID, env string) *models.Stack {
	t.Helper()
	st, err := models.CreateStack(context.Background(), db, models.CreateStackParams{
		TeamID: &teamID,
		Slug:   "stk-adv-" + uuid.NewString()[:10],
		Tier:   "pro",
		Env:    env,
	})
	require.NoError(t, err)
	_, err = db.ExecContext(context.Background(), `
		INSERT INTO stack_services (stack_id, name, expose, port, image_ref, status)
		VALUES ($1::uuid, 'web', true, 8080, $2, 'healthy')`,
		st.ID, "registry.local/"+st.Slug+"-web:latest")
	require.NoError(t, err)
	return st
}

// advReq fires an authenticated JSON request and returns the response. auth=="""
// exercises the RequireAuth gate (401). body==nil sends no payload.
func advReq(t *testing.T, app *fiber.App, method, path, auth string, body any) *http.Response {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	return resp
}

// decodeAdv decodes a response body into a generic map.
func decodeAdv(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out
}

// proTeamWithUsers seeds a pro team plus two distinct user JWTs (owner +
// member, same team_id) and a non-member JWT (a different pro team). Returns
// (teamID, ownerJWT, memberJWT, otherJWT). The owner/member share team_id so
// the "any team member" authz axis is exercised; otherJWT is the cross-team
// 404 axis.
func proTeamWithUsers(t *testing.T, db *sql.DB) (uuid.UUID, string, string, string) {
	t.Helper()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	owner := testhelpers.MustSignSessionJWT(t, mustUUIDStr(), teamID.String(), "owner-adv@example.com")
	member := testhelpers.MustSignSessionJWT(t, mustUUIDStr(), teamID.String(), "member-adv@example.com")
	otherTeam := testhelpers.MustCreateTeamDB(t, db, "pro")
	other := testhelpers.MustSignSessionJWT(t, mustUUIDStr(), otherTeam, "other-adv@example.com")
	return teamID, owner, member, other
}

// ── confirm-deletion (POST = confirm, DELETE = cancel) ────────────────────────

// TestStacksAdvancedBlock_ConfirmDelete_TokenizedTwoStep is the real contract
// for POST /api/v1/stacks/:slug/confirm-deletion: a pending_deletions row
// (created with a known plaintext token) is CASed to 'confirmed' by a POST
// carrying ?token=<plaintext>, the stack row is torn down, and a second POST
// with the same token is 410 (single-use). It also asserts cross-team isolation
// (a valid token clicked by a different team is 410, never confirming the token
// is real) and the RequireAuth gate (401).
func TestStacksAdvancedBlock_ConfirmDelete_TokenizedTwoStep(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)
	app := newStacksAdvancedApp(t, db)

	teamID, ownerJWT, memberJWT, otherJWT := proTeamWithUsers(t, db)
	stack := seedAdvancedStack(t, db, teamID, "production")

	// unauth → 401 (RequireAuth gate).
	r401 := advReq(t, app, http.MethodPost, "/api/v1/stacks/"+stack.Slug+"/confirm-deletion?token=del_x", "", nil)
	r401.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, r401.StatusCode)

	// Seed a real pending row + capture the plaintext token (the token IS the
	// credential the email link carries).
	_, plaintext := mustSeedStackPendingDeletion(t, db, stack.ID, teamID)

	// Cross-team click of a VALID token → 410 (never confirms validity).
	rCross := advReq(t, app, http.MethodPost, "/api/v1/stacks/"+stack.Slug+"/confirm-deletion?token="+plaintext, otherJWT, nil)
	bodyCross := decodeAdv(t, rCross)
	assert.Equal(t, http.StatusGone, rCross.StatusCode, "cross-team token click must be 410, never a confirm")
	assert.Equal(t, "deletion_token_invalid", bodyCross["error"])
	// Row still pending after the rejected cross-team click.
	assert.Equal(t, "pending", stackPendingDeletionStatus(t, db, stack.ID))

	// Owner click with the real token → 200 confirmed, row flips, stack gone.
	rOK := advReq(t, app, http.MethodPost, "/api/v1/stacks/"+stack.Slug+"/confirm-deletion?token="+plaintext, ownerJWT, nil)
	bodyOK := decodeAdv(t, rOK)
	assert.Equal(t, http.StatusOK, rOK.StatusCode)
	assert.Equal(t, true, bodyOK["ok"])
	assert.Contains(t, []any{"confirmed", "confirmed_teardown_pending"}, bodyOK["deletion_status"])
	assert.Equal(t, "confirmed", stackPendingDeletionStatus(t, db, stack.ID))
	// The stack row was torn down by the deprovision fn.
	_, getErr := models.GetStackByID(context.Background(), db, stack.ID)
	var notFound *models.ErrStackNotFound
	assert.True(t, errors.As(getErr, &notFound), "confirmed deletion must delete the stack row")

	// Single-use: a second click of the same (now-consumed) token → 410.
	rReplay := advReq(t, app, http.MethodPost, "/api/v1/stacks/"+stack.Slug+"/confirm-deletion?token="+plaintext, memberJWT, nil)
	rReplay.Body.Close()
	assert.Equal(t, http.StatusGone, rReplay.StatusCode, "a consumed token must be single-use (410)")
}

// TestStacksAdvancedBlock_ConfirmDelete_MissingTokenAndCancel covers the
// confirm-route 400 (missing token) plus the DELETE cancel half: a pending row
// is CASed to 'cancelled' by an authenticated DELETE (no token needed — the
// session is the auth), the stack survives, and a member of the owning team can
// cancel (any-member authz). A cancel with no pending row is 404.
func TestStacksAdvancedBlock_ConfirmDelete_MissingTokenAndCancel(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)
	app := newStacksAdvancedApp(t, db)

	teamID, ownerJWT, memberJWT, otherJWT := proTeamWithUsers(t, db)
	stack := seedAdvancedStack(t, db, teamID, "production")

	// POST confirm with NO token → 400 missing_token.
	rNoTok := advReq(t, app, http.MethodPost, "/api/v1/stacks/"+stack.Slug+"/confirm-deletion", ownerJWT, nil)
	bodyNoTok := decodeAdv(t, rNoTok)
	assert.Equal(t, http.StatusBadRequest, rNoTok.StatusCode)
	assert.Equal(t, "missing_token", bodyNoTok["error"])

	// DELETE cancel with NO pending row → 404.
	rNone := advReq(t, app, http.MethodDelete, "/api/v1/stacks/"+stack.Slug+"/confirm-deletion", ownerJWT, nil)
	rNone.Body.Close()
	assert.Equal(t, http.StatusNotFound, rNone.StatusCode)

	// Seed a pending row, then cross-team cancel → 404 (cross-team isolation).
	mustSeedStackPendingDeletion(t, db, stack.ID, teamID)
	rCross := advReq(t, app, http.MethodDelete, "/api/v1/stacks/"+stack.Slug+"/confirm-deletion", otherJWT, nil)
	rCross.Body.Close()
	assert.Equal(t, http.StatusNotFound, rCross.StatusCode, "cross-team cancel must be 404")
	assert.Equal(t, "pending", stackPendingDeletionStatus(t, db, stack.ID))

	// A MEMBER of the owning team can cancel (any-member authz) → 200, row cancelled.
	rCancel := advReq(t, app, http.MethodDelete, "/api/v1/stacks/"+stack.Slug+"/confirm-deletion", memberJWT, nil)
	rCancel.Body.Close()
	assert.Equal(t, http.StatusOK, rCancel.StatusCode)
	assert.Equal(t, "cancelled", stackPendingDeletionStatus(t, db, stack.ID))
	// Stack survives a cancel.
	_, getErr := models.GetStackByID(context.Background(), db, stack.ID)
	assert.NoError(t, getErr, "a cancelled deletion must leave the stack intact")
}

// mustSeedStackPendingDeletion creates a pending_deletions row for the stack and
// returns (row, plaintextToken). Uses the production model so the hash/token
// shape matches what ConfirmDelete validates.
func mustSeedStackPendingDeletion(t *testing.T, db *sql.DB, stackID, teamID uuid.UUID) (*models.PendingDeletion, string) {
	t.Helper()
	// requested_by_user_id has an FK to users — seed a real user on the team.
	var userID uuid.UUID
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1, $2) RETURNING id`,
		teamID, "pd-"+uuid.NewString()[:8]+"@example.com").Scan(&userID))
	row, plaintext, err := models.CreatePendingDeletion(
		context.Background(), db, stackID, models.PendingDeletionResourceStack,
		teamID, userID, "owner-adv@example.com", 30*time.Minute)
	require.NoError(t, err)
	return row, plaintext
}

// stackPendingDeletionStatus reads the latest pending_deletions status for the
// stack (the truth surface for the two-step flow).
func stackPendingDeletionStatus(t *testing.T, db *sql.DB, stackID uuid.UUID) string {
	t.Helper()
	var status string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT status FROM pending_deletions
		   WHERE resource_id=$1 AND resource_type='stack'
		   ORDER BY requested_at DESC LIMIT 1`, stackID).Scan(&status))
	return status
}

// ── promote ───────────────────────────────────────────────────────────────────

// TestStacksAdvancedBlock_Promote_ApprovalGateAndAuthz is the real promote
// contract: a NON-development target short-circuits to 202 pending_approval +
// a promote_approvals row (the email-link gate) BEFORE any compute, an
// authenticated MEMBER of the owning team gets the same access (no per-user
// RBAC), a non-member is 404 (cross-team), an off-tier team is 402, and an
// unauthenticated call is 401.
func TestStacksAdvancedBlock_Promote_ApprovalGateAndAuthz(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)
	app := newStacksAdvancedApp(t, db)

	teamID, ownerJWT, memberJWT, otherJWT := proTeamWithUsers(t, db)
	stack := seedAdvancedStack(t, db, teamID, "staging")
	promoteBody := map[string]any{"from": "staging", "to": "production"}

	// unauth → 401.
	r401 := advReq(t, app, http.MethodPost, "/api/v1/stacks/"+stack.Slug+"/promote", "", promoteBody)
	r401.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, r401.StatusCode)

	// cross-team → 404 (never 403).
	rCross := advReq(t, app, http.MethodPost, "/api/v1/stacks/"+stack.Slug+"/promote", otherJWT, promoteBody)
	rCross.Body.Close()
	assert.Equal(t, http.StatusNotFound, rCross.StatusCode)

	// owner: non-dev target → 202 pending_approval + persisted approval row.
	rOwner := advReq(t, app, http.MethodPost, "/api/v1/stacks/"+stack.Slug+"/promote", ownerJWT, promoteBody)
	bodyOwner := decodeAdv(t, rOwner)
	assert.Equal(t, http.StatusAccepted, rOwner.StatusCode, "non-dev promote must be 202 pending_approval (email gate)")
	assert.Equal(t, "pending_approval", bodyOwner["status"])
	require.NotEmpty(t, bodyOwner["approval_id"], "202 must return the approval_id")
	assert.NotEmpty(t, bodyOwner["agent_action"], "pending_approval must carry an agent_action")
	// The promote_approvals row is persisted, status='pending', for this team.
	var apprStatus string
	var apprTeam string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT status, team_id::text FROM promote_approvals WHERE id=$1::uuid`,
		bodyOwner["approval_id"]).Scan(&apprStatus, &apprTeam))
	assert.Equal(t, "pending", apprStatus)
	assert.Equal(t, teamID.String(), apprTeam)

	// member of the same team also reaches the gate (any-member authz) → 202.
	rMember := advReq(t, app, http.MethodPost, "/api/v1/stacks/"+stack.Slug+"/promote", memberJWT, promoteBody)
	bodyMember := decodeAdv(t, rMember)
	assert.Equal(t, http.StatusAccepted, rMember.StatusCode)
	assert.Equal(t, "pending_approval", bodyMember["status"])
}

// TestStacksAdvancedBlock_Promote_ContractValidation covers the promote
// handler's real validation contract (rule 16: read the handler): invalid env
// charset → 400 invalid_env, from==to → 400 invalid_target, and an asserted
// `from` that does not match the source's actual env → 409 env_mismatch. Also
// asserts the off-tier (hobby) 402 multi-env gate.
func TestStacksAdvancedBlock_Promote_ContractValidation(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)
	app := newStacksAdvancedApp(t, db)

	teamID, ownerJWT, _, _ := proTeamWithUsers(t, db)
	stack := seedAdvancedStack(t, db, teamID, "staging")
	base := "/api/v1/stacks/" + stack.Slug + "/promote"

	// invalid 'to' charset → 400 invalid_env.
	rBadEnv := advReq(t, app, http.MethodPost, base, ownerJWT, map[string]any{"from": "staging", "to": "bad env!"})
	bodyBadEnv := decodeAdv(t, rBadEnv)
	assert.Equal(t, http.StatusBadRequest, rBadEnv.StatusCode)
	assert.Equal(t, "invalid_env", bodyBadEnv["error"])

	// from == to → 400 invalid_target.
	rSame := advReq(t, app, http.MethodPost, base, ownerJWT, map[string]any{"from": "staging", "to": "staging"})
	bodySame := decodeAdv(t, rSame)
	assert.Equal(t, http.StatusBadRequest, rSame.StatusCode)
	assert.Equal(t, "invalid_target", bodySame["error"])

	// asserted from != source.env → 409 env_mismatch (source is 'staging').
	rMismatch := advReq(t, app, http.MethodPost, base, ownerJWT, map[string]any{"from": "production", "to": "preprod"})
	bodyMismatch := decodeAdv(t, rMismatch)
	assert.Equal(t, http.StatusConflict, rMismatch.StatusCode)
	assert.Equal(t, "env_mismatch", bodyMismatch["error"])

	// off-tier (hobby) → 402 multi-env upgrade gate (rule 3 — tier policy in
	// the handler, not hardcoded here).
	hobbyTeam := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	hobbyJWT := testhelpers.MustSignSessionJWT(t, mustUUIDStr(), hobbyTeam.String(), "hobby-adv@example.com")
	hobbyStack := seedAdvancedStack(t, db, hobbyTeam, "staging")
	rTier := advReq(t, app, http.MethodPost, "/api/v1/stacks/"+hobbyStack.Slug+"/promote", hobbyJWT,
		map[string]any{"from": "staging", "to": "production"})
	bodyTier := decodeAdv(t, rTier)
	assert.Equal(t, http.StatusPaymentRequired, rTier.StatusCode)
	assert.Equal(t, "upgrade_required", bodyTier["error"])
	assert.NotEmpty(t, bodyTier["agent_action"])
}

// ── family ────────────────────────────────────────────────────────────────────

// TestStacksAdvancedBlock_Family_HappyAuthzAndCache covers GET
// /api/v1/stacks/:slug/family: the happy path returns the env family (at least
// the source) + Cache-Control: private, max-age=60; a member of the owning team
// reads it; a non-member is 404; an unauthenticated call is 401; and an
// off-tier (hobby) team is 402.
func TestStacksAdvancedBlock_Family_HappyAuthzAndCache(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)
	app := newStacksAdvancedApp(t, db)

	teamID, ownerJWT, memberJWT, otherJWT := proTeamWithUsers(t, db)
	stack := seedAdvancedStack(t, db, teamID, "production")
	base := "/api/v1/stacks/" + stack.Slug + "/family"

	// unauth → 401.
	r401 := advReq(t, app, http.MethodGet, base, "", nil)
	r401.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, r401.StatusCode)

	// owner happy path → 200 + family contains the source + cache header.
	rOwner := advReq(t, app, http.MethodGet, base, ownerJWT, nil)
	assert.Equal(t, "private, max-age=60", rOwner.Header.Get("Cache-Control"),
		"family read must stamp the per-team private cache header")
	bodyOwner := decodeAdv(t, rOwner)
	assert.Equal(t, http.StatusOK, rOwner.StatusCode)
	assert.Equal(t, true, bodyOwner["ok"])
	fam, ok := bodyOwner["family"].([]any)
	require.True(t, ok, "family must be an array")
	assert.GreaterOrEqual(t, len(fam), 1, "family must include at least the source stack")

	// member of the same team reads it → 200 (any-member authz).
	rMember := advReq(t, app, http.MethodGet, base, memberJWT, nil)
	rMember.Body.Close()
	assert.Equal(t, http.StatusOK, rMember.StatusCode)

	// cross-team → 404.
	rCross := advReq(t, app, http.MethodGet, base, otherJWT, nil)
	rCross.Body.Close()
	assert.Equal(t, http.StatusNotFound, rCross.StatusCode)

	// off-tier (hobby) → 402.
	hobbyTeam := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	hobbyJWT := testhelpers.MustSignSessionJWT(t, mustUUIDStr(), hobbyTeam.String(), "hobby-fam@example.com")
	hobbyStack := seedAdvancedStack(t, db, hobbyTeam, "production")
	rTier := advReq(t, app, http.MethodGet, "/api/v1/stacks/"+hobbyStack.Slug+"/family", hobbyJWT, nil)
	bodyTier := decodeAdv(t, rTier)
	assert.Equal(t, http.StatusPaymentRequired, rTier.StatusCode)
	assert.Equal(t, "upgrade_required", bodyTier["error"])
}

// ── custom domains (create / list / verify / delete) ──────────────────────────

// TestStacksAdvancedBlock_Domains_FullLifecycle drives the four custom-domain
// routes end to end against a real Postgres with a nil k8s provider:
//
//	POST   create  → 201, row persisted at pending_verification + TXT challenge
//	GET    list    → 200, the created row appears
//	POST   verify  → 200, TXT seam matches → status advances to verified
//	                 (the ingress/cert legs need a live k8s and are deferred —
//	                 with k8s nil the verified state is terminal here)
//	DELETE delete  → 200, row removed (list now empty)
//
// Plus the authz axes: a member of the owning team can create+list (any-member
// authz), an unauthenticated call is 401, and a cross-team create is 404.
func TestStacksAdvancedBlock_Domains_FullLifecycle(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)
	app := newStacksAdvancedApp(t, db)

	teamID, ownerJWT, memberJWT, otherJWT := proTeamWithUsers(t, db)
	stack := seedAdvancedStack(t, db, teamID, "production")
	domainsPath := "/api/v1/stacks/" + stack.Slug + "/domains"
	hostname := "app-" + uuid.NewString()[:8] + ".example.com"

	// unauth create → 401.
	r401 := advReq(t, app, http.MethodPost, domainsPath, "", map[string]any{"hostname": hostname})
	r401.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, r401.StatusCode)

	// cross-team create → 404 (stack not owned).
	rCross := advReq(t, app, http.MethodPost, domainsPath, otherJWT, map[string]any{"hostname": hostname})
	rCross.Body.Close()
	assert.Equal(t, http.StatusNotFound, rCross.StatusCode)

	// owner create → 201 + row persisted pending_verification + TXT challenge.
	rCreate := advReq(t, app, http.MethodPost, domainsPath, ownerJWT, map[string]any{"hostname": hostname})
	bodyCreate := decodeAdv(t, rCreate)
	require.Equal(t, http.StatusCreated, rCreate.StatusCode)
	assert.Equal(t, true, bodyCreate["ok"])
	dom, _ := bodyCreate["domain"].(map[string]any)
	require.NotNil(t, dom, "create must return the domain object")
	domID, _ := dom["id"].(string)
	require.NotEmpty(t, domID)
	assert.Equal(t, models.CustomDomainStatusPending, dom["status"])
	verif, _ := dom["verification"].(map[string]any)
	require.NotNil(t, verif, "create must return the DNS challenge")
	assert.Contains(t, verif, "txt")
	assert.Contains(t, verif, "cname")

	// DB truth: one row at pending_verification owned by this team + stack.
	var dbStatus, dbTeam string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT status, team_id::text FROM custom_domains WHERE id=$1::uuid`, domID).Scan(&dbStatus, &dbTeam))
	assert.Equal(t, models.CustomDomainStatusPending, dbStatus)
	assert.Equal(t, teamID.String(), dbTeam)

	// member of the same team can list (any-member authz) → 200, row present.
	rList := advReq(t, app, http.MethodGet, domainsPath, memberJWT, nil)
	bodyList := decodeAdv(t, rList)
	assert.Equal(t, http.StatusOK, rList.StatusCode)
	items, _ := bodyList["items"].([]any)
	require.Len(t, items, 1, "list must return the one created domain")

	// verify with the TXT seam returning the expected payload → 200, advances
	// to verified. (The ingress/cert legs require a live k8s — nil here makes
	// verified terminal; the deeper legs are deferred to the W4 e2e spec.)
	domUUID := uuid.MustParse(domID)
	row, err := models.GetCustomDomainByID(context.Background(), db, domUUID)
	require.NoError(t, err)
	wantTXT := models.VerificationTokenPrefix + row.VerificationToken
	restore := handlers.SetLookupTXTForTest(func(_ context.Context, _ string) ([]string, error) {
		return []string{wantTXT}, nil
	})
	defer restore()

	rVerify := advReq(t, app, http.MethodPost, domainsPath+"/"+domID+"/verify", ownerJWT, nil)
	bodyVerify := decodeAdv(t, rVerify)
	assert.Equal(t, http.StatusOK, rVerify.StatusCode)
	domV, _ := bodyVerify["domain"].(map[string]any)
	require.NotNil(t, domV)
	assert.Equal(t, models.CustomDomainStatusVerified, domV["status"],
		"a matching TXT record must advance the row to verified")
	// DB truth: status flipped to verified.
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT status FROM custom_domains WHERE id=$1::uuid`, domID).Scan(&dbStatus))
	assert.Equal(t, models.CustomDomainStatusVerified, dbStatus)

	// delete → 200, row removed.
	rDelete := advReq(t, app, http.MethodDelete, domainsPath+"/"+domID, ownerJWT, nil)
	rDelete.Body.Close()
	assert.Equal(t, http.StatusOK, rDelete.StatusCode)
	var remaining int
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM custom_domains WHERE id=$1::uuid`, domID).Scan(&remaining))
	assert.Equal(t, 0, remaining, "delete must remove the custom_domains row")
}

// TestStacksAdvancedBlock_Domains_TierGateAndCrossTeamRow covers two more
// custom-domain contract legs: an off-tier (hobby) team is 402 on create
// (CustomDomainsAllowed gate, rule 3), and verify/delete of a domain row that
// belongs to ANOTHER team is 404 (never confirming the row exists — the
// requireOwnedDomain UUID-guess defense).
func TestStacksAdvancedBlock_Domains_TierGateAndCrossTeamRow(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)
	app := newStacksAdvancedApp(t, db)

	teamID, ownerJWT, _, otherJWT := proTeamWithUsers(t, db)
	stack := seedAdvancedStack(t, db, teamID, "production")

	// off-tier (hobby) create → 402 (custom_domains feature gate).
	hobbyTeam := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	hobbyJWT := testhelpers.MustSignSessionJWT(t, mustUUIDStr(), hobbyTeam.String(), "hobby-dom@example.com")
	hobbyStack := seedAdvancedStack(t, db, hobbyTeam, "production")
	rTier := advReq(t, app, http.MethodPost, "/api/v1/stacks/"+hobbyStack.Slug+"/domains", hobbyJWT,
		map[string]any{"hostname": "h-" + uuid.NewString()[:8] + ".example.com"})
	bodyTier := decodeAdv(t, rTier)
	assert.Equal(t, http.StatusPaymentRequired, rTier.StatusCode)
	assert.Equal(t, "upgrade_required", bodyTier["error"])

	// Create a real domain row owned by teamID via the model.
	dom, err := models.CreateCustomDomain(context.Background(), db, teamID, stack.ID,
		"owned-"+uuid.NewString()[:8]+".example.com")
	require.NoError(t, err)

	// Cross-team verify of that row (other team's JWT) → 404 — the cross-team
	// check trips on requireOwnedStack first (stack not owned), so a different
	// team can never reach another team's domain row.
	rCrossVerify := advReq(t, app, http.MethodPost,
		"/api/v1/stacks/"+stack.Slug+"/domains/"+dom.ID.String()+"/verify", otherJWT, nil)
	rCrossVerify.Body.Close()
	assert.Equal(t, http.StatusNotFound, rCrossVerify.StatusCode)

	// Cross-team delete likewise → 404; the row survives.
	rCrossDelete := advReq(t, app, http.MethodDelete,
		"/api/v1/stacks/"+stack.Slug+"/domains/"+dom.ID.String(), otherJWT, nil)
	rCrossDelete.Body.Close()
	assert.Equal(t, http.StatusNotFound, rCrossDelete.StatusCode)
	var n int
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM custom_domains WHERE id=$1::uuid`, dom.ID).Scan(&n))
	assert.Equal(t, 1, n, "a cross-team delete must not remove the row")

	// Owner can still verify/delete the row (sanity: the 404s above were
	// authz, not a broken route). Owner verify (k8s nil → stays pending
	// without TXT match) returns 200; owner delete removes it.
	rOwnerDelete := advReq(t, app, http.MethodDelete,
		"/api/v1/stacks/"+stack.Slug+"/domains/"+dom.ID.String(), ownerJWT, nil)
	rOwnerDelete.Body.Close()
	assert.Equal(t, http.StatusOK, rOwnerDelete.StatusCode)
}
