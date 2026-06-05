package handlers_test

// misc_routes_block_integration_test.go — the LAST real-flow wave of the
// route-coverage tail (USER-FLOW-INVENTORY-AND-TEST-MATRIX.md misc surfaces).
//
// Closes the five "misc" routes that, in
// internal/router/route_donebar_guard_test.go, lived in
// routeCoverageExemptions with a "TODO: matrix W…" pointer and no mapped test:
//
//   - GET  /api/v1/incidents               status-page incidents feed
//   - GET  /auth/email/confirm-deletion    tokenized deletion-confirm redirect
//   - GET  /api/v1/usage/wall              org usage-rollup wall
//   - GET  /api/v1/webhooks/:token/requests captured-webhook-request inspector
//
// (POST /api/v1/experiments/converted is the fifth route; its DB-backed,
// production-router contract is already covered by experiments_test.go's
// TestExperimentsConverted_WritesAuditRow + the three reject tests, so the
// done-bar guard's row for it points there directly rather than duplicating
// the audit-row round-trip here.)
//
// Convention mirrors the W3 team-block / W4 stacks-advanced suites: a thin
// SetupTestDB wrapper, a loud skip-when-no-DB guard, and a per-block app
// builder that wires each route through the SAME middleware chain production
// uses (internal/router/router.go) against a real migrated Postgres —
// RequireAuth for the /api/v1 session-gated routes, OptionalAuth for the
// token-as-credential webhook inspector, and bare public registration for the
// unauth incidents/confirm-deletion surfaces. Helpers are prefixed misc* so
// they neither collide with nor redefine the existing package helpers
// (miniRedis / doJSON / decodeBody / requireTestDB / mustUUIDStr), which this
// suite reuses verbatim.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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

// miscBlockCfg is the shared test config for the misc-routes block. Mirrors the
// fields production sets for these handlers: JWT secret for RequireAuth,
// DashboardBaseURL for the confirm-deletion redirect target, and a non-prod
// Environment + a webhook in EnabledServices so the receive/list handlers run.
func miscBlockCfg() *config.Config {
	return &config.Config{
		JWTSecret:        testhelpers.TestJWTSecret,
		AESKey:           testhelpers.TestAESKeyHex,
		DashboardBaseURL: "https://dash.local",
		APIPublicURL:     "https://api.local",
		Environment:      "test",
		EnabledServices:  "postgres,redis,mongodb,queue,webhook,storage",
	}
}

// miscBlockErrorHandler mirrors the production ErrorHandler swallow-sentinel
// behaviour so respondError bodies aren't overwritten by Fiber's default 500.
func miscBlockErrorHandler(c *fiber.Ctx, err error) error {
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
}

// miscBlockReq fires a request (optional Bearer auth) and returns the raw
// response. auth=="" sends no Authorization header (exercises the unauth /
// token-as-bearer paths).
func miscBlockReq(t *testing.T, app *fiber.App, method, path, auth string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	return resp
}

// miscDecode decodes a response body into a generic map.
func miscDecode(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out
}

// ─────────────────────────────────────────────────────────────────────────
// GET /api/v1/incidents — IncidentsHandler.List  (public, unauth)
// ─────────────────────────────────────────────────────────────────────────

// miscIncidentsApp wires GET /api/v1/incidents exactly as router.go does:
// registered on the bare app (no /api/v1 RequireAuth group), public-by-design
// so any AI agent can ask "is anything broken" without a token.
func miscIncidentsApp(t *testing.T) *fiber.App {
	t.Helper()
	app := fiber.New(fiber.Config{ErrorHandler: miscBlockErrorHandler})
	app.Use(middleware.RequestID())
	app.Get("/api/v1/incidents", handlers.NewIncidentsHandler().List)
	return app
}

// TestMiscBlock_Incidents_PublicFeed asserts the status-page incident-feed
// contract: 200 with {ok, items:[], total:0, status_page} and NO auth required
// (the route is intentionally public — it carries no team-scoped data). This is
// the read-only contract a future incident-feed worker must keep stable when it
// starts populating items.
func TestMiscBlock_Incidents_PublicFeed(t *testing.T) {
	app := miscIncidentsApp(t)

	t.Run("unauthenticated caller gets the empty feed contract", func(t *testing.T) {
		resp := miscBlockReq(t, app, http.MethodGet, "/api/v1/incidents", "")
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body := miscDecode(t, resp)
		assert.Equal(t, true, body["ok"])
		assert.Equal(t, float64(0), body["total"])
		items, ok := body["items"].([]any)
		require.True(t, ok, "items must be a JSON array")
		assert.Empty(t, items, "no incidents recorded today")
		statusPage, _ := body["status_page"].(string)
		assert.Contains(t, statusPage, "instanode.dev/status",
			"feed must point at the human status page")
	})
}

// ─────────────────────────────────────────────────────────────────────────
// GET /auth/email/confirm-deletion — EmailConfirmDeletionRedirectHandler
//   (public; the `t=` token IS the credential, like /approve/:token)
// ─────────────────────────────────────────────────────────────────────────

// miscConfirmDeletionApp wires GET /auth/email/confirm-deletion exactly as
// router.go does: a bare public route (no auth — a click is navigation, not
// action; the dashboard runs the real authenticated POST).
func miscConfirmDeletionApp(t *testing.T) *fiber.App {
	t.Helper()
	cfg := miscBlockCfg()
	app := fiber.New(fiber.Config{ErrorHandler: miscBlockErrorHandler})
	app.Use(middleware.RequestID())
	app.Get("/auth/email/confirm-deletion",
		handlers.EmailConfirmDeletionRedirectHandler(cfg.DashboardBaseURL))
	return app
}

// TestMiscBlock_ConfirmDeletionRedirect_TokenBranches drives both branches of
// the tokenized confirm-deletion redirect (the token IS the credential): a
// present token 302s to the dashboard's /app/confirm-deletion?t=<token> with
// the token carried through verbatim, and a missing token returns the canonical
// 400 envelope (BUG-API-047/204/273: missing_token, application/json, never a
// text/plain "Missing token"). The redirect body is deliberately empty so an
// email-scanner pre-fetch can't trigger destruction.
func TestMiscBlock_ConfirmDeletionRedirect_TokenBranches(t *testing.T) {
	app := miscConfirmDeletionApp(t)

	t.Run("present token 302s to dashboard with token carried through", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/email/confirm-deletion?t=del-tok-123", nil)
		// Don't auto-follow the redirect — assert the Location header itself.
		resp, err := app.Test(req, 10000)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusFound, resp.StatusCode)
		loc := resp.Header.Get("Location")
		assert.Equal(t, "https://dash.local/app/confirm-deletion?t=del-tok-123", loc,
			"the click must navigate to the dashboard with the token carried verbatim")
	})

	t.Run("missing token returns the canonical 400 envelope", func(t *testing.T) {
		resp := miscBlockReq(t, app, http.MethodGet, "/auth/email/confirm-deletion", "")
		defer resp.Body.Close()
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Contains(t, resp.Header.Get("Content-Type"), "application/json",
			"missing-token must keep the JSON envelope (not text/plain)")
		body := miscDecode(t, resp)
		assert.Equal(t, false, body["ok"])
		assert.Equal(t, "missing_token", body["error"],
			"canonical code agents grep on across onboarding/magic_link/deletion_confirm")
	})

	t.Run("blank token (t= with empty value) also 400s", func(t *testing.T) {
		resp := miscBlockReq(t, app, http.MethodGet, "/auth/email/confirm-deletion?t=", "")
		defer resp.Body.Close()
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		body := miscDecode(t, resp)
		assert.Equal(t, "missing_token", body["error"])
	})
}

// ─────────────────────────────────────────────────────────────────────────
// GET /api/v1/usage/wall — UsageWallHandler.GetWall  (RequireAuth)
// ─────────────────────────────────────────────────────────────────────────

// miscUsageWallApp wires GET /api/v1/usage/wall under the production
// /api/v1 RequireAuth group (router.go), backed by the real test DB so the
// team-tier short-circuit + the audit_log near_quota_wall read run against
// actual rows (not sqlmock — that's what the existing usage_wall_test.go
// covers; this is the DB-backed contract the done-bar guard points at).
func miscUsageWallApp(t *testing.T, db *sql.DB) *fiber.App {
	t.Helper()
	cfg := miscBlockCfg()
	app := fiber.New(fiber.Config{ErrorHandler: miscBlockErrorHandler})
	app.Use(middleware.RequestID())
	api := app.Group("/api/v1", middleware.RequireAuth(cfg))
	api.Get("/usage/wall", handlers.NewUsageWallHandler(db).GetWall)
	return app
}

// miscSeedUser inserts a user into teamID and returns a signed session JWT for
// it (the production auth surface itself is covered by auth_flow_e2e_test.go;
// here we just need a valid token the RequireAuth chain accepts).
func miscSeedUser(t *testing.T, db *sql.DB, teamID string) string {
	t.Helper()
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, testhelpers.UniqueEmail(t),
	).Scan(&userID))
	return testhelpers.MustSignSessionJWT(t, userID, teamID, "usage-wall@example.com")
}

// TestMiscBlock_UsageWall_RealDBContract drives GET /api/v1/usage/wall through
// the production RequireAuth chain against a real Postgres across all three
// contract branches:
//   - unauthenticated → 401 (RequireAuth gate),
//   - hobby team with a fresh near_quota_wall audit row → near_wall=true with
//     the metadata flattened to the top level + the Cache-Control/Vary headers,
//   - team-tier caller → near_wall=false short-circuit (no wall on unlimited),
//   - cross-team isolation: team A's session never sees team B's wall row.
func TestMiscBlock_UsageWall_RealDBContract(t *testing.T) {
	requireTestDB(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	app := miscUsageWallApp(t, db)

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		resp := miscBlockReq(t, app, http.MethodGet, "/api/v1/usage/wall", "")
		resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("hobby team with fresh wall row returns near_wall=true + flattened metadata", func(t *testing.T) {
		teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
		jwt := miscSeedUser(t, db, teamID)
		miscSeedWallRow(t, db, teamID)

		resp := miscBlockReq(t, app, http.MethodGet, "/api/v1/usage/wall", jwt)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		// Cache headers are stamped on every 200 path (BUG-API-420).
		assert.Contains(t, resp.Header.Get("Cache-Control"), "max-age=",
			"every 200 path must carry the per-team cache hint")
		assert.Equal(t, "Authorization", resp.Header.Get("Vary"),
			"Vary: Authorization is the per-team cache boundary")
		body := miscDecode(t, resp)
		assert.Equal(t, true, body["ok"])
		assert.Equal(t, true, body["near_wall"])
		assert.Equal(t, "storage", body["axis"])
		assert.Equal(t, "postgres", body["service"])
		assert.Equal(t, float64(87), body["percent_used"])
	})

	t.Run("team tier short-circuits to near_wall=false even with a wall row", func(t *testing.T) {
		teamID := testhelpers.MustCreateTeamDB(t, db, "team")
		jwt := miscSeedUser(t, db, teamID)
		// Even if a row somehow existed, the team-tier gate returns false
		// before the audit query — assert the gate, not the absence of a row.
		miscSeedWallRow(t, db, teamID)

		resp := miscBlockReq(t, app, http.MethodGet, "/api/v1/usage/wall", jwt)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body := miscDecode(t, resp)
		assert.Equal(t, true, body["ok"])
		assert.Equal(t, false, body["near_wall"],
			"team tier is unlimited — no walls, short-circuit before the audit scan")
	})

	t.Run("cross-team isolation: team A session never sees team B's wall", func(t *testing.T) {
		teamA := testhelpers.MustCreateTeamDB(t, db, "hobby")
		teamB := testhelpers.MustCreateTeamDB(t, db, "hobby")
		jwtA := miscSeedUser(t, db, teamA)
		// Only team B has a wall row; team A's session must see near_wall=false.
		miscSeedWallRow(t, db, teamB)

		resp := miscBlockReq(t, app, http.MethodGet, "/api/v1/usage/wall", jwtA)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body := miscDecode(t, resp)
		assert.Equal(t, false, body["near_wall"],
			"the wall query is team-scoped — team A must not read team B's row")
	})
}

// miscSeedWallRow inserts a fresh near_quota_wall audit row for teamID with the
// metadata shape the worker (quota_wall_nudge.go) writes and the handler reads.
func miscSeedWallRow(t *testing.T, db *sql.DB, teamID string) {
	t.Helper()
	meta := `{"tier":"hobby","axis":"storage","service":"postgres","current":471859200,"limit":536870912,"percent_used":87}`
	require.NoError(t, models.InsertAuditEvent(context.Background(), db, models.AuditEvent{
		TeamID:   uuid.MustParse(teamID),
		Actor:    "system",
		Kind:     "near_quota_wall",
		Summary:  "team approaching storage quota",
		Metadata: []byte(meta),
	}))
}

// ─────────────────────────────────────────────────────────────────────────
// GET /api/v1/webhooks/:token/requests — WebhookHandler.ListRequests
//   (OptionalAuth; the token IS the credential — the webhook-request inspector)
// ─────────────────────────────────────────────────────────────────────────

// miscWebhookApp wires both the receive sink and the inspector exactly as
// router.go does (OptionalAuth on the inspector so a session, when present, is
// checked against the owning team), backed by the real test DB + a Redis client
// so a captured request round-trips end-to-end (receive → store → inspect).
func miscWebhookApp(t *testing.T, db *sql.DB, rdb *redis.Client) *fiber.App {
	t.Helper()
	cfg := miscBlockCfg()
	app := fiber.New(fiber.Config{ErrorHandler: miscBlockErrorHandler})
	app.Use(middleware.RequestID())
	webhookH := handlers.NewWebhookHandler(db, rdb, cfg, plans.Default())
	// app.All in production; POST is the documented capture verb we drive here.
	app.Post("/webhook/receive/:token", webhookH.Receive)
	app.Get("/api/v1/webhooks/:token/requests",
		middleware.OptionalAuth(cfg), webhookH.ListRequests)
	return app
}

// miscMintWebhook inserts an active webhook resource owned by teamID and returns
// its token (UUID string). teamID=="" mints an anonymous (team-less) webhook.
func miscMintWebhook(t *testing.T, db *sql.DB, teamID string) string {
	t.Helper()
	params := models.CreateResourceParams{
		ResourceType: models.ResourceTypeWebhook,
		Name:         "wh-inspector-" + uuid.NewString()[:8],
		Tier:         "pro",
		Fingerprint:  "fp-misc-" + uuid.NewString(),
	}
	if teamID != "" {
		tid := uuid.MustParse(teamID)
		params.TeamID = &tid
	} else {
		params.Tier = "anonymous"
	}
	res, err := models.CreateResource(context.Background(), db, params)
	require.NoError(t, err)
	require.NoError(t, models.MarkResourceActive(context.Background(), db, res.ID))
	return res.Token.String()
}

// miscCaptureRequest POSTs a body to the receive sink so the inspector has a
// stored payload to return. Returns the captured request's generated id.
func miscCaptureRequest(t *testing.T, app *fiber.App, token, body string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/webhook/receive/"+token, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "receive must accept the payload")
}

// TestMiscBlock_WebhookInspector_TokenScopedAndIsolated drives the
// captured-webhook-request inspector through the real receive → store →
// inspect round-trip against a live Redis, asserting the inspector's real
// contract:
//   - token-as-bearer: an unauthenticated caller holding the token reads its
//     own captured requests (the token IS the credential),
//   - token-scoping: the inspector returns ONLY the requests captured for that
//     token, never another token's (cross-token isolation),
//   - invalid token → 400; unknown (well-formed) token → 404,
//   - cross-team session: team B's JWT reading team A's webhook token → 403
//     cross_team_session (the IDOR axis).
func TestMiscBlock_WebhookInspector_TokenScopedAndIsolated(t *testing.T) {
	requireTestDB(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	rdb := miniRedis(t)
	app := miscWebhookApp(t, db, rdb)

	t.Run("token-as-bearer reads only its own captured requests", func(t *testing.T) {
		teamA := testhelpers.MustCreateTeamDB(t, db, "pro")
		tokenA := miscMintWebhook(t, db, teamA)
		tokenB := miscMintWebhook(t, db, teamA) // same team, distinct token

		// Capture two requests on A, one (different body) on B.
		miscCaptureRequest(t, app, tokenA, `{"who":"a-first"}`)
		miscCaptureRequest(t, app, tokenA, `{"who":"a-second"}`)
		miscCaptureRequest(t, app, tokenB, `{"who":"b-only"}`)

		// Inspect A (no session — token-as-bearer).
		respA := miscBlockReq(t, app, http.MethodGet, "/api/v1/webhooks/"+tokenA+"/requests", "")
		require.Equal(t, http.StatusOK, respA.StatusCode)
		bodyA := miscDecode(t, respA)
		assert.Equal(t, true, bodyA["ok"])
		assert.Equal(t, float64(2), bodyA["total"], "A must see exactly its 2 captures")
		reqsA, ok := bodyA["requests"].([]any)
		require.True(t, ok)
		require.Len(t, reqsA, 2)
		// Cross-token isolation: none of A's captured bodies mention B's payload.
		for _, r := range reqsA {
			m, _ := r.(map[string]any)
			assert.NotContains(t, m["body"], "b-only",
				"the inspector must never leak another token's captured request")
		}

		// Inspect B independently — it sees only its single capture.
		respB := miscBlockReq(t, app, http.MethodGet, "/api/v1/webhooks/"+tokenB+"/requests", "")
		require.Equal(t, http.StatusOK, respB.StatusCode)
		bodyB := miscDecode(t, respB)
		assert.Equal(t, float64(1), bodyB["total"], "B is scoped to its own single capture")
	})

	t.Run("malformed token → 400", func(t *testing.T) {
		resp := miscBlockReq(t, app, http.MethodGet, "/api/v1/webhooks/not-a-uuid/requests", "")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		body := miscDecode(t, resp)
		assert.Equal(t, "invalid_token", body["error"])
	})

	t.Run("well-formed but unknown token → 404", func(t *testing.T) {
		resp := miscBlockReq(t, app, http.MethodGet,
			"/api/v1/webhooks/"+uuid.NewString()+"/requests", "")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		body := miscDecode(t, resp)
		assert.Equal(t, "not_found", body["error"])
	})

	t.Run("cross-team session reading another team's webhook → 403", func(t *testing.T) {
		teamA := testhelpers.MustCreateTeamDB(t, db, "pro")
		teamB := testhelpers.MustCreateTeamDB(t, db, "pro")
		tokenA := miscMintWebhook(t, db, teamA)
		jwtB := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamB, "ops-b@example.com")

		resp := miscBlockReq(t, app, http.MethodGet, "/api/v1/webhooks/"+tokenA+"/requests", jwtB)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode,
			"team B's session on team A's token is the IDOR poach signal")
		body := miscDecode(t, resp)
		assert.Equal(t, "cross_team_session", body["error"])
	})
}
