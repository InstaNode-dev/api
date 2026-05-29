package handlers_test

// api_keys_authp0_test.go — regression tests for the Auth P0 chain
// (findings AUTH-001, AUTH-002, AUTH-090, AUTH-164) shipped 2026-05-29.
//
// Each test reproduces the original exploit (the QA test that found it)
// AND asserts the post-fix behaviour blocks it. The tests are hermetic —
// they bring up an in-process Fiber app wired to the test Postgres exactly
// like the existing api_keys_coverage_test.go suite, so they run under
// the standard `go test` matrix and don't depend on k8s / Redis / NATS.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// authP0App mirrors apiKeysTestApp but ALSO wires the PAT branch of
// RequireAuth (via SetAPIKeyDB) so the tests can hit the handler with a
// real ink_<...> bearer token — the AUTH-001 exploit surface.
func authP0App(t *testing.T, db *sql.DB) *fiber.App {
	t.Helper()
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": err.Error()})
		},
	})
	app.Use(middleware.RequestID())
	middleware.SetAPIKeyDB(db)
	h := handlers.NewAPIKeysHandler(db)
	api := app.Group("/api/v1", middleware.RequireAuth(cfg))
	api.Post("/auth/api-keys", h.Create)
	api.Get("/auth/api-keys", h.List)
	api.Delete("/auth/api-keys/:id", h.Revoke)
	return app
}

func authP0TeamUser(t *testing.T, db *sql.DB) (teamID, userID, jwt string) {
	t.Helper()
	teamID = testhelpers.MustCreateTeamDB(t, db, "pro")
	emailAddr := testhelpers.UniqueEmail(t)
	require.NoError(t, db.QueryRow(
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id`, teamID, emailAddr,
	).Scan(&userID))
	jwt = testhelpers.MustSignSessionJWT(t, userID, teamID, emailAddr)
	return teamID, userID, jwt
}

// mintPAT inserts a PAT row directly (bypassing the rate-limited handler)
// and returns the plaintext bearer string. scopes is stored as-is.
func mintPAT(t *testing.T, db *sql.DB, teamID, userID string, scopes []string) string {
	t.Helper()
	plaintext, err := models.GenerateAPIKeyPlaintext()
	require.NoError(t, err)
	hash := models.HashAPIKey(plaintext)
	tID := uuid.MustParse(teamID)
	creator := uuid.NullUUID{}
	if userID != "" {
		creator = uuid.NullUUID{UUID: uuid.MustParse(userID), Valid: true}
	}
	_, err = models.CreateAPIKey(t.Context(), db, tID, creator, "test-parent-pat", hash, scopes)
	require.NoError(t, err)
	return plaintext
}

func authP0Do(t *testing.T, app *fiber.App, method, path, bearer, body string, headers ...[2]string) *http.Response {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for _, h := range headers {
		req.Header.Set(h[0], h[1])
	}
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

// TestPAT_CannotMintChild — AUTH-001 regression.
//
// Original exploit (QA T72/T77):
//
//	POST /api/v1/auth/api-keys
//	Authorization: Bearer ink_<any_pat_key>
//	{"name":"child"}
//
// Live behaviour was HTTP 201 + new key issued; the OpenAPI contract
// promises 403. The fix in handlers/api_keys.go now branches on
// middleware.IsAuthedViaAPIKey(c) and rejects with the documented 403 +
// error code "pat_cannot_mint_pat".
func TestPAT_CannotMintChild(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := authP0App(t, db)
	teamID, userID, _ := authP0TeamUser(t, db)

	// Parent PAT has full read+write scope — proves it's not a scope
	// problem, the rejection is structural.
	parent := mintPAT(t, db, teamID, userID, []string{"read", "write"})

	resp := authP0Do(t, app, http.MethodPost, "/api/v1/auth/api-keys", parent, `{"name":"child"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode,
		"AUTH-001: PAT bearer must NOT be able to mint a child PAT")

	var envelope struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&envelope))
	assert.Equal(t, "pat_cannot_mint_pat", envelope.Error,
		"error code must surface the specific contract violation")
}

// TestPAT_ChildScopesSubsetOfParent — AUTH-002 regression.
//
// Original exploit: a read-only parent PAT mints a child with admin scope
// and the server returns 201. The fix blocks ALL PAT-mints-PAT (AUTH-001
// is the structural gate that catches AUTH-002 as a subset), so a
// read-only PAT trying to mint admin gets 403 instead of 201. The
// assertion is on the security outcome — child is NOT created with
// elevated scope — not on the specific error code.
func TestPAT_ChildScopesSubsetOfParent(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := authP0App(t, db)
	teamID, userID, _ := authP0TeamUser(t, db)

	// Read-only parent PAT — the original exploit vector.
	parent := mintPAT(t, db, teamID, userID, []string{"read"})

	resp := authP0Do(t, app, http.MethodPost, "/api/v1/auth/api-keys", parent,
		`{"name":"escalate","scopes":["admin"]}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode,
		"AUTH-002: read-only PAT must NOT be able to mint admin child")

	// Belt: confirm no second key exists in the DB.
	keys, err := models.ListAPIKeysByTeam(t.Context(), db, uuid.MustParse(teamID))
	require.NoError(t, err)
	require.Len(t, keys, 1, "DB must still hold only the parent PAT row")
	assert.NotContains(t, keys[0].Scopes, "admin",
		"the surviving row must NOT be admin-scoped")
}

// TestPAT_SessionJWTCannotMintAdminScope_RequiresReauth — AUTH-090.
//
// Original exploit (QA T76): minting `admin` scope from a plain session
// JWT succeeds (201 + admin-scope PAT). Combined with AUTH-001/002 it
// completes the escalation chain.
//
// Fix: minting an admin-scope PAT from a session JWT requires the
// dashboard-set X-Confirm-Reauth: 1 header (proof of a fresh re-auth
// step). Without the header → 403 reauth_required. With the header →
// 201 (the legitimate dashboard flow still works).
func TestPAT_SessionJWTCannotMintAdminScope_RequiresReauth(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := authP0App(t, db)
	_, _, jwt := authP0TeamUser(t, db)

	// No re-auth header → 403.
	resp := authP0Do(t, app, http.MethodPost, "/api/v1/auth/api-keys", jwt,
		`{"name":"admin-key","scopes":["admin"]}`)
	require.Equal(t, http.StatusForbidden, resp.StatusCode,
		"AUTH-090: admin scope from session JWT without re-auth must 403")
	var envelope struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&envelope))
	assert.Equal(t, "reauth_required", envelope.Error,
		"error code must signal the required follow-up to the agent/UI")
	resp.Body.Close()

	// With re-auth header → 201 (the legitimate dashboard flow).
	resp = authP0Do(t, app, http.MethodPost, "/api/v1/auth/api-keys", jwt,
		`{"name":"admin-key","scopes":["admin"]}`,
		[2]string{"X-Confirm-Reauth", "1"})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode,
		"with re-auth header the admin PAT mint must succeed (legitimate dashboard flow)")
}

// TestPAT_EmptyScopesRejected — AUTH-164 regression.
//
// Original exploit: `scopes:[]` or `scopes:null` silently default to
// ["read","write"]. A caller asking for "no scopes" gets broad write
// access by accident. Fix: fail-closed with 400 invalid_scopes on
// explicit empty / null. An absent field still falls back to a safe
// default (["read"]).
func TestPAT_EmptyScopesRejected(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := authP0App(t, db)
	_, _, jwt := authP0TeamUser(t, db)

	cases := []struct {
		name       string
		body       string
		wantStatus int
		wantError  string
	}{
		{"empty_array", `{"name":"k","scopes":[]}`, http.StatusBadRequest, "invalid_scopes"},
		{"explicit_null", `{"name":"k","scopes":null}`, http.StatusBadRequest, "invalid_scopes"},
		{"absent_falls_back_to_read", `{"name":"k"}`, http.StatusCreated, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := authP0Do(t, app, http.MethodPost, "/api/v1/auth/api-keys", jwt, tc.body)
			defer resp.Body.Close()
			require.Equal(t, tc.wantStatus, resp.StatusCode)
			if tc.wantError != "" {
				var envelope struct {
					Error string `json:"error"`
				}
				require.NoError(t, json.NewDecoder(resp.Body).Decode(&envelope))
				assert.Equal(t, tc.wantError, envelope.Error)
			}
		})
	}
}
