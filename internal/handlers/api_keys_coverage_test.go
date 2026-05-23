package handlers_test

// api_keys_coverage_test.go — hermetic coverage for the Personal Access Token
// CRUD handler (api_keys.go). The handler is DB-only (no k8s / object-store /
// NATS), so these tests run under CI's postgres-only service matrix. Before
// this file the handler's routes were not wired into any test app and the file
// measured 0% under CI.

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
	"instant.dev/internal/testhelpers"
)

// apiKeysTestApp builds a minimal Fiber app exposing only the api-key routes,
// gated by RequireAuth using the standard test JWT secret. Mirrors router.go.
func apiKeysTestApp(t *testing.T, db *sql.DB) *fiber.App {
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
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error", "message": err.Error()})
		},
	})
	app.Use(middleware.RequestID())
	h := handlers.NewAPIKeysHandler(db)
	api := app.Group("/api/v1", middleware.RequireAuth(cfg))
	api.Post("/auth/api-keys", h.Create)
	api.Get("/auth/api-keys", h.List)
	api.Delete("/auth/api-keys/:id", h.Revoke)
	return app
}

func apiKeysTeamUser(t *testing.T, db *sql.DB) (teamID, jwt string) {
	t.Helper()
	teamID = testhelpers.MustCreateTeamDB(t, db, "pro")
	emailAddr := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRow(
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id`, teamID, emailAddr,
	).Scan(&userID))
	jwt = testhelpers.MustSignSessionJWT(t, userID, teamID, emailAddr)
	return teamID, jwt
}

func apiKeysDo(t *testing.T, app *fiber.App, method, path, jwt, body string) *http.Response {
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

func TestAPIKeys_CreateListRevoke_HappyPath(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := apiKeysTestApp(t, db)
	_, jwt := apiKeysTeamUser(t, db)

	// Create
	resp := apiKeysDo(t, app, http.MethodPost, "/api/v1/auth/api-keys", jwt, `{"name":"laptop","scopes":["read","write"]}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var created struct {
		OK   bool   `json:"ok"`
		ID   string `json:"id"`
		Name string `json:"name"`
		Key  string `json:"key"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	resp.Body.Close()
	assert.True(t, created.OK)
	assert.Equal(t, "laptop", created.Name)
	assert.NotEmpty(t, created.Key, "plaintext key returned once on create")
	require.NotEmpty(t, created.ID)

	// List shows the key (no plaintext)
	resp = apiKeysDo(t, app, http.MethodGet, "/api/v1/auth/api-keys", jwt, "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var listed struct {
		OK    bool `json:"ok"`
		Items []struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Revoked bool   `json:"revoked"`
		} `json:"items"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&listed))
	resp.Body.Close()
	require.Len(t, listed.Items, 1)
	assert.Equal(t, "laptop", listed.Items[0].Name)
	assert.False(t, listed.Items[0].Revoked)

	// Revoke
	resp = apiKeysDo(t, app, http.MethodDelete, "/api/v1/auth/api-keys/"+created.ID, jwt, "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Re-list shows revoked=true
	resp = apiKeysDo(t, app, http.MethodGet, "/api/v1/auth/api-keys", jwt, "")
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&listed))
	resp.Body.Close()
	require.Len(t, listed.Items, 1)
	assert.True(t, listed.Items[0].Revoked)
}

func TestAPIKeys_Create_ValidationArms(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := apiKeysTestApp(t, db)
	_, jwt := apiKeysTeamUser(t, db)

	cases := []struct {
		name string
		body string
		code int
	}{
		{"invalid_json", `{not json`, http.StatusBadRequest},
		{"missing_name", `{"name":""}`, http.StatusBadRequest},
		{"name_too_long", `{"name":"` + strings.Repeat("x", 121) + `"}`, http.StatusBadRequest},
		{"invalid_scope", `{"name":"k","scopes":["delete"]}`, http.StatusBadRequest},
		{"valid_admin_scope", `{"name":"k","scopes":["admin"]}`, http.StatusCreated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := apiKeysDo(t, app, http.MethodPost, "/api/v1/auth/api-keys", jwt, tc.body)
			assert.Equal(t, tc.code, resp.StatusCode)
			resp.Body.Close()
		})
	}
}

func TestAPIKeys_Revoke_NotFoundAndInvalidID(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := apiKeysTestApp(t, db)
	_, jwt := apiKeysTeamUser(t, db)

	// Not-a-UUID path param.
	resp := apiKeysDo(t, app, http.MethodDelete, "/api/v1/auth/api-keys/not-a-uuid", jwt, "")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()

	// Well-formed UUID that doesn't exist for this team → 404.
	resp = apiKeysDo(t, app, http.MethodDelete, "/api/v1/auth/api-keys/"+uuid.NewString(), jwt, "")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func TestAPIKeys_PATCannotCreatePAT(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := apiKeysTestApp(t, db)
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	// A PAT-style session has a team_id but NO user_id → createdBy invalid.
	jwt := testhelpers.MustSignSessionJWT(t, "", teamID, "")
	resp := apiKeysDo(t, app, http.MethodPost, "/api/v1/auth/api-keys", jwt, `{"name":"k"}`)
	// The session middleware rejects an empty uid before the handler runs;
	// either 401 (middleware) or 403 (handler PAT-guard) proves the no-uid
	// path is closed. Accept both so the test is robust to middleware order.
	assert.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, resp.StatusCode)
	resp.Body.Close()
}
