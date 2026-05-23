package handlers_test

// webhook_final_test.go — FINAL coverage pass for webhook.go's authenticated
// provision arms (newWebhookAuthenticated): invalid_team, team_lookup DB error,
// and create_resource DB error. Uses an OptionalAuth-wired app + a session JWT
// over a faultdb-backed handler.

import (
	"context"
	"database/sql"
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
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

func webhookAuthApp(t *testing.T, db *sql.DB) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		Environment:     "test",
		AESKey:          testhelpers.TestAESKeyHex,
		JWTSecret:       testhelpers.TestJWTSecret,
		EnabledServices: "webhook",
	}
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	t.Cleanup(cleanR)
	h := handlers.NewWebhookHandler(db, rdb, cfg, plans.Default())
	app := fiber.New(fiber.Config{
		ProxyHeader: "X-Forwarded-For",
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if e == handlers.ErrResponseWritten {
				return nil
			}
			code := fiber.StatusInternalServerError
			if fe, ok := e.(*fiber.Error); ok {
				code = fe.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": e.Error()})
		},
	})
	app.Use(middleware.RequestID())
	app.Use(middleware.Fingerprint())
	app.Post("/webhook/new", middleware.OptionalAuth(cfg), h.NewWebhook)
	return app
}

func whJWT(t *testing.T, db *sql.DB, teamID string) string {
	t.Helper()
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email).Scan(&userID))
	return testhelpers.MustSignSessionJWT(t, userID, teamID, email)
}

func whPost(t *testing.T, app *fiber.App, ip, jwt, body string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/webhook/new", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	return resp
}

func whErr(t *testing.T, resp *http.Response) string {
	t.Helper()
	var m map[string]any
	_ = decodeJSON(resp, &m)
	if s, ok := m["error"].(string); ok {
		return s
	}
	return ""
}

// TestWebhookFinal_Anon_OverCap_Dedup — anonymous webhook provisions burn the
// daily cap; the over-cap call dedups to the existing resource (webhook.go:237+
// dedup branch). Webhook provisioning is Redis-only (no backend), so the first
// calls succeed and the over-cap call dedup-hits.
func TestWebhookFinal_Anon_OverCap_Dedup(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := webhookAuthApp(t, db)
	const ip = "10.76.0.4"
	post := func() *http.Response {
		return whPost(t, app, ip, "", `{"name":"wh","env":"production"}`)
	}
	first := post()
	require.Equal(t, http.StatusCreated, first.StatusCode)
	first.Body.Close()
	sawDedupOrDeny := false
	for i := 0; i < 8; i++ {
		resp := post()
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusPaymentRequired {
			sawDedupOrDeny = true
		}
		resp.Body.Close()
	}
	assert.True(t, sawDedupOrDeny, "over-cap anonymous webhook calls must dedup/deny")
}

// newWebhookAuthenticated: JWT tid not a UUID → invalid_team (webhook.go:402).
func TestWebhookFinal_Auth_BadTeamID_400(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := webhookAuthApp(t, db)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), "not-a-uuid", testhelpers.UniqueEmail(t))
	resp := whPost(t, app, "10.73.0.1", jwt, `{"name":"wh","env":"production"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_team", whErr(t, resp))
}

// newWebhookAuthenticated: GetTeamByID errors → team_lookup_failed
// (webhook.go:406). failAfter=0 — team lookup is the first DB call.
func TestWebhookFinal_Auth_TeamLookup_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	jwt := whJWT(t, seedDB, teamID)

	app := webhookAuthApp(t, openFaultDB(t, 0))
	resp := whPost(t, app, "10.73.0.2", jwt, `{"name":"wh","env":"production"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "team_lookup_failed", whErr(t, resp))
}

// newWebhookAuthenticated: CreateResource errors → provision_failed
// (webhook.go:424). team(1) succeeds, the INSERT(2) errors. failAfter=1.
func TestWebhookFinal_Auth_CreateResource_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	jwt := whJWT(t, seedDB, teamID)

	app := webhookAuthApp(t, openFaultDB(t, 1))
	resp := whPost(t, app, "10.73.0.3", jwt, `{"name":"wh","env":"production"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "provision_failed", whErr(t, resp))
}
