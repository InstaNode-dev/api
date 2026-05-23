package handlers_test

// queue_credprovider_coverage_test.go — covers the per-tenant credential arms
// of the queue handler (queue.go issueTenantCreds / addQueueCredentials) that
// the default legacy_open provider can't reach: the AuthMode=isolated success
// path (real per-tenant JWT/NKey embedded in the response) and the
// creds-issuance-error fallback. A fake QueueCredentialProvider injected via
// SetCredProvider exercises both without standing up a NATS operator + signing
// keys (which production needs but CI cannot provide).

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
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonqp "instant.dev/common/queueprovider"
	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// fakeQueueCredProvider implements commonqp.QueueCredentialProvider with a
// programmable IssueTenantCredentials outcome.
type fakeQueueCredProvider struct {
	creds *commonqp.TenantCreds
	err   error
}

func (f *fakeQueueCredProvider) IssueTenantCredentials(ctx context.Context, in commonqp.IssueRequest) (*commonqp.TenantCreds, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.creds, nil
}
func (f *fakeQueueCredProvider) RevokeTenantCredentials(ctx context.Context, keyID string) error {
	return nil
}
func (f *fakeQueueCredProvider) Capabilities() commonqp.Capabilities {
	return commonqp.Capabilities{PerTenantAccounts: true, SubjectScopedAuth: true, StreamIsolation: true}
}
func (f *fakeQueueCredProvider) Name() string { return "fake-isolated" }

func queueCredTestApp(t *testing.T, db *sql.DB, rdb *redis.Client, cp commonqp.QueueCredentialProvider) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:       testhelpers.TestJWTSecret,
		AESKey:          testhelpers.TestAESKeyHex,
		EnabledServices: "queue",
		Environment:     "test",
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
	app.Use(middleware.RequestID(), middleware.Fingerprint())
	h := handlers.NewQueueHandler(db, rdb, cfg, nil, plans.Default())
	h.SetCredProvider(cp)
	app.Post("/queue/new", middleware.OptionalAuth(cfg), h.NewQueue)
	return app
}

func queueNew(t *testing.T, app *fiber.App, ip string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/queue/new", strings.NewReader(`{"name":"events"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

func TestQueue_IsolatedCreds_EmbeddedInResponse(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()

	cp := &fakeQueueCredProvider{creds: &commonqp.TenantCreds{
		AuthMode:  commonqp.AuthModeIsolated,
		JWT:       "eyJ.fake.jwt",
		NKey:      "SUFAKENKEYSEED",
		CredsFile: "-----BEGIN NATS USER JWT-----\nfake\n",
		Username:  "tenant_user",
		KeyID:     "ATENANTACCOUNTKEY",
	}}
	app := queueCredTestApp(t, db, rdb, cp)

	resp := queueNew(t, app, "10.70.0.1")
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var body struct {
		OK          bool   `json:"ok"`
		AuthMode    string `json:"auth_mode"`
		Credentials struct {
			AuthMode string `json:"auth_mode"`
			NatsJWT  string `json:"nats_jwt"`
			NatsNKey string `json:"nats_nkey"`
		} `json:"credentials"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	resp.Body.Close()
	assert.True(t, body.OK)
	assert.Equal(t, commonqp.AuthModeIsolated, body.AuthMode)
	assert.Equal(t, commonqp.AuthModeIsolated, body.Credentials.AuthMode)
	assert.Equal(t, "eyJ.fake.jwt", body.Credentials.NatsJWT)
	assert.Equal(t, "SUFAKENKEYSEED", body.Credentials.NatsNKey)
}

func TestQueue_CredIssueError_FallsBackToLegacyOpen(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()

	// Provider errors on issuance → handler logs + falls back to legacy_open
	// (no credentials block), still returning a usable 201.
	cp := &fakeQueueCredProvider{err: errors.New("operator seed unavailable")}
	app := queueCredTestApp(t, db, rdb, cp)

	resp := queueNew(t, app, "10.70.0.2")
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var body struct {
		OK       bool   `json:"ok"`
		AuthMode string `json:"auth_mode"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	resp.Body.Close()
	assert.True(t, body.OK)
	assert.Equal(t, commonqp.AuthModeLegacyOpen, body.AuthMode)
}
