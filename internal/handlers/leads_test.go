package handlers_test

// leads_test.go — unit + integration tests for POST /api/v1/leads.
//
// Validation tests run in-process with no external deps (nil DB — the handler
// returns before any DB call on every invalid-input path).
// The happy-path INSERT test requires TEST_DATABASE_URL and is skipped in CI
// builds that don't mount the test Postgres service container.

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/testhelpers"
)

// newLeadsApp wires a minimal Fiber app bound to the leads handler.
// db may be nil when only testing input-validation paths that never reach
// the DB layer.
func newLeadsApp(h *handlers.LeadsHandler) *fiber.App {
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false, "error": err.Error()})
		},
	})
	app.Post("/api/v1/leads", h.Create)
	return app
}

type leadsResp struct {
	OK      bool   `json:"ok"`
	ID      string `json:"id"`
	Error   string `json:"error"`
	Message string `json:"message"`
}

func postLead(t *testing.T, app *fiber.App, body any) (int, leadsResp) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/leads", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	defer resp.Body.Close()
	var out leadsResp
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return resp.StatusCode, out
}

// Validation tests — no DB required (nil db is safe because invalid inputs
// are rejected before any DB call is made).

func TestLeadsCreate_MissingEmail(t *testing.T) {
	app := newLeadsApp(handlers.NewLeadsHandler(nil))
	code, body := postLead(t, app, map[string]string{"name": "Alice"})
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "missing_email", body.Error)
}

func TestLeadsCreate_EmptyEmail(t *testing.T) {
	app := newLeadsApp(handlers.NewLeadsHandler(nil))
	code, body := postLead(t, app, map[string]string{"email": ""})
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "missing_email", body.Error)
}

func TestLeadsCreate_InvalidEmailFormat(t *testing.T) {
	app := newLeadsApp(handlers.NewLeadsHandler(nil))
	cases := []string{"not-an-email", "@nolocalpart", "noatsign", "a @b.c"}
	for _, e := range cases {
		t.Run(e, func(t *testing.T) {
			code, body := postLead(t, app, map[string]string{"email": e})
			assert.Equal(t, http.StatusBadRequest, code, "expected 400 for %q", e)
			assert.Equal(t, "invalid_email_format", body.Error)
		})
	}
}

func TestLeadsCreate_EmailTooLong(t *testing.T) {
	app := newLeadsApp(handlers.NewLeadsHandler(nil))
	long := strings.Repeat("a", 250) + "@b.com"
	code, body := postLead(t, app, map[string]string{"email": long})
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "invalid_email_format", body.Error)
}

func TestLeadsCreate_InvalidBody(t *testing.T) {
	app := newLeadsApp(handlers.NewLeadsHandler(nil))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/leads", strings.NewReader("{notjson"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestLeadsCreate_FieldLengthLimits(t *testing.T) {
	app := newLeadsApp(handlers.NewLeadsHandler(nil))
	cases := []struct {
		field string
		value string
		want  string
	}{
		{"name", strings.Repeat("x", 129), "invalid_name"},
		{"company", strings.Repeat("y", 129), "invalid_company"},
		{"use_case", strings.Repeat("z", 1025), "invalid_use_case"},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			code, body := postLead(t, app, map[string]string{"email": "alice@example.com", tc.field: tc.value})
			assert.Equal(t, http.StatusBadRequest, code)
			assert.Equal(t, tc.want, body.Error)
		})
	}
}

// Happy-path test — requires TEST_DATABASE_URL and a migrated schema.

func TestLeadsCreate_HappyPath(t *testing.T) {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping DB test")
	}
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()

	app := newLeadsApp(handlers.NewLeadsHandler(db))
	code, body := postLead(t, app, map[string]string{
		"email":    "enterprise-test@example.com",
		"name":     "Alice Smith",
		"company":  "Acme Corp",
		"use_case": "We need unlimited Postgres for our multi-tenant SaaS.",
	})

	require.Equal(t, http.StatusCreated, code)
	assert.True(t, body.OK)
	assert.NotEmpty(t, body.ID, "response should include the new lead UUID")

	// Verify the row landed in the DB.
	var email string
	err := db.QueryRowContext(t.Context(), `SELECT email FROM enterprise_leads WHERE id = $1`, body.ID).Scan(&email)
	require.NoError(t, err)
	assert.Equal(t, "enterprise-test@example.com", email)
}
