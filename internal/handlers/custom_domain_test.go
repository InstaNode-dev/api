package handlers_test

// custom_domain_test.go — unit coverage for the per-tier custom_domains_max
// cap added by FIX-G (2026-05-14).
//
// Scope: the *count* enforcement that sits between the boolean tier gate
// (CustomDomainsAllowed) and the row insert. The full integration flow
// (TXT challenge, ingress, cert) is covered by the live-API e2e suite —
// these tests only need to prove that:
//
//   1. A team at-or-over the cap gets a 402 with `agent_action` and the
//      offending limit/current numbers in the JSON payload (so an agent
//      can self-remediate).
//   2. A team under the cap is admitted to the next step in the handler
//      (the body parse) — we assert the count branch did NOT 402 by
//      reading the body-parse failure that follows.
//
// We deliberately stop short of mocking the full happy-path INSERT here —
// that path lives in models/custom_domain.go which has its own coverage,
// and exercising it would require mirroring the full set of SELECT/INSERT
// stubs in sqlmock. The 402 / non-402 split is the actual policy
// regression we want to lock.

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

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
)

// customDomainTestApp wires POST /api/v1/stacks/:slug/domains against a
// mocked DB + a stub auth middleware. The k8s provider is intentionally
// nil — the Create handler never reaches the k8s call when the cap fires.
func customDomainTestApp(t *testing.T, db *sql.DB, teamID uuid.UUID) *fiber.App {
	t.Helper()
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).
				JSON(fiber.Map{"ok": false, "error": err.Error()})
		},
	})
	app.Use(middleware.RequestID())
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, teamID.String())
		c.Locals(middleware.LocalKeyUserID, uuid.NewString())
		return c.Next()
	})
	cfg := &config.Config{}
	h := handlers.NewCustomDomainHandler(db, cfg, plans.Default(), nil)
	app.Post("/api/v1/stacks/:slug/domains", h.Create)
	return app
}

// defaultDeploymentTTLPolicy is the auto_24h policy value GetTeamByID's
// COALESCE falls back to; the test mock supplies it directly so the column
// set matches the real query.
const defaultDeploymentTTLPolicy = "auto_24h"

// expectTeamRowForCustomDomain stubs the GetTeamByID query that requireTeam runs first.
// The plan_tier dictates which branch of the cap logic fires.
//
// The column set must match models.GetTeamByID's SELECT exactly. The
// default_deployment_ttl_policy column (migration 045) is the 6th — a stale
// 5-column mock makes Scan fail with "expected 5 destination arguments in
// Scan, not 6".
func expectTeamRowForCustomDomain(mock sqlmock.Sqlmock, teamID uuid.UUID, planTier string) {
	rows := sqlmock.NewRows([]string{
		"id", "name", "plan_tier", "stripe_customer_id", "created_at",
		"default_deployment_ttl_policy",
	}).
		AddRow(teamID, sql.NullString{String: "Acme", Valid: true}, planTier, sql.NullString{}, time.Now(),
			defaultDeploymentTTLPolicy)
	mock.ExpectQuery(`SELECT.*FROM teams WHERE id`).
		WithArgs(teamID).WillReturnRows(rows)
}

// expectDomainListByTeam stubs ListCustomDomainsByTeam. count is the
// number of "existing" rows we want the count query to return — the test
// can simulate "team has 0 / 1 / 5 hostnames already" by tweaking count.
func expectDomainListByTeam(mock sqlmock.Sqlmock, teamID uuid.UUID, count int) {
	cols := []string{
		"id", "team_id", "stack_id", "hostname",
		"verification_token", "status",
		"verified_at", "cert_ready_at",
		"last_check_at", "last_check_err",
		"created_at",
	}
	rows := sqlmock.NewRows(cols)
	for i := 0; i < count; i++ {
		rows.AddRow(
			uuid.New(), teamID, uuid.New(), "host-"+uuid.New().String()+".example.com",
			"tok", "verified",
			sql.NullTime{}, sql.NullTime{},
			sql.NullTime{}, sql.NullString{},
			time.Now(),
		)
	}
	mock.ExpectQuery(`SELECT.*FROM custom_domains.*team_id`).
		WithArgs(teamID).WillReturnRows(rows)
}

// postDomain fires the create request. We pass a non-empty body so the
// handler doesn't reject for invalid_body before it reaches the cap check.
// (Body parse happens *after* the cap check, so under cap we'll see a
// later error; over cap we'll see the 402 short-circuit.)
func postDomain(t *testing.T, app *fiber.App, slug string, body any) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stacks/"+slug+"/domains", &buf)
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// Tier below the feature gate (hobby) — must 402 with upgrade_required,
// NOT custom_domains_limit_reached. This guards the order of the two
// 402 paths: the boolean gate trips first so the user sees "upgrade your
// plan" rather than "you hit the cap" (which would be a misleading hint
// for a tier where the feature isn't on at all).
func TestCustomDomainCreate_Hobby_GetsBooleanUpgrade_NotCapError(t *testing.T) {
	teamID := uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	expectTeamRowForCustomDomain(mock, teamID, "hobby")
	// No domain-list query — the boolean gate fires first.

	app := customDomainTestApp(t, db, teamID)
	resp := postDomain(t, app, "any-slug", map[string]string{"hostname": "app.example.com"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "upgrade_required", body["error"],
		"hobby must trip the boolean gate (upgrade_required), not the cap (custom_domains_limit_reached)")
	require.NoError(t, mock.ExpectationsWereMet())
}

// Hobby Plus at the cap (1) — must 402 with custom_domains_limit_reached
// and include limit/current/tier/agent_action so an agent can recover.
func TestCustomDomainCreate_HobbyPlus_AtCap_Returns402WithAgentAction(t *testing.T) {
	teamID := uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	expectTeamRowForCustomDomain(mock, teamID, "hobby_plus")
	// hobby_plus cap is 1; simulate 1 existing domain — next add must 402.
	expectDomainListByTeam(mock, teamID, 1)

	app := customDomainTestApp(t, db, teamID)
	resp := postDomain(t, app, "any-slug", map[string]string{"hostname": "app.example.com"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "custom_domains_limit_reached", body["error"])
	assert.Equal(t, float64(1), body["limit"])
	assert.Equal(t, float64(1), body["current"])
	assert.Equal(t, "hobby_plus", body["tier"])
	assert.Equal(t, "delete_existing_or_upgrade", body["agent_action"],
		"agent_action must be machine-readable so an LLM can self-recover")
	require.NoError(t, mock.ExpectationsWereMet())
}

// Pro over the cap (5) — same shape, different numbers. Locks the per-tier
// limit lookup (CustomDomainsMaxLimit) so a future yaml drift can't
// silently move the cap.
func TestCustomDomainCreate_Pro_OverCap_Returns402(t *testing.T) {
	teamID := uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	expectTeamRowForCustomDomain(mock, teamID, "pro")
	// Pro cap is 5; simulate 5 existing domains.
	expectDomainListByTeam(mock, teamID, 5)

	app := customDomainTestApp(t, db, teamID)
	resp := postDomain(t, app, "any-slug", map[string]string{"hostname": "app.example.com"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "custom_domains_limit_reached", body["error"])
	assert.Equal(t, float64(5), body["limit"])
	assert.Equal(t, float64(5), body["current"])
	assert.Equal(t, "pro", body["tier"])
}

// Hobby Plus under the cap — the count check passes; the handler proceeds
// to the stack lookup which will fail (no stack row stubbed). We assert
// the response is NOT a 402 with the cap error, which proves the count
// branch let the request through.
func TestCustomDomainCreate_HobbyPlus_UnderCap_PassesCountCheck(t *testing.T) {
	teamID := uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	expectTeamRowForCustomDomain(mock, teamID, "hobby_plus")
	// 0 existing domains, cap 1 — should pass and continue past the cap.
	expectDomainListByTeam(mock, teamID, 0)
	// The next step in the handler is requireOwnedStack — a SELECT on
	// stacks WHERE slug = 'any-slug'. Stub it returning no rows so the
	// handler short-circuits with 404 (or service_unavailable) rather
	// than 402-cap-reached. We allow any matching pattern.
	mock.ExpectQuery(`SELECT.*FROM stacks`).WillReturnError(sql.ErrNoRows)

	app := customDomainTestApp(t, db, teamID)
	resp := postDomain(t, app, "any-slug", map[string]string{"hostname": "app.example.com"})
	defer resp.Body.Close()

	// The exact status after the cap check depends on subsequent stubs —
	// what matters here is that the body is NOT custom_domains_limit_reached.
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if errStr, ok := body["error"].(string); ok {
		assert.NotEqual(t, "custom_domains_limit_reached", errStr,
			"under-cap call must not 402 with custom_domains_limit_reached; got body=%v (status=%d)", body, resp.StatusCode)
	}
}

// Plain-language sanity check on the registry-side numbers — duplicated
// here so a regression in api/plans.yaml fails this test (the common-side
// test guards common/defaultYAML; this one guards the api/plans.yaml that
// actually ships in production).
func TestCustomDomainsMax_RegistryNumbers(t *testing.T) {
	r := plans.Default()
	cases := []struct {
		tier string
		want int
	}{
		{"anonymous", 0},
		{"free", 0},
		{"hobby", 0},
		{"hobby_plus", 1},
		{"pro", 5},
		{"team", 50},
		{"growth", 3},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, r.CustomDomainsMaxLimit(c.tier),
			"CustomDomainsMaxLimit(%q)", c.tier)
	}
}

// _ keeps context import live when the test file is edited down to only
// the registry-side test; remove if both contextual tests survive.
var _ = context.Background
