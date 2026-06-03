package handlers

// deploy_redeploy_inplace_mock_test.go — sqlmock-driven error-branch
// coverage for the POST /deploy/new redeploy=true in-place path.
//
// Why sqlmock and not the real test DB:
//
//   - 678-683 (lookup driver error → 503 fetch_failed): real postgres
//     either returns ErrNoRows (handled by the dedicated 404 arm) or
//     returns a row. To exercise the generic "DB exploded" arm we need
//     to inject a driver error after the team-lookup succeeds, which
//     sqlmock does deterministically.
//
//   - 689-695 (defence-in-depth wrong_team mismatch): the production
//     SQL is team-scoped, so a real DB physically cannot return a row
//     where existing.TeamID != team.ID. The arm exists as a model-layer
//     bug guard. sqlmock lets us forge that exact bug by returning a
//     row whose team_id column does not match the WHERE clause's
//     team_id arg — pinning the guard against a future model refactor.
//
//   - 708-710 (UpdateDeploymentStatus error → continues): we want to
//     prove the handler still 202s even when the status flip fails. A
//     real DB UPDATE here always succeeds.
//
// 701-704 (empty provider_id → 409 not_ready) is covered separately by
// a real-DB seed test in deploy_redeploy_inplace_test.go — the row
// shape is naturally produced by the platform during the building
// window, so sqlmock would be over-engineering.
//
// In-package test so the unexported DeployHandler struct fields, the
// noop compute provider wiring, and the New handler are all reachable
// without import indirection.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/alicebob/miniredis/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	"instant.dev/internal/providers/compute/noop"
)

// errMockRedeployDriver is the sentinel returned by sqlmock for the
// FindActiveDeploymentByTeamEnvName driver-error and the
// UpdateDeploymentStatus driver-error test cases. Named so the slog.Warn
// arm's "error" field is searchable in test logs if a regression brings
// the line back as uncovered.
var errMockRedeployDriver = errors.New("mock: deployments table exploded")

// deploymentColumnsList mirrors models.deploymentColumns (kept as a slice
// so sqlmock.NewRows can consume it). MUST stay in sync with that
// constant — drift here means scanDeployment fails with a column-count
// mismatch and the test breaks loudly rather than silently mis-asserting.
var deploymentColumnsList = []string{
	"id", "team_id", "resource_id", "app_id", "provider_id", "status", "app_url",
	"env_vars", "port", "tier", "env", "private", "allowed_ips", "error_message",
	"created_at", "updated_at",
	"notify_webhook", "notify_webhook_secret", "notify_state", "notify_attempts",
	"expires_at", "ttl_policy", "reminders_sent", "last_reminder_at",
	"source", "image_ref", "registry_creds_enc",
	"git_url", "git_ref", "git_token_enc",
}

// redeployMockApp wires a minimal Fiber app that drives DeployHandler.New
// against a sqlmock-backed DB. Mirrors teamCoverageApp from
// team_coverage_push_test.go: a Locals-injecting middleware fakes the
// auth surface so RequireAuth is bypassed; no Idempotency middleware so
// the single test request hits the handler directly.
//
// Returns the app + the team UUID + the user UUID. The teamID matches
// the team-lookup mock's RETURNING row so requireTeam succeeds before
// the handler reaches the redeploy branch under test.
func redeployMockApp(t *testing.T, db *sql.DB) (*fiber.App, uuid.UUID, uuid.UUID) {
	t.Helper()
	teamID := uuid.New()
	userID := uuid.New()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	cfg := &config.Config{
		JWTSecret:       "test-secret-that-is-at-least-32-bytes-long!!",
		AESKey:          "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
		EnabledServices: "deploy",
		Environment:     "test",
	}

	h := &DeployHandler{
		db:           db,
		rdb:          rdb,
		cfg:          cfg,
		compute:      noop.New(),
		planRegistry: plans.Default(),
	}

	app := fiber.New(fiber.Config{
		BodyLimit: 50 * 1024 * 1024,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error", "message": err.Error()})
		},
	})
	// Fake auth: stash team_id + user_id directly into Locals so
	// requireTeam reads the IDs but no JWT is required.
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, teamID.String())
		c.Locals(middleware.LocalKeyUserID, userID.String())
		return c.Next()
	})
	app.Post("/deploy/new", h.New)
	return app, teamID, userID
}

// multipartRedeployMockBody builds a multipart body for redeploy=true tests.
// Local helper so we don't depend on the _test package's body builder.
func multipartRedeployMockBody(t *testing.T, fields map[string]string) (*bytes.Buffer, string) {
	t.Helper()
	buf := &bytes.Buffer{}
	w := multipart.NewWriter(buf)
	fw, err := w.CreateFormFile("tarball", "app.tar.gz")
	require.NoError(t, err)
	_, err = fw.Write([]byte("mock-tarball-bytes"))
	require.NoError(t, err)
	for k, v := range fields {
		require.NoError(t, w.WriteField(k, v))
	}
	require.NoError(t, w.Close())
	return buf, w.FormDataContentType()
}

// expectTeamLookupOK queues a GetTeamByID sqlmock expectation that returns
// the canonical 6-column team row. Used by every test in this file because
// requireTeam fires before the redeploy branch is reached.
func expectTeamLookupOK(mock sqlmock.Sqlmock, teamID uuid.UUID, tier string) {
	mock.ExpectQuery(`SELECT id, name, plan_tier, stripe_customer_id, created_at`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "plan_tier", "stripe_customer_id", "created_at",
			"default_deployment_ttl_policy",
		}).AddRow(teamID, "mock-team", tier, sql.NullString{}, time.Now(), "auto_24h"))
}

// TestDeployNew_Redeploy_LookupDriverError_Returns503 pins deploy.go:678-683.
// requireTeam succeeds; FindActiveDeploymentByTeamEnvName returns a generic
// driver error (NOT sql.ErrNoRows). Handler must 503 fetch_failed and log.
func TestDeployNew_Redeploy_LookupDriverError_Returns503(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	app, teamID, _ := redeployMockApp(t, db)

	expectTeamLookupOK(mock, teamID, "pro")
	// FindActiveDeploymentByTeamEnvName lookup → driver explodes.
	mock.ExpectQuery(`FROM deployments\s+WHERE team_id = \$1\s+AND env = \$2\s+AND env_vars->>'_name' = \$3`).
		WithArgs(teamID, "development", "foo").
		WillReturnError(errMockRedeployDriver)

	body, ct := multipartRedeployMockBody(t, map[string]string{
		"name":     "foo",
		"redeploy": "true",
		"port":     "8080",
		"env":      "development",
	})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode,
		"lookup driver error must surface as 503 fetch_failed; body: %s", string(respBody))

	var errBody struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	require.NoError(t, json.Unmarshal(respBody, &errBody))
	assert.False(t, errBody.OK)
	assert.Equal(t, "fetch_failed", errBody.Error,
		"driver-error path must use the canonical fetch_failed code, not the 404 envelope")

	// Belt-and-braces: sqlmock saw exactly the two queries we sequenced
	// (team lookup + deployments lookup). Anything extra would indicate
	// the handler reached compute or audit_log paths we explicitly want
	// it to short-circuit on a lookup failure.
	require.NoError(t, mock.ExpectationsWereMet())
}

// TestDeployNew_Redeploy_WrongTeam_DefenceInDepth pins deploy.go:689-695.
// The model layer's SQL is team-scoped, so this arm can only fire if a
// future refactor breaks the query. We forge the bug by returning a row
// whose team_id column does NOT equal the authenticated team's UUID, then
// assert the handler returns the same 404 envelope as the no-match path
// (no cross-tenant existence leak).
func TestDeployNew_Redeploy_WrongTeam_DefenceInDepth(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	app, authedTeamID, _ := redeployMockApp(t, db)
	otherTeamID := uuid.New() // the forged "wrong" team_id on the row

	expectTeamLookupOK(mock, authedTeamID, "pro")

	// FindActiveDeploymentByTeamEnvName returns a row but team_id is
	// otherTeamID — the defence-in-depth check at line 688 must reject it.
	envVarsJSON, _ := json.Marshal(map[string]string{"_name": "wrong-team-app"})
	mock.ExpectQuery(`FROM deployments\s+WHERE team_id = \$1\s+AND env = \$2\s+AND env_vars->>'_name' = \$3`).
		WithArgs(authedTeamID, "development", "wrong-team-app").
		WillReturnRows(sqlmock.NewRows(deploymentColumnsList).AddRow(
			uuid.New(),                  // id
			otherTeamID,                 // team_id (the forged mismatch)
			uuid.NullUUID{},             // resource_id
			"wrongteam",                 // app_id
			"app-wrongteam",             // provider_id — non-empty so we pass the 701 guard too
			"healthy",                   // status
			"https://wrongteam.deploy.", // app_url
			envVarsJSON,                 // env_vars
			8080,                        // port
			"pro",                       // tier
			"development",               // env
			false,                       // private
			"",                          // allowed_ips
			sql.NullString{},            // error_message
			time.Now(), time.Now(),      // created_at, updated_at
			sql.NullString{}, sql.NullString{}, "unset", 0, // notify_*
			sql.NullTime{}, "permanent", 0, sql.NullTime{}, // ttl_*
			"tarball", "", "", // source, image_ref, registry_creds_enc (mig 064)
			"", "", "", // git_url, git_ref, git_token_enc (mig 065)
		))

	body, ct := multipartRedeployMockBody(t, map[string]string{
		"name":     "wrong-team-app",
		"redeploy": "true",
		"port":     "8080",
		"env":      "development",
	})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusNotFound, resp.StatusCode,
		"defence-in-depth wrong_team must surface as 404 (NOT 403/500); body: %s", string(respBody))

	var errBody struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	require.NoError(t, json.Unmarshal(respBody, &errBody))
	assert.False(t, errBody.OK)
	assert.Equal(t, "no_existing_deployment_to_redeploy", errBody.Error,
		"wrong_team response shape MUST be byte-identical to the no-match 404 (no info leak)")

	require.NoError(t, mock.ExpectationsWereMet())
}

// TestDeployNew_Redeploy_UpdateStatusError_StillAccepts pins deploy.go:708-710.
// The status flip to 'building' is best-effort: a transient UPDATE failure
// must NOT block the redeploy from being kicked off. The handler must log
// a warning and continue to the audit + async compute path, returning 202.
//
// This test mocks the UPDATE to fail; the subsequent audit goroutine and
// runRedeployAsync goroutine will both run against the closed sqlmock DB
// after the test returns. Both paths are best-effort and safego-guarded,
// so they slog.Warn and exit without panicking — sqlmock's "unmet
// expectations" check is intentionally NOT called at the end of this test
// because the async goroutines may or may not race the test cleanup.
func TestDeployNew_Redeploy_UpdateStatusError_StillAccepts(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	app, teamID, _ := redeployMockApp(t, db)
	rowID := uuid.New()

	expectTeamLookupOK(mock, teamID, "pro")

	// FindActiveDeploymentByTeamEnvName returns a valid, owned, ready row.
	envVarsJSON, _ := json.Marshal(map[string]string{"_name": "update-fail"})
	mock.ExpectQuery(`FROM deployments\s+WHERE team_id = \$1\s+AND env = \$2\s+AND env_vars->>'_name' = \$3`).
		WithArgs(teamID, "development", "update-fail").
		WillReturnRows(sqlmock.NewRows(deploymentColumnsList).AddRow(
			rowID,
			teamID,
			uuid.NullUUID{},
			"updfail8",
			"app-updfail8",
			"healthy",
			"https://updfail8.deploy.",
			envVarsJSON,
			8080, "pro", "development",
			false, "",
			sql.NullString{},
			time.Now(), time.Now(),
			sql.NullString{}, sql.NullString{}, "unset", 0,
			sql.NullTime{}, "permanent", 0, sql.NullTime{},
			"tarball", "", "", // source, image_ref, registry_creds_enc (mig 064)
			"", "", "", // git_url, git_ref, git_token_enc (mig 065)
		))

	// UPDATE deployments SET status = $1 ... → driver error. The handler
	// must slog.Warn and CONTINUE (NOT return 5xx) — the redeploy itself
	// is still useful because runRedeployAsync will flip the row later.
	mock.ExpectExec(`UPDATE deployments\s+SET status = \$1, error_message = \$2, updated_at = now\(\)`).
		WithArgs("building", nil, rowID).
		WillReturnError(errMockRedeployDriver)

	// MatchExpectationsInOrder=false because the audit goroutine
	// (emitDeployAudit) and runRedeployAsync goroutine race the response
	// write; we don't pin further expectations after the UPDATE.
	mock.MatchExpectationsInOrder(false)

	body, ct := multipartRedeployMockBody(t, map[string]string{
		"name":     "update-fail",
		"redeploy": "true",
		"port":     "8080",
		"env":      "development",
	})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusAccepted, resp.StatusCode,
		"UPDATE status failure must NOT block the 202 accept; body: %s", string(respBody))

	var parsed struct {
		OK         bool `json:"ok"`
		Redeployed bool `json:"redeployed"`
		Item       struct {
			AppID      string `json:"app_id"`
			Redeployed bool   `json:"redeployed"`
		} `json:"item"`
	}
	require.NoError(t, json.Unmarshal(respBody, &parsed))
	assert.True(t, parsed.OK)
	assert.True(t, parsed.Redeployed)
	assert.Equal(t, "updfail8", parsed.Item.AppID,
		"in-place redeploy reuses the existing app_id even when the status flip fails")

	// Give the audit + redeploy goroutines a moment to drain before the
	// sqlmock DB is closed. They're best-effort (safego-guarded) so a
	// panic here would still bubble out — this drains gracefully when
	// they run cleanly, and the safego recover catches anything else.
	time.Sleep(50 * time.Millisecond)
}

// TestDeployNew_Redeploy_EmptyProviderID_Returns409 pins deploy.go:701-704.
// A row whose provider_id is "" represents a deployment whose initial
// build is still running — compute.Redeploy can't operate on it yet.
// The handler must 409 not_ready (same posture as POST /deploy/:id/redeploy
// against an unbuilt row).
//
// sqlmock variant: the real-DB integration test in
// deploy_redeploy_inplace_test.go pre-seeds a row with provider_id = NULL
// (Postgres-side), which scanDeployment surfaces as "". We mirror that
// exactly via sql.NullString{Valid: false}.
func TestDeployNew_Redeploy_EmptyProviderID_Returns409(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	app, teamID, _ := redeployMockApp(t, db)

	expectTeamLookupOK(mock, teamID, "pro")

	envVarsJSON, _ := json.Marshal(map[string]string{"_name": "still-building"})
	mock.ExpectQuery(`FROM deployments\s+WHERE team_id = \$1\s+AND env = \$2\s+AND env_vars->>'_name' = \$3`).
		WithArgs(teamID, "development", "still-building").
		WillReturnRows(sqlmock.NewRows(deploymentColumnsList).AddRow(
			uuid.New(),
			teamID,
			uuid.NullUUID{},
			"buildonly",
			sql.NullString{Valid: false}, // provider_id NULL — the trigger
			"building",
			sql.NullString{Valid: false}, // app_url NULL too — same building state
			envVarsJSON,
			8080, "pro", "development",
			false, "",
			sql.NullString{},
			time.Now(), time.Now(),
			sql.NullString{}, sql.NullString{}, "unset", 0,
			sql.NullTime{}, "permanent", 0, sql.NullTime{},
			"tarball", "", "", // source, image_ref, registry_creds_enc (mig 064)
			"", "", "", // git_url, git_ref, git_token_enc (mig 065)
		))

	body, ct := multipartRedeployMockBody(t, map[string]string{
		"name":     "still-building",
		"redeploy": "true",
		"port":     "8080",
		"env":      "development",
	})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusConflict, resp.StatusCode,
		"redeploy of a row with empty provider_id must 409 not_ready; body: %s", string(respBody))

	var errBody struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	require.NoError(t, json.Unmarshal(respBody, &errBody))
	assert.False(t, errBody.OK)
	assert.Equal(t, "not_ready", errBody.Error,
		"empty-provider_id response code MUST be 'not_ready' so agents can retry without re-listing")

	require.NoError(t, mock.ExpectationsWereMet())
}

// TestDeployNew_Redeploy_MissingName_AfterValidation pins deploy.go:655-661.
// The branch fires when shouldRedeployInPlace is true AND name == "". In
// practice requireName at line 604 fires first on empty/whitespace input,
// so production traffic never reaches our 654 check. The arm is
// defence-in-depth — kept so a future refactor that loosens requireName
// (e.g. allows "" for a different reason) doesn't silently fall through to
// FindActiveDeploymentByTeamEnvName with an empty name. We exercise it by
// calling the handler with a context already past the requireName step:
// not possible via HTTP, so we drive the helper directly here.
//
// Direct unit-level coverage: we already proved shouldRedeployInPlace
// returns true for "true" in the whitebox file; combining that with a
// pre-flight name-emptiness check is what the if-statement does. We can
// reach the actual code path by calling New with a multipart that
// satisfies requireName (non-empty name) but encoding a SECOND name field
// whose first value is consumed by requireName as "" — multipart parsing
// preserves the first value only, so this is brittle. Cleanest path: a
// targeted whitebox check that the branch logic (name == "" guard
// combined with shouldRedeployInPlace) returns the documented error
// envelope. We do that via a synthesised fiber.Ctx in
// deploy_redeploy_inplace_whitebox_test.go's shouldRedeployInPlace tests
// + the assertion below that the HTTP-level NoName test from
// deploy_redeploy_inplace_test.go already proves the rejection envelope
// (its assertion accepts both name_required and redeploy_requires_name).
//
// This stub test is intentionally a no-op so the coverage tool sees the
// reasoning trail in one place. The genuine line-655-661 hit comes from
// the upstream NoName test when requireName happens to forward an empty
// name (which it does for the rejected-too-short cases — covered by
// requireName's own test suite).
// The defence-in-depth `if name == ""` arm that this test used to
// document was removed (see deploy.go above the FindActiveDeploymentByTeamEnvName
// call) once it was proven unreachable: requireName() always returns either
// an error or a non-empty trimmed string. The metric label "missing_name"
// is therefore unused and is intentionally absent from
// DeployRedeployInPlaceTotal's documented outcomes.

// ── ctx + helper sanity check (compile-only) ────────────────────────────
//
// Touching context here so go vet doesn't complain about an unused import
// when the test file is built standalone.
var _ = context.Background
