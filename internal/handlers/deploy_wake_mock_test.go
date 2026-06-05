package handlers

// deploy_wake_mock_test.go — sqlmock-driven happy-path + error-branch coverage
// for POST /deploy/:id/wake (Wake handler, Task #54). The flag-off 501 path is
// covered in deploy_wake_test.go; this file covers the flag-ON branches:
// happy path (scale + DB flip + re-read), not-found, cross-team 404, scale
// failure (503), and the WakeDeployment DB-error (503).
//
// In-package test so the unexported DeployHandler fields are reachable and a
// recording compute provider can be injected without import indirection.

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/alicebob/miniredis/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	"instant.dev/internal/providers/compute"
)

// wakeRecordingProvider records Scale calls and can be told to fail.
type wakeRecordingProvider struct {
	scaleCalls []int32
	scaleErr   error
}

func (p *wakeRecordingProvider) Deploy(context.Context, compute.DeployOptions) (*compute.AppDeployment, error) {
	return nil, nil
}
func (p *wakeRecordingProvider) Status(context.Context, string) (*compute.AppDeployment, error) {
	return nil, nil
}
func (p *wakeRecordingProvider) Logs(context.Context, string, bool) (io.ReadCloser, error) {
	return nil, nil
}
func (p *wakeRecordingProvider) Teardown(context.Context, string) error { return nil }
func (p *wakeRecordingProvider) Redeploy(context.Context, string, []byte, map[string]string) (*compute.AppDeployment, error) {
	return nil, nil
}
func (p *wakeRecordingProvider) UpdateAccessControl(context.Context, string, bool, []string) error {
	return nil
}
func (p *wakeRecordingProvider) Scale(_ context.Context, _ string, replicas int32) error {
	p.scaleCalls = append(p.scaleCalls, replicas)
	return p.scaleErr
}

// wakeMockApp builds a flag-ON wake app with faked auth Locals + the recording
// provider. Returns app + teamID + provider so tests assert Scale calls.
func wakeMockApp(t *testing.T, db *sql.DB, prov compute.Provider) (*fiber.App, uuid.UUID) {
	t.Helper()
	teamID := uuid.New()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	h := &DeployHandler{
		db:           db,
		rdb:          rdb,
		cfg:          &config.Config{DeployScaleToZeroEnabled: true, Environment: "test"},
		compute:      prov,
		planRegistry: plans.Default(),
	}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error"})
		},
	})
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, teamID.String())
		return c.Next()
	})
	app.Post("/deploy/:id/wake", h.Wake)
	return app, teamID
}

// wakeDeploymentRow builds the full deploymentColumns row for sqlmock. Column
// order MUST match the deploymentColumns constant in models/deployment.go.
func wakeDeploymentRow(id, teamID uuid.UUID, appID, providerID string, scaledToZero bool) *sqlmock.Rows {
	cols := []string{
		"id", "team_id", "resource_id", "app_id", "provider_id", "status", "app_url",
		"env_vars", "port", "tier", "env", "private", "allowed_ips", "error_message",
		"created_at", "updated_at",
		"notify_webhook", "notify_webhook_secret", "notify_state", "notify_attempts",
		"expires_at", "ttl_policy", "reminders_sent", "last_reminder_at",
		"source", "image_ref", "registry_creds_enc",
		"git_url", "git_ref", "git_token_enc",
		"last_activity_at", "scaled_to_zero", "always_on",
	}
	now := time.Now()
	return sqlmock.NewRows(cols).AddRow(
		id, teamID, uuid.NullUUID{}, appID, providerID, "healthy", "https://x.deployment.instanode.dev",
		[]byte(`{}`), 8080, "hobby", "production", false, "", "",
		now, now,
		sql.NullString{}, sql.NullString{}, "unset", 0,
		sql.NullTime{}, "permanent", 0, sql.NullTime{},
		"tarball", "", "",
		"", "", "",
		sql.NullTime{Time: now, Valid: true}, scaledToZero, false,
	)
}

// wakeMockAppNoAuth is wakeMockApp without the team-injecting middleware, so
// requireTeam sees an empty team_id and the handler returns 401. Used to cover
// the `team, err := h.requireTeam(c); if err != nil { return err }` arm.
func wakeMockAppNoAuth(t *testing.T, db *sql.DB) *fiber.App {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	h := &DeployHandler{
		db:           db,
		rdb:          rdb,
		cfg:          &config.Config{DeployScaleToZeroEnabled: true, Environment: "test"},
		compute:      &wakeRecordingProvider{},
		planRegistry: plans.Default(),
	}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error"})
		},
	})
	app.Post("/deploy/:id/wake", h.Wake)
	return app
}

// TestWake_RequireTeamFails covers the requireTeam error arm: no team_id in
// Locals → 401 before any scale or DB work.
func TestWake_RequireTeamFails(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	app := wakeMockAppNoAuth(t, db)
	req := httptest.NewRequest(http.MethodPost, "/deploy/app-noauth/wake", nil)
	resp, err := app.Test(req, 2000)
	require.NoError(t, err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-auth wake = %d, want 401", resp.StatusCode)
	}
}

// TestWake_FetchDriverError503 covers the generic GetDeploymentByAppID driver
// error arm (NOT sql.ErrNoRows) → 503 fetch_failed.
func TestWake_FetchDriverError503(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	app, teamID := wakeMockApp(t, db, &wakeRecordingProvider{})
	expectTeamLookupOK(mock, teamID, "hobby")
	mock.ExpectQuery(`FROM deployments WHERE app_id = \$1`).
		WithArgs("app-drv").
		WillReturnError(errors.New("deployments table exploded"))

	req := httptest.NewRequest(http.MethodPost, "/deploy/app-drv/wake", nil)
	resp, err := app.Test(req, 2000)
	require.NoError(t, err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("fetch-driver-error wake = %d, want 503", resp.StatusCode)
	}
}

// TestWake_ReReadFailureFallsBack covers the post-write re-read failure arm:
// scale + WakeDeployment already succeeded, so a failing GetDeploymentByID must
// NOT fail the wake — the handler falls back to the pre-read row with
// ScaledToZero cleared and still returns 200.
func TestWake_ReReadFailureFallsBack(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	prov := &wakeRecordingProvider{}
	app, teamID := wakeMockApp(t, db, prov)
	id := uuid.New()

	expectTeamLookupOK(mock, teamID, "hobby")
	mock.ExpectQuery(`FROM deployments WHERE app_id = \$1`).
		WithArgs("app-reread").
		WillReturnRows(wakeDeploymentRow(id, teamID, "app-reread", "app-reread", true))
	mock.ExpectExec(`UPDATE deployments`).
		WithArgs(id).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// Re-read fails → handler must fall back, NOT 5xx.
	mock.ExpectQuery(`FROM deployments WHERE id = \$1`).
		WithArgs(id).
		WillReturnError(errors.New("re-read exploded"))

	req := httptest.NewRequest(http.MethodPost, "/deploy/app-reread/wake", nil)
	resp, err := app.Test(req, 2000)
	require.NoError(t, err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("re-read-failure wake = %d, want 200 (fallback); body: %s", resp.StatusCode, string(body))
	}
	if len(prov.scaleCalls) != 1 {
		t.Errorf("expected one Scale call before re-read, got %v", prov.scaleCalls)
	}
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestWake_HappyPath(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	prov := &wakeRecordingProvider{}
	app, teamID := wakeMockApp(t, db, prov)
	id := uuid.New()

	expectTeamLookupOK(mock, teamID, "hobby")
	// GetDeploymentByAppID — asleep row owned by the team.
	mock.ExpectQuery(`FROM deployments WHERE app_id = \$1`).
		WithArgs("app-abc").
		WillReturnRows(wakeDeploymentRow(id, teamID, "app-abc", "app-abc", true))
	// WakeDeployment UPDATE.
	mock.ExpectExec(`UPDATE deployments`).
		WithArgs(id).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// Re-read after wake.
	mock.ExpectQuery(`FROM deployments WHERE id = \$1`).
		WithArgs(id).
		WillReturnRows(wakeDeploymentRow(id, teamID, "app-abc", "app-abc", false))

	req := httptest.NewRequest(http.MethodPost, "/deploy/app-abc/wake", nil)
	resp, err := app.Test(req, 2000)
	require.NoError(t, err)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("wake status = %d, want 200", resp.StatusCode)
	}
	if len(prov.scaleCalls) != 1 || prov.scaleCalls[0] != 1 {
		t.Errorf("expected one Scale(1) call, got %v", prov.scaleCalls)
	}
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestWake_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	app, teamID := wakeMockApp(t, db, &wakeRecordingProvider{})
	expectTeamLookupOK(mock, teamID, "hobby")
	mock.ExpectQuery(`FROM deployments WHERE app_id = \$1`).
		WithArgs("app-missing").
		WillReturnError(sql.ErrNoRows)

	req := httptest.NewRequest(http.MethodPost, "/deploy/app-missing/wake", nil)
	resp, err := app.Test(req, 2000)
	require.NoError(t, err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("wake on missing deploy = %d, want 404", resp.StatusCode)
	}
}

func TestWake_CrossTeam404(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	app, teamID := wakeMockApp(t, db, &wakeRecordingProvider{})
	otherTeam := uuid.New()
	id := uuid.New()
	expectTeamLookupOK(mock, teamID, "hobby")
	// Row owned by a DIFFERENT team → handler must 404 (not 403).
	mock.ExpectQuery(`FROM deployments WHERE app_id = \$1`).
		WithArgs("app-other").
		WillReturnRows(wakeDeploymentRow(id, otherTeam, "app-other", "app-other", true))

	req := httptest.NewRequest(http.MethodPost, "/deploy/app-other/wake", nil)
	resp, err := app.Test(req, 2000)
	require.NoError(t, err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-team wake = %d, want 404", resp.StatusCode)
	}
}

func TestWake_ScaleFailure503(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	prov := &wakeRecordingProvider{scaleErr: errors.New("k8s boom")}
	app, teamID := wakeMockApp(t, db, prov)
	id := uuid.New()
	expectTeamLookupOK(mock, teamID, "hobby")
	mock.ExpectQuery(`FROM deployments WHERE app_id = \$1`).
		WithArgs("app-boom").
		WillReturnRows(wakeDeploymentRow(id, teamID, "app-boom", "app-boom", true))

	req := httptest.NewRequest(http.MethodPost, "/deploy/app-boom/wake", nil)
	resp, err := app.Test(req, 2000)
	require.NoError(t, err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("scale-failure wake = %d, want 503", resp.StatusCode)
	}
}

func TestWake_DBFlipFailure503(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	app, teamID := wakeMockApp(t, db, &wakeRecordingProvider{})
	id := uuid.New()
	expectTeamLookupOK(mock, teamID, "hobby")
	mock.ExpectQuery(`FROM deployments WHERE app_id = \$1`).
		WithArgs("app-dbfail").
		WillReturnRows(wakeDeploymentRow(id, teamID, "app-dbfail", "app-dbfail", true))
	mock.ExpectExec(`UPDATE deployments`).
		WithArgs(id).
		WillReturnError(errors.New("db exploded"))

	req := httptest.NewRequest(http.MethodPost, "/deploy/app-dbfail/wake", nil)
	resp, err := app.Test(req, 2000)
	require.NoError(t, err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("db-flip-failure wake = %d, want 503", resp.StatusCode)
	}
}
