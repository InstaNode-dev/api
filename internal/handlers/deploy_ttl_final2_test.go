package handlers_test

// deploy_ttl_final2_test.go — FINAL SERIAL PASS #2 coverage for the DB-error
// arms in deploy_ttl.go (MakePermanent / SetTTL / lookupDeployment) the happy-
// path deploy_ttl_test.go leaves uncovered:
//
//   * MakePermanent update_failed   (L72-78, failAfter=2)
//   * MakePermanent refresh_failed  (L82-86, failAfter=3)
//   * SetTTL update_failed          (L157-163, failAfter=2)
//   * SetTTL refresh_failed         (L166-170, failAfter=3)
//   * lookupDeployment fetch_failed (L217-220, failAfter=1)
//
// Seeds a deployment under the JWT's team on the pooled DB, then drives the
// handler over a fault DB sharing the same postgres DSN so an EARLY query
// succeeds (seeing the seeded row) and the targeted LATER query errors.

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
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
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// deployTTLFaultApp builds the two TTL endpoints over a fault DB.
func deployTTLFaultApp(t *testing.T, db *sql.DB) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:       testhelpers.TestJWTSecret,
		AESKey:          testhelpers.TestAESKeyHex,
		ComputeProvider: "noop",
	}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if errors.Is(e, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if fe, ok := e.(*fiber.Error); ok {
				code = fe.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error"})
		},
	})
	dh := handlers.NewDeployHandler(db, nil, cfg, plans.Default())
	app.Use(middleware.RequestID())
	app.Post("/api/v1/deployments/:id/make-permanent", middleware.RequireAuth(cfg), dh.MakePermanent)
	app.Post("/api/v1/deployments/:id/ttl", middleware.RequireAuth(cfg), dh.SetTTL)
	return app
}

// ttlSeedDeployment seeds a hobby deployment owned by teamID and returns its
// app_id slug.
func ttlSeedDeployment(t *testing.T, db *sql.DB, teamID string) string {
	t.Helper()
	d, err := models.CreateDeployment(context.Background(), db, models.CreateDeploymentParams{
		TeamID: uuid.MustParse(teamID),
		AppID:  "ttlf2-" + uuid.NewString()[:8],
		Tier:   "hobby",
	})
	require.NoError(t, err)
	t.Cleanup(func() { db.Exec(`DELETE FROM deployments WHERE id = $1`, d.ID) })
	return d.AppID
}

func postTTL(t *testing.T, app *fiber.App, path, jwt, body string) (int, string) {
	t.Helper()
	var r *strings.Reader
	if body != "" {
		r = strings.NewReader(body)
	} else {
		r = strings.NewReader("")
	}
	req := httptest.NewRequest(http.MethodPost, path, r)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	var raw [2048]byte
	n, _ := resp.Body.Read(raw[:])
	return resp.StatusCode, string(raw[:n])
}

func ttlNeedDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
}

func TestDeployTTLFinal2_MakePermanent_UpdateFailed(t *testing.T) {
	ttlNeedDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "hobby")
	appID := ttlSeedDeployment(t, seedDB, teamID)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "ttlf2@example.com")

	// team(1)+lookup(2) ok, MakeDeploymentPermanent(3) errors.
	app := deployTTLFaultApp(t, openFaultDB(t, 2))
	status, body := postTTL(t, app, "/api/v1/deployments/"+appID+"/make-permanent", jwt, "")
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Contains(t, body, "update_failed")
}

func TestDeployTTLFinal2_MakePermanent_RefreshFailed(t *testing.T) {
	ttlNeedDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "hobby")
	appID := ttlSeedDeployment(t, seedDB, teamID)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "ttlf2@example.com")

	// team(1)+lookup(2)+update(3) ok, GetDeploymentByID refresh(4) errors.
	app := deployTTLFaultApp(t, openFaultDB(t, 3))
	status, body := postTTL(t, app, "/api/v1/deployments/"+appID+"/make-permanent", jwt, "")
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Contains(t, body, "fetch_failed")
}

func TestDeployTTLFinal2_SetTTL_UpdateFailed(t *testing.T) {
	ttlNeedDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "hobby")
	appID := ttlSeedDeployment(t, seedDB, teamID)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "ttlf2@example.com")

	app := deployTTLFaultApp(t, openFaultDB(t, 2))
	status, body := postTTL(t, app, "/api/v1/deployments/"+appID+"/ttl", jwt, `{"hours":48}`)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Contains(t, body, "update_failed")
}

func TestDeployTTLFinal2_SetTTL_RefreshFailed(t *testing.T) {
	ttlNeedDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "hobby")
	appID := ttlSeedDeployment(t, seedDB, teamID)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "ttlf2@example.com")

	app := deployTTLFaultApp(t, openFaultDB(t, 3))
	status, body := postTTL(t, app, "/api/v1/deployments/"+appID+"/ttl", jwt, `{"hours":48}`)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Contains(t, body, "fetch_failed")
}

// lookupDeployment fetch_failed: GetDeploymentByAppID errors (non-NotFound)
// before any UUID fallback → fetch_failed. failAfter=1 (team lookup ok, app_id
// lookup errors).
func TestDeployTTLFinal2_Lookup_FetchFailed(t *testing.T) {
	ttlNeedDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "hobby")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "ttlf2@example.com")

	app := deployTTLFaultApp(t, openFaultDB(t, 1))
	status, body := postTTL(t, app, "/api/v1/deployments/some-app/make-permanent", jwt, "")
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Contains(t, body, "fetch_failed")
}
