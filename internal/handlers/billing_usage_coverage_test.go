package handlers_test

// billing_usage_coverage_test.go — fills the remaining GetUsage / computeUsage
// / tierForTeam / mbToBytes branches not exercised by billing_usage_test.go:
//
//   - GetUsage with no team local → 401 unauthorized.
//   - computeUsage tier-lookup error → 500 usage_failed (propagated through
//     the cache GetOrSet loader).
//   - mbToBytes unlimited (-1) path via the team tier whose storage limit is
//     unlimited.

import (
	"database/sql"
	"encoding/json"
	"errors"
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

	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
)

func TestBillingUsage_NoTeamLocal_Returns401(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false, "error": err.Error()})
		},
	})
	// No team_id local stamped → uuid.Parse("") fails → 401.
	h := handlers.NewBillingUsageHandler(db, nil, plans.Default())
	app.Get("/api/v1/billing/usage", h.GetUsage)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/billing/usage", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestBillingUsage_TierLookupError_Returns500(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	teamID := uuid.New()
	// tierForTeam → GetTeamByID errors → computeUsage returns the error →
	// GetOrSet propagates → 500 usage_failed.
	mock.ExpectQuery(`SELECT.*FROM teams WHERE id`).
		WithArgs(teamID).
		WillReturnError(errors.New("boom"))

	app := newUsageApp(t, db, rdb, teamID)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/billing/usage", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "usage_failed", body["error"])
}

func TestBillingUsage_StorageSumError_Returns500(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	teamID := uuid.New()
	mock.ExpectQuery(`SELECT.*FROM teams WHERE id`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "plan_tier", "stripe_customer_id", "created_at", "default_deployment_ttl_policy",
		}).AddRow(teamID, sql.NullString{}, "hobby", sql.NullString{}, time.Now(), "auto_24h"))
	// First storage SUM errors → computeUsage returns it.
	mock.ExpectQuery(`SELECT COALESCE\(SUM\(storage_bytes\)`).
		WillReturnError(errors.New("sum boom"))

	app := newUsageApp(t, db, rdb, teamID)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/billing/usage", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// TestBillingUsage_UnlimitedTier_MbToBytesNegative covers mbToBytes(-1) → -1:
// the team tier has unlimited storage, so each storage metric's limit_bytes
// must render as -1 (the dashboard's "∞").
func TestBillingUsage_UnlimitedTier_MbToBytesNegative(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	teamID := uuid.New()
	// team tier → unlimited storage (-1) → mbToBytes(-1) path.
	mock.ExpectQuery(`SELECT.*FROM teams WHERE id`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "plan_tier", "stripe_customer_id", "created_at", "default_deployment_ttl_policy",
		}).AddRow(teamID, sql.NullString{}, "team", sql.NullString{}, time.Now(), "auto_24h"))
	for range []string{"postgres", "redis", "mongodb"} {
		mock.ExpectQuery(`SELECT COALESCE\(SUM\(storage_bytes\)`).
			WillReturnRows(sqlmock.NewRows([]string{"sum"}).AddRow(int64(0)))
	}
	mock.ExpectQuery(`(?i)SELECT count\(\*\)\s+FROM deployments`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`SELECT COUNT\(\*\)\s+FROM resources`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`SELECT COUNT\(DISTINCT key\) FROM vault_secrets`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM users WHERE team_id`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	app := newUsageApp(t, db, rdb, teamID)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/billing/usage", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		Usage map[string]struct {
			LimitBytes int64 `json:"limit_bytes"`
		} `json:"usage"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, int64(-1), body.Usage["postgres"].LimitBytes, "unlimited tier storage limit must serialise as -1")
	_ = middleware.LocalKeyTeamID
}
