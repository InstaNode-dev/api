package handlers_test

// billing_usage_coverage_test.go — fills the remaining GetUsage / computeUsage
// / tierForTeam / mbToBytes branches not exercised by billing_usage_test.go:
//
//   - GetUsage with no team local → 401 unauthorized.
//   - computeUsage tier-lookup error → 500 usage_failed (propagated through
//     the cache GetOrSet loader).
//   - mbToBytes unlimited (-1) + finite paths: exercised directly in
//     mb_to_bytes_internal_test.go (no real tier carries -1 post strict-margin
//     redesign).

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

// NOTE: the unlimited (mbToBytes(-1) → -1) path is exercised directly with
// synthetic inputs in mb_to_bytes_internal_test.go (package handlers). Post
// strict-80%-margin redesign no real tier carries an unlimited (-1) storage
// limit, so the -1 path can no longer be reached via the team tier through
// the HTTP usage handler; testing the helper directly keeps the defensive
// "-1 → ∞" rendering covered.
