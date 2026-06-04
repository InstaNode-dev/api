package handlers_test

// billing_test_cohort_test.go — W0 / PR-1 (cohort-isolation foundation).
//
// Proves the api-side synthetic-cohort skip-guard on the two self-serve
// charge-initiation handlers (CreateCheckoutAPI, ChangePlanAPI): a team with
// teams.is_test_cohort=true (migration 067) is rejected with a deterministic
// 403 synthetic_test_cohort BEFORE any Razorpay call, while a normal team
// sails past the guard. See
// docs/sessions/2026-06-04/TEST-ACCOUNTS-AND-NR-SYNTHETICS-PLAN.md §1.6.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// errCodeSyntheticTestCohort mirrors the unexported handler constant — the
// stable wire code the synthetic runner asserts on.
const errCodeSyntheticTestCohort = "synthetic_test_cohort"

func cohortNeedsDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("billing_test_cohort_test: TEST_DATABASE_URL not set — skipping integration test")
	}
	return testhelpers.SetupTestDB(t)
}

// cohortBillingApp wires both charge-initiation endpoints with a fake-auth
// middleware that injects only team_id (no user_id, so the email-verify gate
// fails OPEN — isolating the cohort guard as the only blocker under test).
// Razorpay creds are intentionally empty so a normal team that passes the
// guard halts at billing_not_configured (503) without any network call.
func cohortBillingApp(t *testing.T, db *sql.DB, teamID string) *fiber.App {
	t.Helper()
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret} // no Razorpay creds
	bh := handlers.NewBillingHandler(db, cfg, email.NewNoop())
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
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
		if teamID != "" {
			c.Locals(middleware.LocalKeyTeamID, teamID)
		}
		return c.Next()
	})
	app.Post("/api/v1/billing/checkout", bh.CreateCheckoutAPI)
	app.Post("/api/v1/billing/change-plan", bh.ChangePlanAPI)
	return app
}

func cohortPost(t *testing.T, app *fiber.App, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// TestCheckout_TestCohortGuard_FailsOpenOnDBError: a DB blip on the cohort
// lookup must NOT block a real customer's checkout. The guard fails open
// (treats the lookup error as "not a test cohort") and execution proceeds
// past it — so the response is anything OTHER than synthetic_test_cohort.
// Uses sqlmock so the error branch is deterministic and DB-independent.
func TestCheckout_TestCohortGuard_FailsOpenOnDBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	teamID := uuid.NewString()
	mock.ExpectQuery("SELECT is_test_cohort FROM teams WHERE id").
		WillReturnError(errors.New("db blip"))

	app := cohortBillingApp(t, db, teamID) // no Razorpay creds → halts at not_configured
	status, body := cohortPost(t, app, "/api/v1/billing/checkout", `{"plan":"pro"}`)

	assert.NotEqual(t, errCodeSyntheticTestCohort, body["error"],
		"a DB error on the cohort lookup must fail OPEN, not block the customer")
	assert.NotEqual(t, http.StatusForbidden, status)
}

// TestCheckout_TestCohortTeam_Rejected: a synthetic team is 403'd with the
// distinct code on the checkout path before any Razorpay call.
func TestCheckout_TestCohortTeam_Rejected(t *testing.T) {
	db, cleanup := cohortNeedsDB(t)
	defer cleanup()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	require.NoError(t, models.SetTestCohort(context.Background(), db, uuid.MustParse(teamID), true))

	app := cohortBillingApp(t, db, teamID)
	status, body := cohortPost(t, app, "/api/v1/billing/checkout", `{"plan":"pro"}`)

	assert.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, errCodeSyntheticTestCohort, body["error"])
}

// TestChangePlan_TestCohortTeam_Rejected: same guard on the change-plan path.
func TestChangePlan_TestCohortTeam_Rejected(t *testing.T) {
	db, cleanup := cohortNeedsDB(t)
	defer cleanup()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	require.NoError(t, models.SetTestCohort(context.Background(), db, uuid.MustParse(teamID), true))

	app := cohortBillingApp(t, db, teamID)
	status, body := cohortPost(t, app, "/api/v1/billing/change-plan", `{"target_plan":"pro"}`)

	assert.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, errCodeSyntheticTestCohort, body["error"])
}

// TestCheckout_NormalTeam_NotSkipped: a normal (default is_test_cohort=false)
// team is NOT caught by the guard — it passes through and halts later
// (billing_not_configured, since Razorpay creds are empty). The assertion is
// that the response is anything OTHER than synthetic_test_cohort, proving the
// guard is cohort-specific and inert for real teams.
func TestCheckout_NormalTeam_NotSkipped(t *testing.T) {
	db, cleanup := cohortNeedsDB(t)
	defer cleanup()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby") // is_test_cohort defaults false

	app := cohortBillingApp(t, db, teamID)
	status, body := cohortPost(t, app, "/api/v1/billing/checkout", `{"plan":"pro"}`)

	assert.NotEqual(t, errCodeSyntheticTestCohort, body["error"],
		"a normal team must NOT be rejected by the synthetic-cohort guard")
	assert.NotEqual(t, http.StatusForbidden, status,
		"a normal team must pass the guard (halts later at billing_not_configured)")
}

// TestChangePlan_NormalTeam_NotSkipped: change-plan twin of the above.
func TestChangePlan_NormalTeam_NotSkipped(t *testing.T) {
	db, cleanup := cohortNeedsDB(t)
	defer cleanup()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")

	app := cohortBillingApp(t, db, teamID)
	status, body := cohortPost(t, app, "/api/v1/billing/change-plan", `{"target_plan":"pro"}`)

	assert.NotEqual(t, errCodeSyntheticTestCohort, body["error"],
		"a normal team must NOT be rejected by the synthetic-cohort guard")
	_ = status
}
