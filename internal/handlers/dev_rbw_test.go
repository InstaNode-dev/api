package handlers_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/testhelpers"
)

// devApp mounts NewSetTierHandler on a throwaway fiber app whose ErrorHandler
// recognises the ErrResponseWritten sentinel respondError returns — without
// it, the returned sentinel would be coerced to a generic 500, masking the
// real 4xx/503 status the handler set.
func devApp(h fiber.Handler) *fiber.App {
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return fiber.DefaultErrorHandler(c, err)
		},
	})
	app.Post("/internal/set-tier", h)
	return app
}

func postSetTier(t *testing.T, app *fiber.App, raw string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("POST", "/internal/set-tier", strings.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	return resp.StatusCode, m
}

// TestSetTier_InvalidBody covers the BodyParser error arm.
func TestSetTier_InvalidBody(t *testing.T) {
	app := devApp(handlers.NewSetTierHandler(nil))
	code, m := postSetTier(t, app, `{not json`)
	require.Equal(t, fiber.StatusBadRequest, code)
	require.Equal(t, "invalid_body", m["error"])
}

// TestSetTier_MissingTeamID covers the empty team_id guard.
func TestSetTier_MissingTeamID(t *testing.T) {
	app := devApp(handlers.NewSetTierHandler(nil))
	code, m := postSetTier(t, app, `{"tier":"pro"}`)
	require.Equal(t, fiber.StatusBadRequest, code)
	require.Equal(t, "missing_team_id", m["error"])
}

// TestSetTier_InvalidTier covers the non-upgrade-tier rejection (downgrade,
// junk, and hobby are all rejected here — downgrade is Razorpay's job).
func TestSetTier_InvalidTier(t *testing.T) {
	app := devApp(handlers.NewSetTierHandler(nil))
	for _, tier := range []string{"hobby", "anonymous", "bogus", ""} {
		code, m := postSetTier(t, app, `{"team_id":"00000000-0000-0000-0000-000000000001","tier":"`+tier+`"}`)
		require.Equal(t, fiber.StatusBadRequest, code, "tier=%q", tier)
		require.Equal(t, "invalid_tier", m["error"], "tier=%q", tier)
	}
}

// TestSetTier_InvalidUUID covers the uuid.Parse failure arm.
func TestSetTier_InvalidUUID(t *testing.T) {
	app := devApp(handlers.NewSetTierHandler(nil))
	code, m := postSetTier(t, app, `{"team_id":"not-a-uuid","tier":"pro"}`)
	require.Equal(t, fiber.StatusBadRequest, code)
	require.Equal(t, "invalid_team_id", m["error"])
}

// TestSetTier_UpgradeFailed covers the UpgradeTeamAllTiers error arm: a valid
// UUID for a team that does not exist still parses, but the upgrade against a
// closed DB connection fails → 503 upgrade_failed.
func TestSetTier_UpgradeFailed(t *testing.T) {
	db, cleanup := testhelpers.SetupTestDB(t)
	cleanup() // close the pool so every query errors
	app := devApp(handlers.NewSetTierHandler(db))
	code, m := postSetTier(t, app, `{"team_id":"00000000-0000-0000-0000-000000000009","tier":"pro"}`)
	require.Equal(t, fiber.StatusServiceUnavailable, code)
	require.Equal(t, "upgrade_failed", m["error"])
}

// TestSetTier_Success covers the happy path: a real team is upgraded and the
// handler returns ok + the echoed team_id/tier.
func TestSetTier_Success(t *testing.T) {
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")

	app := devApp(handlers.NewSetTierHandler(db))
	code, m := postSetTier(t, app, `{"team_id":"`+teamID+`","tier":"pro"}`)
	require.Equal(t, fiber.StatusOK, code)
	require.Equal(t, true, m["ok"])
	require.Equal(t, teamID, m["team_id"])
	require.Equal(t, "pro", m["tier"])
}
