package handlers

// resource_count_cap_whitebox_test.go — in-package (white-box) branch coverage
// for enforceResourceCountCap's edge paths that the HTTP-level
// resource_count_cap_test.go can't reach (the cap helper is unexported and some
// branches are only reachable with a synthetic registry / closed DB):
//   - flag OFF / nil cfg → inert,
//   - limit < 0 (unlimited) → inert,
//   - count-query error → 503 quota_check_failed (fail-closed when enabled).
//
// The happy "at cap → 402" and "under cap → pass" paths are covered end-to-end
// via the HTTP tests; here we exercise only the defensive/edge arms.

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"

	"instant.dev/internal/config"
	"instant.dev/internal/plans"
)

// ctxForCap returns a fiber.Ctx bound to a throwaway app for direct handler
// calls. UserContext is set to context.Background() so database/sql doesn't call
// (*fasthttp.RequestCtx).Done() (which panics on a bare RequestCtx).
func ctxForCap(t *testing.T) (*fiber.Ctx, func()) {
	t.Helper()
	app := fiber.New()
	c := app.AcquireCtx(&fasthttp.RequestCtx{})
	c.SetUserContext(context.Background())
	return c, func() { app.ReleaseCtx(c) }
}

func TestEnforceResourceCountCap_FlagOffInert_Whitebox(t *testing.T) {
	c, done := ctxForCap(t)
	defer done()

	h := &provisionHelper{
		cfg:   &config.Config{ResourceCountCapsEnabled: false},
		plans: plans.Default(),
	}
	handled, err := h.enforceResourceCountCap(c, uuid.New(), "hobby", "postgres", "rq")
	assert.False(t, handled, "flag OFF must be inert")
	assert.NoError(t, err)

	// nil cfg → also inert (defensive).
	h2 := &provisionHelper{cfg: nil, plans: plans.Default()}
	handled2, err2 := h2.enforceResourceCountCap(c, uuid.New(), "hobby", "postgres", "rq")
	assert.False(t, handled2)
	assert.NoError(t, err2)

	// nil plans → inert (defensive).
	h3 := &provisionHelper{cfg: &config.Config{ResourceCountCapsEnabled: true}, plans: nil}
	handled3, err3 := h3.enforceResourceCountCap(c, uuid.New(), "hobby", "postgres", "rq")
	assert.False(t, handled3)
	assert.NoError(t, err3)
}

func TestEnforceResourceCountCap_UnlimitedIsInert_Whitebox(t *testing.T) {
	c, done := ctxForCap(t)
	defer done()

	// Build a registry whose hobby postgres_count is -1 (unlimited) so the
	// limit<0 branch is reached. ResourceCountLimit returns the field verbatim
	// when negative.
	const unlimitedYAML = `
plans:
  anonymous:
    display_name: "Anonymous"
    price_monthly_cents: 0
    limits:
      provisions_per_day: 5
  hobby:
    display_name: "Hobby"
    price_monthly_cents: 900
    limits:
      provisions_per_day: -1
      postgres_count: -1
`
	dir := t.TempDir()
	path := filepath.Join(dir, "unlimited.yaml")
	require.NoError(t, os.WriteFile(path, []byte(unlimitedYAML), 0o600))
	reg, err := plans.Load(path)
	require.NoError(t, err)

	h := &provisionHelper{
		cfg:   &config.Config{ResourceCountCapsEnabled: true},
		plans: reg,
		db:    nil, // never reached — unlimited returns before the DB query
	}
	handled, capErr := h.enforceResourceCountCap(c, uuid.New(), "hobby", "postgres", "rq")
	assert.False(t, handled, "unlimited (-1) cap must be inert and NOT query the DB")
	assert.NoError(t, capErr)
}

func TestEnforceResourceCountCap_CountErrorFailsClosed_Whitebox(t *testing.T) {
	c, done := ctxForCap(t)
	defer done()

	// A closed *sql.DB makes CountActiveResourcesByTeamAndType error → the
	// helper fails CLOSED with handled=true (the caller returns the 503).
	closed, err := sql.Open("postgres", "postgres://invalid:invalid@127.0.0.1:1/none?sslmode=disable")
	require.NoError(t, err)
	require.NoError(t, closed.Close())

	h := &provisionHelper{
		cfg:   &config.Config{ResourceCountCapsEnabled: true},
		plans: plans.Default(),
		db:    closed,
	}
	handled, capErr := h.enforceResourceCountCap(c, uuid.New(), "hobby", "postgres", "rq")
	assert.True(t, handled, "a count-query error with the flag on must be handled (fail closed)")
	assert.ErrorIs(t, capErr, ErrResponseWritten, "respondError returns the written sentinel")
	assert.Equal(t, fiber.StatusServiceUnavailable, c.Response().StatusCode())
}
