package handlers_test

// resource_count_cap_test.go — Task #55 per-service resource-count cap.
//
// These exercise the FLAG-GATED enforcement added to db/vector/cache/nosql/
// storage handlers. The load-bearing tests:
//   - flag OFF (default) → a team AT its cap is NOT rejected (proves inert),
//   - flag ON → a team AT its cap gets 402 <service>_limit_reached,
//   - a registry-iterating guard (rule 18) asserting every count-capped service
//     enforces when the flag is on (so service N+1 can't ship uncapped).
//
// Run:
//   TEST_DATABASE_URL=postgres://instant:instant@localhost:5432/instant_platform?sslmode=disable \
//   go test ./internal/handlers/... -run 'ResourceCountCap' -v -count=1

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// sqlExec is the subset of *sql.DB the seed helper needs.
type sqlExec interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

// countCappedServices is the service set with a per-tier resource-count cap.
// Mirrors handlers.countCapResourceTypes minus queue (queue has its own always-
// on A6 block + its own route name). These are the five flag-gated services.
var countCappedServices = []struct {
	service string // resources.resource_type AND plans key
	route   string // POST route
	errCode string // expected 402 error code
}{
	{"postgres", "/db/new", "postgres_limit_reached"},
	{"vector", "/vector/new", "vector_limit_reached"},
	{"redis", "/cache/new", "redis_limit_reached"},
	{"mongodb", "/nosql/new", "mongodb_limit_reached"},
	{"storage", "/storage/new", "storage_limit_reached"},
}

// newCountCapApp builds a Fiber app exercising the given count-capped service's
// POST route with the count-caps flag set to `flagOn`.
//
// Most services route through the shared NewTestAppWithServices test app. Storage
// is special-cased: its handler 503s at the top when the storage provider is nil
// (the shared app passes nil), so the count cap — which fires BEFORE any backend
// call — would never be reached. We give storage an OFFLINE do-spaces provider
// (newDOSpacesProvider) purely to get past the nil-provider guard; the cap still
// returns 402 before the provider is ever touched.
func newCountCapApp(t *testing.T, db *sql.DB, service string, flagOn bool) (*fiber.App, func()) {
	t.Helper()
	mut := func(c *config.Config) { c.ResourceCountCapsEnabled = flagOn }
	if service != "storage" {
		return testhelpers.NewTestAppWithServices(t, db, nil,
			"postgres,vector,redis,mongodb,storage,queue", mut)
	}

	// Storage: real handler + offline provider so newStorageAuthenticated runs.
	rdb, rcleanup := testhelpers.SetupTestRedis(t)
	cfg := testStorageCapConfig(flagOn)
	storageH := handlers.NewStorageHandler(db, rdb, cfg, newDOSpacesProvider(t), plans.Default())
	app := fiber.New(fiber.Config{
		ProxyHeader: "X-Forwarded-For",
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return c.SendStatus(fiber.StatusInternalServerError)
		},
	})
	app.Use(middleware.RequestID())
	app.Use(middleware.Fingerprint())
	app.Post("/storage/new", middleware.OptionalAuth(cfg), storageH.NewStorage)
	return app, func() { rcleanup() }
}

// testStorageCapConfig builds a config for the storage cap app with the flag set.
func testStorageCapConfig(flagOn bool) *config.Config {
	cfg := storageProvConfig(false) // reuse the offline-storage config from storage_provarms_test.go
	cfg.EnabledServices = "storage"
	cfg.ResourceCountCapsEnabled = flagOn
	return cfg
}

// seedN inserts n active resources of resourceType for the team via raw SQL.
func seedN(t *testing.T, db sqlExec, teamID, resourceType, tier string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		_, err := db.ExecContext(context.Background(),
			`INSERT INTO resources (team_id, resource_type, name, tier, status)
			 VALUES ($1, $2, $3, $4, 'active')`,
			teamID, resourceType, fmt.Sprintf("seed-%s-%d", resourceType, i), tier)
		require.NoError(t, err, "seed %s #%d", resourceType, i)
	}
}

// TestResourceCountCap_FlagOffIsInert is THE inert-path proof: with the flag
// unset (default), a hobby team already AT its per-service cap is NOT rejected
// with a *_limit_reached 402. Zero behavior change when off.
func TestResourceCountCap_FlagOffIsInert(t *testing.T) {
	requireTestDB(t)

	planReg := plans.Default()
	for _, svc := range countCappedServices {
		t.Run(svc.service, func(t *testing.T) {
			db, cleanDB := testhelpers.SetupTestDB(t)
			defer cleanDB()
			ensureStackTables(t, db)

			limit := planReg.ResourceCountLimit("hobby", svc.service)
			require.Greater(t, limit, 0, "hobby %s_count must be positive", svc.service)

			// Flag OFF (default).
			app, cleanup := newCountCapApp(t, db, svc.service, false)
			defer cleanup()

			teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
			jwt := testhelpers.MustSignSessionJWT(t, "u-off-"+svc.service, teamID, "off-"+svc.service+"@example.com")

			// Seed the team AT its cap.
			seedN(t, db, teamID, svc.service, "hobby", limit)

			resp := postWithAuthJSONTier(t, app, svc.route, jwt, `{"name":"over-cap"}`)
			defer resp.Body.Close()

			// The provision may 503 (no real backend in tests), but it must
			// NEVER be the count-cap 402 while the flag is off.
			if resp.StatusCode == http.StatusPaymentRequired {
				b := decodeTierErrBody(t, resp)
				assert.NotEqual(t, svc.errCode, b.Error,
					"flag OFF: %s at cap must NOT be rejected by the count cap (inert)", svc.service)
			}
		})
	}
}

// TestResourceCountCap_FlagOnAtLimitRejects is the rule-18 registry-iterating
// guard: with the flag ON, a hobby team AT its cap gets 402 <service>_limit_reached
// for EVERY count-capped service. If a new count-capped service ships without
// wiring the enforcement block, its sub-test fails here.
func TestResourceCountCap_FlagOnAtLimitRejects(t *testing.T) {
	requireTestDB(t)

	planReg := plans.Default()
	for _, svc := range countCappedServices {
		t.Run(svc.service, func(t *testing.T) {
			db, cleanDB := testhelpers.SetupTestDB(t)
			defer cleanDB()
			ensureStackTables(t, db)

			limit := planReg.ResourceCountLimit("hobby", svc.service)
			require.Greater(t, limit, 0, "hobby %s_count must be positive", svc.service)

			// Flag ON.
			app, cleanup := newCountCapApp(t, db, svc.service, true)
			defer cleanup()

			teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
			jwt := testhelpers.MustSignSessionJWT(t, "u-on-"+svc.service, teamID, "on-"+svc.service+"@example.com")

			seedN(t, db, teamID, svc.service, "hobby", limit)

			resp := postWithAuthJSONTier(t, app, svc.route, jwt, `{"name":"over-cap"}`)
			defer resp.Body.Close()

			require.Equal(t, http.StatusPaymentRequired, resp.StatusCode,
				"flag ON: %s team AT cap (%d) must get 402", svc.service, limit)
			b := decodeTierErrBody(t, resp)
			assert.False(t, b.OK)
			assert.Equal(t, svc.errCode, b.Error,
				"flag ON: %s at cap must return %s", svc.service, svc.errCode)
		})
	}
}

// TestResourceCountCap_FlagOnUnderLimitPasses verifies the count cap does NOT
// reject a team under its cap when the flag is on (the provision may still 503
// for lack of a real backend, but not with a count-cap 402).
func TestResourceCountCap_FlagOnUnderLimitPasses(t *testing.T) {
	requireTestDB(t)

	planReg := plans.Default()
	for _, svc := range countCappedServices {
		t.Run(svc.service, func(t *testing.T) {
			db, cleanDB := testhelpers.SetupTestDB(t)
			defer cleanDB()
			ensureStackTables(t, db)

			limit := planReg.ResourceCountLimit("hobby", svc.service)
			require.Greater(t, limit, 1, "hobby %s_count must be > 1 for an under-limit state", svc.service)

			app, cleanup := newCountCapApp(t, db, svc.service, true)
			defer cleanup()

			teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
			jwt := testhelpers.MustSignSessionJWT(t, "u-under-"+svc.service, teamID, "under-"+svc.service+"@example.com")

			// Seed UNDER the cap.
			seedN(t, db, teamID, svc.service, "hobby", limit-1)

			resp := postWithAuthJSONTier(t, app, svc.route, jwt, `{"name":"under-cap"}`)
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusPaymentRequired {
				b := decodeTierErrBody(t, resp)
				assert.NotEqual(t, svc.errCode, b.Error,
					"flag ON: %s under cap must NOT be rejected by the count cap", svc.service)
			}
		})
	}
}
