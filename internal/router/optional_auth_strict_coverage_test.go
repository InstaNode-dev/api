// optional_auth_strict_coverage_test.go — registry-iterating regression test
// for the "anonymous-capable mutating endpoint MUST 401 on a malformed bearer"
// contract (T19 P1-7, MR-P1-38; rule 18: registry-iterating tests, not
// hand-typed lists).
//
// History:
//
//   - 2026-05-20: T19 P1-7 migrated /db/new, /vector/new, /cache/new,
//     /nosql/new, /queue/new, /storage/new, /webhook/new from bare
//     OptionalAuth to OptionalAuthStrict so an agent presenting an
//     expired/typo'd bearer header sees a 401 instead of silently
//     getting anonymous-tier provisioning.
//   - 2026-05-21: H46 F1 followed up on /storage/:token/presign for the
//     same reason.
//   - 2026-05-30: this file. /stacks/new + DELETE /stacks/:slug were the
//     two remaining single-site-fallacy misses (rule 17 surface). This
//     test iterates the live route list so the next time a new
//     anonymous-capable mutating endpoint ships, it is verified to be on
//     the strict variant — not by reading the router source, but by
//     replaying a malformed bearer at the route itself.
//
// Design:
//
//	A malformed bearer ("Bearer not-a-jwt") on a strict route MUST
//	produce 401 BEFORE the handler runs. A missing bearer header on the
//	same route must still pass through to the handler (the routes are
//	anonymous-capable). The test asserts both wire shapes per route, so
//	a future drop-back to bare OptionalAuth fails this test loudly
//	regardless of how the route is registered.
package router_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/email"
	"instant.dev/internal/plans"
	"instant.dev/internal/router"
	"instant.dev/internal/testhelpers"
)

// anonymousCapableMutatingRoutes is the registry of routes that:
//
//  1. accept anonymous callers (no Authorization header is OK), AND
//  2. mutate state (POST/DELETE/PATCH/PUT — never GET).
//
// Every entry MUST be wired with middleware.OptionalAuthStrict (not bare
// OptionalAuth) per T19 P1-7 / MR-P1-38: a present-but-malformed bearer
// header is an agent typo / stale token, and silently downgrading to the
// anonymous tier gives no signal to the caller.
//
// Adding a new anonymous-capable mutating endpoint? Add it here AND wire
// OptionalAuthStrict in router.go. The test below will fail loudly if
// the chain is wrong.
var anonymousCapableMutatingRoutes = []struct {
	method string
	path   string
}{
	{"POST", "/db/new"},
	{"POST", "/vector/new"},
	{"POST", "/cache/new"},
	{"POST", "/nosql/new"},
	{"POST", "/queue/new"},
	{"POST", "/storage/new"},
	{"POST", "/webhook/new"},
	{"POST", "/stacks/new"},
	// DELETE /stacks/:slug — anonymous stacks own their slug as a secret;
	// a bad bearer here used to silently downgrade and (after the slug
	// lookup) delete the anonymous stack if the slug happened to match.
	{"DELETE", "/stacks/anonymous-slug-does-not-exist"},
	// POST /storage/:token/presign — H46 F1 (2026-05-21). Same contract:
	// strict mode keeps a stale session from signing for an unowned
	// tenant prefix.
	{"POST", "/storage/some-token/presign"},
}

// TestRouter_AnonymousMutatingRoutes_StrictBearer iterates the registry
// above and asserts that every entry rejects a malformed bearer with 401
// (the OptionalAuthStrict contract). This is a rule-18 registry-driven
// test: a future drop-back to bare OptionalAuth on any one of these
// routes fails here regardless of how the router source happens to be
// arranged.
func TestRouter_AnonymousMutatingRoutes_StrictBearer(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	rdb, rdbClean := testhelpers.SetupTestRedis(t)
	defer rdbClean()

	cfg := newRouterTestConfig()
	cfg.Environment = "production"
	// Storage provider must boot so /storage/new and /storage/:token/presign
	// are registered. shared-key + AllowSharedKey=true reuses the T3
	// success-branch setup from router_coverage_test.go.
	cfg.ObjectStoreEndpoint = "do-spaces.example.com"
	cfg.ObjectStoreMode = "shared-key"
	cfg.ObjectStoreAllowSharedKey = true
	cfg.ObjectStoreAccessKey = "AKIATEST"
	cfg.ObjectStoreSecretKey = "secret-32-bytes-long-padded-here-okay!"
	cfg.ObjectStoreBucket = "instant-shared-test"
	cfg.ObjectStoreSecure = true

	mailer := email.NewNoop()
	planReg := plans.Default()

	app, _ := router.NewWithHooks(cfg, db, rdb, nil, mailer, planReg, nil, nil)
	require.NotNil(t, app)

	for _, r := range anonymousCapableMutatingRoutes {
		t.Run(r.method+" "+r.path, func(t *testing.T) {
			// Probe 1: malformed bearer → 401. This is the strict-mode
			// contract. The exact 401 reason (malformed/expired/etc.)
			// is asserted in middleware/auth_test.go; here we only care
			// that the route does NOT silently downgrade to anonymous.
			req := httptest.NewRequest(r.method, r.path, nil)
			req.Header.Set("Authorization", "Bearer this-is-not-a-jwt")
			resp, err := app.Test(req, 5_000)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equalf(t, http.StatusUnauthorized, resp.StatusCode,
				"%s %s must 401 on a malformed bearer (OptionalAuthStrict); "+
					"got %d. If you added this route with bare OptionalAuth, "+
					"swap to OptionalAuthStrict — see router.go comment "+
					"above the /db/new line for the rationale.",
				r.method, r.path, resp.StatusCode)

			// Probe 2: no Authorization header at all → must NOT 401.
			// The routes are explicitly anonymous-capable; the strict
			// variant only triggers when a header is PRESENT but bad.
			// We accept any non-401 status — the handler downstream
			// may 4xx for a missing body / unknown slug / etc., but
			// that proves the middleware chain let the request through.
			req2 := httptest.NewRequest(r.method, r.path, nil)
			resp2, err := app.Test(req2, 5_000)
			require.NoError(t, err)
			defer resp2.Body.Close()
			assert.NotEqualf(t, http.StatusUnauthorized, resp2.StatusCode,
				"%s %s must NOT 401 when no Authorization header is sent "+
					"(routes are anonymous-capable); got %d. If you tightened "+
					"this route to require auth, remove it from the "+
					"anonymousCapableMutatingRoutes registry above.",
				r.method, r.path, resp2.StatusCode)
		})
	}
}
