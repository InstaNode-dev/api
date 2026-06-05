package handlers_test

// approve_block_routes_test.go — W4 deploy-approval block integration suite.
//
// Covers the public email-link approval landing from
// USER-FLOW-INVENTORY-AND-TEST-MATRIX.md §W4: GET /approve/:token. This route
// was, in internal/router/route_donebar_guard_test.go, listed in
// routeCoverageExemptions ("approval-link landing — no integration test yet.
// TODO: matrix W4 deploy-approval flow.") with NO mapped test. This suite
// supplies the DB-backed integration coverage the done-bar guard's routeTestMap
// now points at, so the route moves exempt → mapped.
//
// THE REAL CONTRACT (read from internal/handlers/promote_approval.go Approve):
// the route is PUBLIC — the 32-byte random token IS the credential, so there is
// no Bearer/session (it must work for an anonymous click in an email client).
// The handler renders HTML (or redirects) across four token branches:
//
//	1. token doesn't exist          → 404 "this link is invalid" HTML
//	2. token exists but past expiry → flips row to 'expired', 410 "expired" HTML
//	3. token exists, status≠pending → 410 "already used" HTML
//	4. token valid + pending        → atomic approve, 302 → dashboard ?approved=1
//
// plus a per-IP rate limit (promoteApprovalRateLimitPerSec/sec) that renders a
// 429 "slow down" HTML page. All non-success branches render the SAME shape of
// page (no branch is distinguishable to a probing attacker beyond the 302 vs
// 4xx the genuine user must see).
//
// Each test runs against a real migrated Postgres (testhelpers.SetupTestDB)
// through the PRODUCTION route wiring (approveBlockApp mirrors router.go's
// app.Get("/approve/:token", NewPromoteApprovalHandler(db, rdb).Approve)),
// asserting:
//   - happy path: 302 + Location → dashboard/<id>?approved=1 AND the row is
//     PERSISTED as 'approved' in Postgres (source-of-truth state change),
//   - single-use: a second click on an approved token → 410 "already used",
//   - expired token: 410 + the row is flipped to 'expired' in Postgres,
//   - invalid token: 404 (existence of a real token is unobservable),
//   - rate limit: the (N+1)th click within one IP-second → 429.
//
// Skips loudly when TEST_DATABASE_URL is unset (approveBlockSkipNoDB).

import (
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/models"
)

// approveRateLimitBudget mirrors the unexported promoteApprovalRateLimitPerSec
// in promote_approval.go (per-IP requests per second, currently 10). This
// black-box (package handlers_test) suite can't reach the unexported constant,
// so it tracks the value here; if the prod budget changes, this burst count
// just needs to stay above it for the limiter to trip — the assertion below
// only requires that SOME request in the burst is rate-limited.
const approveRateLimitBudget = 10

// readApproveBody drains + closes the response body and returns it as a string.
func readApproveBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(b)
}

// ─────────────────────────────────────────────────────────────────────────
// GET /approve/:token — PromoteApprovalHandler.Approve  (happy path)
// ─────────────────────────────────────────────────────────────────────────

func TestApproveBlock_ValidPendingToken(t *testing.T) {
	approveBlockSkipNoDB(t)
	db, cleanup := approveBlockDB(t)
	defer cleanup()

	t.Run("valid pending token → 302 + dashboard redirect + row persisted as approved", func(t *testing.T) {
		teamID := approveBlockSeedTeam(t, db)
		row := approveBlockSeedApproval(t, db, teamID, models.PromoteApprovalStatusPending, time.Hour)
		app := approveBlockApp(t, db, miniRedis(t))

		resp := approveBlockGet(t, app, row.Token, "203.0.113.10")
		body := readApproveBody(t, resp)
		require.Equal(t, http.StatusFound, resp.StatusCode, "body=%s", body)

		// Redirect lands on the dashboard's per-approval detail with ?approved=1
		// (the toast trigger) — the canonical post-approval destination.
		loc := resp.Header.Get("Location")
		assert.Equal(t, handlers.PromoteApprovalDashboardURL+"/"+row.ID.String()+"?approved=1", loc,
			"302 Location must point at the dashboard approval detail with the approved toast flag")

		// Source-of-truth state change: the row is PERSISTED as 'approved'.
		assert.Equal(t, models.PromoteApprovalStatusApproved, approveBlockStatusOf(t, db, row.ID),
			"a valid click must atomically flip the row from pending → approved in Postgres")
	})

	t.Run("single-use: a second click on the now-approved token → 410 already-used", func(t *testing.T) {
		teamID := approveBlockSeedTeam(t, db)
		row := approveBlockSeedApproval(t, db, teamID, models.PromoteApprovalStatusPending, time.Hour)
		app := approveBlockApp(t, db, miniRedis(t))

		// First click approves.
		first := approveBlockGet(t, app, row.Token, "203.0.113.11")
		_ = readApproveBody(t, first)
		require.Equal(t, http.StatusFound, first.StatusCode)

		// Second click: the row is no longer pending → 410 "already used".
		second := approveBlockGet(t, app, row.Token, "203.0.113.11")
		body := readApproveBody(t, second)
		assert.Equal(t, http.StatusGone, second.StatusCode, "single-use token must not approve twice")
		assert.Contains(t, body, "already been used",
			"a second click renders the 'already used' page, never a second 302")
		// State is unchanged — still approved, not re-flipped.
		assert.Equal(t, models.PromoteApprovalStatusApproved, approveBlockStatusOf(t, db, row.ID))
	})
}

// ─────────────────────────────────────────────────────────────────────────
// GET /approve/:token — already-used / rejected / executed tokens
// ─────────────────────────────────────────────────────────────────────────

func TestApproveBlock_NonPendingToken(t *testing.T) {
	approveBlockSkipNoDB(t)
	db, cleanup := approveBlockDB(t)
	defer cleanup()

	// Every already-resolved status renders the same "already used" page and
	// must NOT re-approve. Drives branch 3 of the handler.
	for _, status := range []string{
		models.PromoteApprovalStatusApproved,
		models.PromoteApprovalStatusRejected,
		models.PromoteApprovalStatusExecuted,
	} {
		status := status
		t.Run(status+" token → 410 already-used, no state change", func(t *testing.T) {
			teamID := approveBlockSeedTeam(t, db)
			row := approveBlockSeedApproval(t, db, teamID, status, time.Hour)
			app := approveBlockApp(t, db, miniRedis(t))

			resp := approveBlockGet(t, app, row.Token, "203.0.113.20")
			body := readApproveBody(t, resp)
			assert.Equal(t, http.StatusGone, resp.StatusCode)
			assert.Contains(t, body, "already been used")
			assert.Equal(t, status, approveBlockStatusOf(t, db, row.ID),
				"clicking a %s token must not change its status", status)
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────
// GET /approve/:token — expired token (branch 2: flips row to 'expired')
// ─────────────────────────────────────────────────────────────────────────

func TestApproveBlock_ExpiredToken(t *testing.T) {
	approveBlockSkipNoDB(t)
	db, cleanup := approveBlockDB(t)
	defer cleanup()

	t.Run("pending-but-past-expiry token → 410 expired + row flipped to 'expired'", func(t *testing.T) {
		teamID := approveBlockSeedTeam(t, db)
		// Negative TTL forces an already-expired (but still 'pending') row.
		row := approveBlockSeedApproval(t, db, teamID, models.PromoteApprovalStatusPending, -time.Hour)
		app := approveBlockApp(t, db, miniRedis(t))

		resp := approveBlockGet(t, app, row.Token, "203.0.113.30")
		body := readApproveBody(t, resp)
		require.Equal(t, http.StatusGone, resp.StatusCode, "body=%s", body)
		assert.Contains(t, body, "expired", "expired token renders the 'expired' page")

		// The handler flips the row to 'expired' as a side effect (best-effort,
		// but against a healthy DB it must land).
		assert.Equal(t, models.PromoteApprovalStatusExpired, approveBlockStatusOf(t, db, row.ID),
			"a click on a past-expiry pending row flips its status to 'expired'")
	})
}

// ─────────────────────────────────────────────────────────────────────────
// GET /approve/:token — invalid token (branch 1: never-issued / typo'd)
// ─────────────────────────────────────────────────────────────────────────

func TestApproveBlock_InvalidToken(t *testing.T) {
	approveBlockSkipNoDB(t)
	db, cleanup := approveBlockDB(t)
	defer cleanup()

	t.Run("unknown token → 404 invalid (existence of a real token unobservable)", func(t *testing.T) {
		app := approveBlockApp(t, db, miniRedis(t))
		// A well-formed-but-never-issued token.
		bogus := "this-token-was-never-issued-" + uuid.NewString()

		resp := approveBlockGet(t, app, bogus, "203.0.113.40")
		body := readApproveBody(t, resp)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		assert.Contains(t, body, "invalid",
			"an unknown token renders the same 'invalid' page a typo'd link would — no oracle for probing")
	})
}

// ─────────────────────────────────────────────────────────────────────────
// GET /approve/:token — per-IP rate limit (defends the token space)
// ─────────────────────────────────────────────────────────────────────────

func TestApproveBlock_RateLimit(t *testing.T) {
	approveBlockSkipNoDB(t)
	db, cleanup := approveBlockDB(t)
	defer cleanup()

	t.Run("exceeding the per-IP/sec budget → 429 slow-down page", func(t *testing.T) {
		app := approveBlockApp(t, db, miniRedis(t))
		const ip = "198.51.100.7"
		// The budget is approveRateLimitBudget requests per IP-second. Hammer
		// well past it with a bogus token (we only care about the limiter, which
		// runs BEFORE the token lookup). At least one request in the burst must
		// trip the limit and render the 429 page.
		got429 := false
		var lastBody string
		for i := 0; i < approveRateLimitBudget+5; i++ {
			resp := approveBlockGet(t, app, "rl-probe-token", ip)
			lastBody = readApproveBody(t, resp)
			if resp.StatusCode == http.StatusTooManyRequests {
				got429 = true
				assert.Contains(t, lastBody, "Too many requests",
					"the 429 renders the rate-limit page")
				break
			}
		}
		require.True(t, got429,
			"a burst beyond the per-IP/sec budget must yield a 429; last body=%s", lastBody)
	})
}
