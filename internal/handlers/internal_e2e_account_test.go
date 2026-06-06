package handlers_test

// internal_e2e_account_test.go — coverage for the CI-only guarded
// ephemeral-test-account surface:
//
//   POST   /internal/e2e/account
//   DELETE /internal/e2e/account/:team_id
//
// Test matrix (mirrors the brief — the guard + cohort-scoping is the
// security-sensitive part):
//   - token unset            → 404 (inert by default)
//   - wrong token            → 404 (existence-hiding, constant-time compare)
//   - valid token create     → 200, is_test_cohort team, JWT authenticates
//   - tier="team"            → 400 (Team gated)
//   - tier="growth"          → 400 (gated)
//   - reap test-cohort team  → purged (team gone, resources marked for reaper)
//   - reap NON-cohort team   → 403 not_test_cohort  ← THE CRITICAL SAFETY TEST
//   - reap already-gone team → 200 idempotent
//   - per-token rate limit   → 429 once the window cap is exceeded

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/testhelpers"
)

const testE2EToken = "e2e-account-token-at-least-32-bytes!!"

func skipUnlessE2EDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("e2e account tests: TEST_DATABASE_URL not set")
	}
}

// newE2ETestApp wires only the e2e mint/reap handlers (+ a tiny RequireAuth
// probe route used to prove a minted JWT authenticates). token is the
// configured E2E_ACCOUNT_TOKEN; pass "" to exercise the inert-by-default path.
// rdb may be nil (rate limit fails open).
func newE2ETestApp(t *testing.T, db *sql.DB, rdb *redis.Client, token string) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		E2EAccountToken: token,
		JWTSecret:       testhelpers.TestJWTSecret,
		AESKey:          testhelpers.TestAESKeyHex,
		Environment:     "test",
	}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error", "message": err.Error()})
		},
	})
	h := handlers.NewE2EAccountHandler(db, rdb, cfg)
	app.Post("/internal/e2e/account", h.CreateAccount)
	app.Delete("/internal/e2e/account/:team_id", h.ReapAccount)

	// Probe route: proves the minted session JWT authenticates through the
	// ordinary RequireAuth middleware (the whole point of reusing the signer).
	app.Get("/probe", middleware.RequireAuth(cfg), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"team_id": c.Locals(middleware.LocalKeyTeamID)})
	})
	return app
}

// e2eCreateResp is the create-endpoint response shape we assert on.
type e2eCreateResp struct {
	TeamID         string   `json:"team_id"`
	UserID         string   `json:"user_id"`
	Email          string   `json:"email"`
	Tier           string   `json:"tier"`
	SessionJWT     string   `json:"session_jwt"`
	ExpiresAt      string   `json:"expires_at"`
	SeededTokens   []string `json:"seeded_tokens"`
	SeededCount    int      `json:"seeded_count"`
	FailedDeployID string   `json:"failed_deploy_id"`
	Error          string   `json:"error"`
}

func postE2ECreate(t *testing.T, app *fiber.App, token, body string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/internal/e2e/account", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-E2E-Token", token)
	}
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

func deleteE2EReap(t *testing.T, app *fiber.App, token, teamID string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/internal/e2e/account/"+teamID, nil)
	if token != "" {
		req.Header.Set("X-E2E-Token", token)
	}
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

func decodeE2ECreate(t *testing.T, resp *http.Response) e2eCreateResp {
	t.Helper()
	var out e2eCreateResp
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out
}

// --- guard: inert by default -------------------------------------------------

func TestE2EAccount_TokenUnset_Returns404(t *testing.T) {
	t.Parallel()
	// No DB needed — the guard 404s before any DB work.
	app := newE2ETestApp(t, nil, nil, "") // configured token empty
	resp := postE2ECreate(t, app, "anything", `{"tier":"free"}`)
	require.Equal(t, http.StatusNotFound, resp.StatusCode,
		"empty E2E_ACCOUNT_TOKEN must make the endpoint inert (404)")

	// Reap is equally inert.
	resp2 := deleteE2EReap(t, app, "anything", uuid.New().String())
	require.Equal(t, http.StatusNotFound, resp2.StatusCode)
}

func TestE2EAccount_WrongToken_Returns404(t *testing.T) {
	t.Parallel()
	app := newE2ETestApp(t, nil, nil, testE2EToken)
	resp := postE2ECreate(t, app, "wrong-token", `{"tier":"free"}`)
	require.Equal(t, http.StatusNotFound, resp.StatusCode,
		"wrong X-E2E-Token must 404 (not 401/403) to hide the route")

	// Missing header (token configured) is also 404.
	resp2 := postE2ECreate(t, app, "", `{"tier":"free"}`)
	require.Equal(t, http.StatusNotFound, resp2.StatusCode)
}

// --- create: happy path ------------------------------------------------------

func TestE2EAccount_Create_FreeTier_MintsTestCohortAndAuthenticatingJWT(t *testing.T) {
	skipUnlessE2EDB(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	app := newE2ETestApp(t, db, nil, testE2EToken)

	resp := postE2ECreate(t, app, testE2EToken, `{"tier":"free"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	out := decodeE2ECreate(t, resp)

	require.NotEmpty(t, out.TeamID)
	require.NotEmpty(t, out.UserID)
	require.Equal(t, "free", out.Tier)
	require.Contains(t, out.Email, "e2e-cohort+")
	require.Contains(t, out.Email, "@instanode.dev")
	require.NotEmpty(t, out.SessionJWT)
	require.NotEmpty(t, out.ExpiresAt)

	// The team must be is_test_cohort=true.
	var isCohort bool
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT is_test_cohort FROM teams WHERE id = $1`, out.TeamID).Scan(&isCohort))
	require.True(t, isCohort, "minted team must be is_test_cohort")

	// The primary user must be email_verified.
	var verified bool
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT email_verified FROM users WHERE id = $1`, out.UserID).Scan(&verified))
	require.True(t, verified, "minted primary user must be email_verified")

	// The session JWT must authenticate through RequireAuth.
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer "+out.SessionJWT)
	probeResp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, probeResp.StatusCode, "minted JWT must authenticate")
	var probe struct {
		TeamID string `json:"team_id"`
	}
	require.NoError(t, json.NewDecoder(probeResp.Body).Decode(&probe))
	require.Equal(t, out.TeamID, probe.TeamID, "probe must resolve the minted team")

	// The session JWT's claims are HS256-signed with the same secret + short TTL.
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(out.SessionJWT, claims, func(_ *jwt.Token) (interface{}, error) {
		return []byte(testhelpers.TestJWTSecret), nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	require.NoError(t, err)
	require.Equal(t, out.TeamID, claims["tid"])
	require.Equal(t, out.UserID, claims["uid"])
}

func TestE2EAccount_Create_PaidTier_SetsTier(t *testing.T) {
	skipUnlessE2EDB(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	app := newE2ETestApp(t, db, nil, testE2EToken)

	resp := postE2ECreate(t, app, testE2EToken, `{"tier":"pro"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	out := decodeE2ECreate(t, resp)
	require.Equal(t, "pro", out.Tier)

	var planTier string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT plan_tier FROM teams WHERE id = $1`, out.TeamID).Scan(&planTier))
	require.Equal(t, "pro", planTier, "paid-tier mint must escalate plan_tier via the upgrade path")
}

func TestE2EAccount_Create_EmptyBody_DefaultsToFree(t *testing.T) {
	skipUnlessE2EDB(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	app := newE2ETestApp(t, db, nil, testE2EToken)

	resp := postE2ECreate(t, app, testE2EToken, ``)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	out := decodeE2ECreate(t, resp)
	require.Equal(t, "free", out.Tier)
}

func TestE2EAccount_Create_MalformedBody_400(t *testing.T) {
	t.Parallel()
	app := newE2ETestApp(t, nil, nil, testE2EToken)
	resp := postE2ECreate(t, app, testE2EToken, `{not json`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// --- create: gated tiers rejected -------------------------------------------

func TestE2EAccount_Create_TeamTier_Rejected400(t *testing.T) {
	t.Parallel()
	app := newE2ETestApp(t, nil, nil, testE2EToken)
	resp := postE2ECreate(t, app, testE2EToken, `{"tier":"team"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"tier=team must be rejected — Team is gated, never minted")
	out := decodeE2ECreate(t, resp)
	require.Equal(t, "tier_not_allowed", out.Error)
}

func TestE2EAccount_Create_GrowthTier_Rejected400(t *testing.T) {
	t.Parallel()
	app := newE2ETestApp(t, nil, nil, testE2EToken)
	resp := postE2ECreate(t, app, testE2EToken, `{"tier":"growth"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	out := decodeE2ECreate(t, resp)
	require.Equal(t, "tier_not_allowed", out.Error)
}

func TestE2EAccount_Create_UnknownTier_Rejected400(t *testing.T) {
	t.Parallel()
	app := newE2ETestApp(t, nil, nil, testE2EToken)
	resp := postE2ECreate(t, app, testE2EToken, `{"tier":"platinum"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	out := decodeE2ECreate(t, resp)
	require.Equal(t, "invalid_tier", out.Error)
}

// TestE2EAccount_Create_AllAllowedTiers_RoundTrip is the rule-18 registry-
// iterating guard: EVERY tier the handler advertises as allowed must mint
// successfully and the minted team must carry that tier as its plan_tier
// snapshot. Iterating handlers.E2EAllowedTiersForTest() (not a hand-typed
// slice) means adding a tier to the allow-set automatically expands this
// assertion — a new allowed tier can't silently ship un-exercised.
func TestE2EAccount_Create_AllAllowedTiers_RoundTrip(t *testing.T) {
	skipUnlessE2EDB(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	app := newE2ETestApp(t, db, nil, testE2EToken)

	for _, tier := range handlers.E2EAllowedTiersForTest() {
		tier := tier
		t.Run(tier, func(t *testing.T) {
			resp := postE2ECreate(t, app, testE2EToken, fmt.Sprintf(`{"tier":%q}`, tier))
			require.Equal(t, http.StatusOK, resp.StatusCode, "tier %q must mint", tier)
			out := decodeE2ECreate(t, resp)
			require.Equal(t, tier, out.Tier, "response tier must echo the requested tier")

			var planTier string
			require.NoError(t, db.QueryRowContext(context.Background(),
				`SELECT plan_tier FROM teams WHERE id = $1`, out.TeamID).Scan(&planTier))
			// The team's persisted plan_tier mirrors the requested tier for every
			// real team plan. "anonymous" is NOT a team plan — an anonymous
			// account is a free team row (CreateTestCohortTeam starts at 'free')
			// with tier="anonymous" echoed on the response for the caller to
			// drive the anon-path journey. So the persisted plan_tier is 'free'.
			wantPlanTier := tier
			if tier == "anonymous" {
				wantPlanTier = "free"
			}
			require.Equal(t, wantPlanTier, planTier,
				"minted team's plan_tier must reflect the requested tier (snapshot at creation)")
		})
	}
}

// TestE2EAccount_Create_AllBlockedTiers_Rejected is the companion guard: every
// gated tier (team/growth) must 400 with tier_not_allowed. Iterating the
// handler's blocked-set keeps the test honest if a tier is added to the gate.
func TestE2EAccount_Create_AllBlockedTiers_Rejected(t *testing.T) {
	t.Parallel()
	app := newE2ETestApp(t, nil, nil, testE2EToken)
	for _, tier := range handlers.E2EBlockedTiersForTest() {
		tier := tier
		t.Run(tier, func(t *testing.T) {
			resp := postE2ECreate(t, app, testE2EToken, fmt.Sprintf(`{"tier":%q}`, tier))
			require.Equal(t, http.StatusBadRequest, resp.StatusCode,
				"gated tier %q must be rejected (never minted)", tier)
			out := decodeE2ECreate(t, resp)
			require.Equal(t, "tier_not_allowed", out.Error)
		})
	}
}

// --- create: with_resources pre-seed ----------------------------------------

// TestE2EAccount_Create_WithResources_SeedsFastResources asserts that
// with_resources=true pre-seeds exactly the handler's seed set, that each seeded
// row is active + owned by the minted team + tier-snapshotted, and that the
// response surfaces the seeded tokens. Iterates the handler's seed-type list so
// adding a seed type auto-expands the assertion.
func TestE2EAccount_Create_WithResources_SeedsFastResources(t *testing.T) {
	skipUnlessE2EDB(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	app := newE2ETestApp(t, db, nil, testE2EToken)

	resp := postE2ECreate(t, app, testE2EToken, `{"tier":"pro","with_resources":true}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	out := decodeE2ECreate(t, resp)

	wantTypes := handlers.E2ESeedResourceTypesForTest()
	require.Equal(t, len(wantTypes), out.SeededCount,
		"seeded_count must equal the handler's seed-type count")
	require.Len(t, out.SeededTokens, len(wantTypes),
		"seeded_tokens must carry one token per seed type")

	ctx := context.Background()
	// Every seeded resource row must be active, owned by the minted team, and
	// carry the team's tier snapshot.
	gotTypes := map[string]bool{}
	for _, tok := range out.SeededTokens {
		var rtype, status, tier string
		var teamID string
		require.NoError(t, db.QueryRowContext(ctx,
			`SELECT resource_type, status, tier, team_id::text FROM resources WHERE token = $1`, tok).
			Scan(&rtype, &status, &tier, &teamID))
		require.Equal(t, "active", status, "seeded resource must be active")
		require.Equal(t, "pro", tier, "seeded resource must carry the team tier snapshot")
		require.Equal(t, out.TeamID, teamID, "seeded resource must be owned by the minted team")
		gotTypes[rtype] = true
	}
	for _, want := range wantTypes {
		require.True(t, gotTypes[want], "seed set must include a %q resource", want)
	}
}

// TestE2EAccount_Create_WithoutResources_SeedsNothing pins that the seed is
// opt-in: omitting with_resources mints an empty account (seeded_count=0) and
// the response still carries an empty (non-null) seeded_tokens array.
func TestE2EAccount_Create_WithoutResources_SeedsNothing(t *testing.T) {
	skipUnlessE2EDB(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	app := newE2ETestApp(t, db, nil, testE2EToken)

	resp := postE2ECreate(t, app, testE2EToken, `{"tier":"free"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	out := decodeE2ECreate(t, resp)
	require.Equal(t, 0, out.SeededCount)
	require.NotNil(t, out.SeededTokens, "seeded_tokens must be [] not null when nothing is seeded")
	require.Empty(t, out.SeededTokens)

	var n int
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM resources WHERE team_id = $1`, out.TeamID).Scan(&n))
	require.Equal(t, 0, n, "no resources must be seeded when with_resources is omitted")
}

// TestE2EAccount_Create_WithResources_SeedFailure_Returns503 forces the seed
// step to fail (via the e2eSeedFastResources seam) and asserts CreateAccount
// surfaces a 503 seed_failed — CI must never receive a half-populated account.
func TestE2EAccount_Create_WithResources_SeedFailure_Returns503(t *testing.T) {
	skipUnlessE2EDB(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	app := newE2ETestApp(t, db, nil, testE2EToken)

	restore := handlers.SetE2ESeedFastResourcesForTest(errors.New("seed exploded"))
	defer restore()

	resp := postE2ECreate(t, app, testE2EToken, `{"tier":"pro","with_resources":true}`)
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode,
		"a seed failure must surface as 503, never a half-populated 200")
	out := decodeE2ECreate(t, resp)
	require.Equal(t, "seed_failed", out.Error)
}

// --- reap --------------------------------------------------------------------

func TestE2EAccount_Reap_TestCohortTeam_Purged(t *testing.T) {
	skipUnlessE2EDB(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	app := newE2ETestApp(t, db, nil, testE2EToken)

	// Mint, then insert a resource so we can assert it was marked for reaper.
	out := decodeE2ECreate(t, postE2ECreate(t, app, testE2EToken, `{"tier":"pro"}`))
	require.NotEmpty(t, out.TeamID)
	ctx := context.Background()
	var resID string
	require.NoError(t, db.QueryRowContext(ctx, `
		INSERT INTO resources (team_id, resource_type, tier, status)
		VALUES ($1, 'postgres', 'pro', 'active')
		RETURNING id::text`, out.TeamID).Scan(&resID))

	resp := deleteE2EReap(t, app, testE2EToken, out.TeamID)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Team is gone.
	var teamCount int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT count(*) FROM teams WHERE id = $1`, out.TeamID).Scan(&teamCount))
	require.Equal(t, 0, teamCount, "reaped test-cohort team must be deleted")

	// The resource row survives (ON DELETE SET NULL) but is marked for the
	// worker reaper: team_id NULL, tier='free', expires_at set in the past.
	var teamID sql.NullString
	var tier string
	var expiresAt sql.NullTime
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT team_id, tier, expires_at FROM resources WHERE id = $1`, resID).
		Scan(&teamID, &tier, &expiresAt))
	require.False(t, teamID.Valid, "resource team_id must be NULL after team delete")
	require.Equal(t, "free", tier, "resource must be re-tiered to 'free' so the reaper picks it up")
	require.True(t, expiresAt.Valid, "resource expires_at must be set so the reaper deprovisions it")
}

// TestE2EAccount_Reap_NonCohortTeam_Forbidden is THE CRITICAL SAFETY TEST: a
// real (non-test-cohort) team must NEVER be deletable via the e2e surface.
func TestE2EAccount_Reap_NonCohortTeam_Forbidden(t *testing.T) {
	skipUnlessE2EDB(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	app := newE2ETestApp(t, db, nil, testE2EToken)

	// Create a REAL team (is_test_cohort defaults false).
	ctx := context.Background()
	var realTeamID string
	require.NoError(t, db.QueryRowContext(ctx,
		`INSERT INTO teams (name, plan_tier) VALUES ('real-customer', 'pro') RETURNING id::text`).
		Scan(&realTeamID))

	resp := deleteE2EReap(t, app, testE2EToken, realTeamID)
	require.Equal(t, http.StatusForbidden, resp.StatusCode,
		"reaping a non-test-cohort team MUST 403 — never delete a real team")
	var out struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	require.Equal(t, "not_test_cohort", out.Error)

	// The real team must still exist — the 403 protected it.
	var cnt int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT count(*) FROM teams WHERE id = $1`, realTeamID).Scan(&cnt))
	require.Equal(t, 1, cnt, "real team must survive a refused reap")
}

func TestE2EAccount_Reap_AlreadyGone_Idempotent200(t *testing.T) {
	skipUnlessE2EDB(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	app := newE2ETestApp(t, db, nil, testE2EToken)

	resp := deleteE2EReap(t, app, testE2EToken, uuid.New().String())
	require.Equal(t, http.StatusOK, resp.StatusCode, "reaping a non-existent team is an idempotent 200")
}

func TestE2EAccount_Reap_BadTeamID_400(t *testing.T) {
	t.Parallel()
	app := newE2ETestApp(t, nil, nil, testE2EToken)
	resp := deleteE2EReap(t, app, testE2EToken, "not-a-uuid")
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestE2EAccount_Reap_TokenUnset_404(t *testing.T) {
	t.Parallel()
	app := newE2ETestApp(t, nil, nil, "")
	resp := deleteE2EReap(t, app, "anything", uuid.New().String())
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// --- per-token rate limit ----------------------------------------------------

func TestE2EAccount_RateLimit_TripsAfterCap(t *testing.T) {
	skipUnlessE2EDB(t)
	db, dbCleanup := testhelpers.SetupTestDB(t)
	defer dbCleanup()
	rdb, rCleanup := testhelpers.SetupTestRedis(t)
	defer rCleanup()
	app := newE2ETestApp(t, db, rdb, testE2EToken)

	// Pre-load the per-token sliding window to the cap so the next mint trips
	// the limit deterministically (no need to actually create 120 accounts).
	// Key shape must match handler: rl_e2e_account:<sha256-hex-of-token>.
	sum := sha256.Sum256([]byte(testE2EToken))
	key := "rl_e2e_account:" + hex.EncodeToString(sum[:])
	ctx := context.Background()
	now := time.Now().UnixNano()
	for i := 0; i < 120; i++ {
		require.NoError(t, rdb.ZAdd(ctx, key, redis.Z{
			Score:  float64(now + int64(i)),
			Member: fmt.Sprintf("%d:%d", now+int64(i), i),
		}).Err())
	}

	resp := postE2ECreate(t, app, testE2EToken, `{"tier":"free"}`)
	require.Equal(t, http.StatusTooManyRequests, resp.StatusCode,
		"a token at its window cap must be rate-limited")
	out := decodeE2ECreate(t, resp)
	require.Equal(t, "rate_limited", out.Error)
}

func TestE2EAccount_RateLimit_NilRedis_FailsOpen(t *testing.T) {
	skipUnlessE2EDB(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	// nil redis → rate limit fails open → mint succeeds.
	app := newE2ETestApp(t, db, nil, testE2EToken)
	resp := postE2ECreate(t, app, testE2EToken, `{"tier":"free"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "nil Redis must fail open (rule 1), not block")
}
