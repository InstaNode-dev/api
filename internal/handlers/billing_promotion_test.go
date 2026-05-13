package handlers_test

// billing_promotion_test.go — covers POST /api/v1/billing/promotion/validate.
//
// Test surface:
//
//   1) Valid code for the requested plan          → 200 + ok:true + discount
//   2) Unknown code                                → 200 + ok:false + agent_action
//   3) Valid code for a non-applicable plan        → 200 + ok:false (matches
//                                                    plans.ValidatePromotion's
//                                                    "does not apply" branch)
//   4) Empty code in the body                      → 400 invalid_body
//   5) Rate limit: 31st call in an hour            → 429 rate_limit_exceeded
//   6) Unauthenticated                             → 401 unauthorized
//
// We build a temp plans.yaml so the registry has a known promotion seed
// (LAUNCH50 → pro/team) — the production plans.yaml carries an empty
// promotions list, so plans.Default() can't drive the happy path.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

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

// promoTestYAML is a minimal plans.yaml fragment with the bare-minimum plan
// definitions (the registry requires an "anonymous" key) plus two
// promotion codes: LAUNCH50 (pro/team, no expiry) and EXPIRED99
// (already-expired). Writing to a temp file is simpler than reaching into
// the unexported parse() helper to stuff an in-memory Registry.
const promoTestYAML = `
plans:
  anonymous:
    display_name: "Anonymous"
    price_monthly_cents: 0
    trial_days: 0
    limits: { provisions_per_day: 5 }
    features: {}
  hobby:
    display_name: "Hobby"
    price_monthly_cents: 900
    trial_days: 0
    limits: { provisions_per_day: 50 }
    features: {}
  pro:
    display_name: "Pro"
    price_monthly_cents: 4900
    trial_days: 0
    limits: { provisions_per_day: 500 }
    features: {}
  team:
    display_name: "Team"
    price_monthly_cents: 19900
    trial_days: 0
    limits: { provisions_per_day: 5000 }
    features: {}

promotions:
  - code: "LAUNCH50"
    discount_percent: 50
    applies_to: ["pro", "team"]
    expires_at: "2099-12-31"
    max_uses: 1000
    description: "50% off Pro or Team for the first 1000 signups"
  - code: "EXPIRED99"
    discount_percent: 99
    applies_to: ["pro"]
    expires_at: "2020-01-01"
    max_uses: -1
    description: "Already-expired test code"
`

// newPromoRegistry writes promoTestYAML to a tempfile and loads it. Returns
// the loaded Registry; calling t.TempDir() ensures cleanup on test exit.
func newPromoRegistry(t *testing.T) *plans.Registry {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "plans.yaml")
	require.NoError(t, os.WriteFile(path, []byte(promoTestYAML), 0o600))
	reg, err := plans.Load(path)
	require.NoError(t, err)
	return reg
}

// newPromoApp builds the minimal Fiber app for promotion-validate tests.
// The middleware shim seeds c.Locals with the supplied teamID when
// authenticate=true; otherwise it skips, exercising the 401 branch.
func newPromoApp(t *testing.T, rdb *redis.Client, reg *plans.Registry, authenticate bool, teamID uuid.UUID) *fiber.App {
	t.Helper()
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false, "error": err.Error()})
		},
	})
	app.Use(middleware.RequestID())
	if authenticate {
		app.Use(func(c *fiber.Ctx) error {
			c.Locals(middleware.LocalKeyTeamID, teamID.String())
			c.Locals(middleware.LocalKeyUserID, uuid.NewString())
			return c.Next()
		})
	}
	h := handlers.NewBillingPromotionHandler(rdb, reg)
	app.Post("/api/v1/billing/promotion/validate", h.ValidatePromotion)
	return app
}

// postPromo issues a single POST to the endpoint and returns the parsed
// response body + status. Centralised so each test reads as "set up body
// → assert response".
func postPromo(t *testing.T, app *fiber.App, body any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/promotion/validate", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	var out map[string]any
	if resp.ContentLength != 0 {
		_ = json.NewDecoder(resp.Body).Decode(&out)
	}
	return resp.StatusCode, out
}

// TestValidatePromotion_ValidCode_ReturnsDiscount — the happy path the
// dashboard's PromoCodePanel walks. Asserts the full response shape so a
// drift in either direction (handler reshapes the struct, dashboard
// changes its parser) is caught by exactly one of the two test suites.
func TestValidatePromotion_ValidCode_ReturnsDiscount(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	reg := newPromoRegistry(t)
	teamID := uuid.New()
	app := newPromoApp(t, rdb, reg, true, teamID)

	status, body := postPromo(t, app, map[string]string{"code": "LAUNCH50", "plan": "pro"})
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, true, body["ok"])
	assert.Equal(t, "LAUNCH50", body["code"])

	discount, ok := body["discount"].(map[string]any)
	require.True(t, ok, "discount must be a populated object on the happy path; body=%v", body)
	assert.Equal(t, "percent_off", discount["kind"])
	assert.Equal(t, float64(50), discount["value"])
	assert.Equal(t, float64(1000), discount["max_uses"])
	appliesTo, ok := discount["applies_to"].([]any)
	require.True(t, ok)
	assert.ElementsMatch(t, []any{"pro", "team"}, appliesTo)
	// valid_until should be the end-of-day UTC for the YYYY-MM-DD in the YAML.
	assert.Contains(t, body["valid_until"], "2099-12-31T23:59:59")
}

// TestValidatePromotion_CaseInsensitive — the registry treats codes as
// case-insensitive; the response should echo the canonical uppercase.
// Belt-and-suspenders test so a future tightening of the registry's
// case handling can't silently break the dashboard.
func TestValidatePromotion_CaseInsensitive(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	reg := newPromoRegistry(t)
	teamID := uuid.New()
	app := newPromoApp(t, rdb, reg, true, teamID)

	status, body := postPromo(t, app, map[string]string{"code": "launch50", "plan": "pro"})
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, true, body["ok"], "lowercase code must validate identically to uppercase; body=%v", body)
	assert.Equal(t, "LAUNCH50", body["code"], "response must echo the canonical uppercase code")
}

// TestValidatePromotion_InvalidCode_ReturnsOkFalse — unknown codes get
// 200 + ok:false + agent_action, NOT 4xx. The dashboard renders the red
// state through its success-path parser; MCP/CLI agents copy the
// agent_action verbatim.
func TestValidatePromotion_InvalidCode_ReturnsOkFalse(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	reg := newPromoRegistry(t)
	teamID := uuid.New()
	app := newPromoApp(t, rdb, reg, true, teamID)

	status, body := postPromo(t, app, map[string]string{"code": "DOESNOTEXIST", "plan": "pro"})
	require.Equal(t, http.StatusOK, status, "invalid codes return 200 so the dashboard's happy-path parser handles them")
	assert.Equal(t, false, body["ok"])
	assert.Equal(t, "promotion_invalid", body["error"])
	assert.NotEmpty(t, body["message"])
	assert.NotEmpty(t, body["agent_action"], "MCP/CLI agents need the LLM-ready copy on every rejection")
	assert.Nil(t, body["discount"], "discount must be absent on the rejection path")
}

// TestValidatePromotion_WrongPlan_ReturnsOkFalse — LAUNCH50 applies to
// pro/team only; asking for it on hobby returns 200 + ok:false.
// Mirrors plans_test.go:TestValidatePromotion_WrongPlan_ReturnsError but
// at the HTTP boundary.
func TestValidatePromotion_WrongPlan_ReturnsOkFalse(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	reg := newPromoRegistry(t)
	teamID := uuid.New()
	app := newPromoApp(t, rdb, reg, true, teamID)

	status, body := postPromo(t, app, map[string]string{"code": "LAUNCH50", "plan": "hobby"})
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, false, body["ok"])
	assert.Equal(t, "promotion_invalid", body["error"])
	assert.Contains(t, body["message"], "hobby")
	assert.NotEmpty(t, body["agent_action"])
}

// TestValidatePromotion_ExpiredCode_ReturnsExpired — codes past their
// expires_at get the structured "promotion_expired" error so the
// dashboard can show a different copy ("this code has expired") vs.
// "this code is invalid".
func TestValidatePromotion_ExpiredCode_ReturnsExpired(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	reg := newPromoRegistry(t)
	teamID := uuid.New()
	app := newPromoApp(t, rdb, reg, true, teamID)

	status, body := postPromo(t, app, map[string]string{"code": "EXPIRED99", "plan": "pro"})
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, false, body["ok"])
	assert.Equal(t, "promotion_expired", body["error"])
	assert.NotEmpty(t, body["agent_action"])
}

// TestValidatePromotion_EmptyCode_Returns400 — an empty/missing code is
// a client bug, not a user error. We return 400 so the dashboard's
// error toast fires instead of the red banner.
func TestValidatePromotion_EmptyCode_Returns400(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	reg := newPromoRegistry(t)
	teamID := uuid.New()
	app := newPromoApp(t, rdb, reg, true, teamID)

	status, body := postPromo(t, app, map[string]string{"code": "", "plan": "pro"})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_body", body["error"])
}

// TestValidatePromotion_MissingPlan_Returns400 — same as empty code:
// caller responsibility, not user responsibility.
func TestValidatePromotion_MissingPlan_Returns400(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	reg := newPromoRegistry(t)
	teamID := uuid.New()
	app := newPromoApp(t, rdb, reg, true, teamID)

	status, body := postPromo(t, app, map[string]string{"code": "LAUNCH50"})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_body", body["error"])
}

// TestValidatePromotion_RateLimit_31stCallIs429 — fires 31 sequential
// requests and asserts only the 31st flips to 429. Proves the
// per-team-per-hour bucket cap. Using miniredis means the test is
// hermetic — no external Redis needed.
func TestValidatePromotion_RateLimit_31stCallIs429(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	reg := newPromoRegistry(t)
	teamID := uuid.New()
	app := newPromoApp(t, rdb, reg, true, teamID)

	// First 30 calls: should not be rate-limited regardless of body
	// validity. Using a valid code so the counter is the only thing the
	// 31st-call test exercises.
	for i := 0; i < 30; i++ {
		status, _ := postPromo(t, app, map[string]string{"code": "LAUNCH50", "plan": "pro"})
		require.NotEqual(t, http.StatusTooManyRequests, status, fmt.Sprintf("call %d/30 must not be rate-limited", i+1))
	}

	// 31st call → 429.
	status, body := postPromo(t, app, map[string]string{"code": "LAUNCH50", "plan": "pro"})
	require.Equal(t, http.StatusTooManyRequests, status, "31st call must be rate-limited")
	assert.Equal(t, "rate_limit_exceeded", body["error"])
	// codeToAgentAction registers a default agent_action for rate_limit_exceeded.
	assert.NotEmpty(t, body["agent_action"], "429 must carry the agent_action for the LLM caller")
}

// TestValidatePromotion_RateLimit_PerTeamBucket — team A burning its
// bucket must NOT prevent team B from validating. Scoping the bucket
// per team is the whole point — a noisy neighbour can't lock everyone
// else out.
func TestValidatePromotion_RateLimit_PerTeamBucket(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	reg := newPromoRegistry(t)
	teamA := uuid.New()
	teamB := uuid.New()
	appA := newPromoApp(t, rdb, reg, true, teamA)
	appB := newPromoApp(t, rdb, reg, true, teamB)

	// Burn team A's bucket.
	for i := 0; i < 31; i++ {
		postPromo(t, appA, map[string]string{"code": "LAUNCH50", "plan": "pro"})
	}
	// Team B's first call must still succeed.
	status, body := postPromo(t, appB, map[string]string{"code": "LAUNCH50", "plan": "pro"})
	require.Equal(t, http.StatusOK, status, "team B must not inherit team A's rate-limit bucket")
	assert.Equal(t, true, body["ok"])
}

// TestValidatePromotion_Unauthenticated_Returns401 — when no session
// middleware runs (no team_id in c.Locals), the handler short-circuits
// to 401. In production this branch is unreachable because RequireAuth
// upstream rejects the request first, but the handler must be safe
// independently of the router wiring.
func TestValidatePromotion_Unauthenticated_Returns401(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	reg := newPromoRegistry(t)
	app := newPromoApp(t, rdb, reg, false, uuid.Nil) // authenticate=false

	status, body := postPromo(t, app, map[string]string{"code": "LAUNCH50", "plan": "pro"})
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, "unauthorized", body["error"])
}

// TestValidatePromotion_RedisDown_FailsOpen — Redis errors must NOT
// block a legitimate validation. The handler treats Redis as
// best-effort; a brownout means we lose brute-force protection but
// users mid-checkout still see their discount.
func TestValidatePromotion_RedisDown_FailsOpen(t *testing.T) {
	// Closed port → dial fails fast.
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer rdb.Close()

	reg := newPromoRegistry(t)
	teamID := uuid.New()
	app := newPromoApp(t, rdb, reg, true, teamID)

	status, body := postPromo(t, app, map[string]string{"code": "LAUNCH50", "plan": "pro"})
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, true, body["ok"], "Redis failure must fail open — checkout cannot be blocked by a cache outage")
}
