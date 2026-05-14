package handlers_test

// internal_terminate_test.go — coverage for POST /internal/teams/:id/terminate.
//
// The route is the api side of the worker's payment_grace_terminator
// dispatcher. We exercise it through a minimal Fiber app that wires
// only the terminate handler — no /api/v1 auth middleware, because
// that's exactly the point: internal traffic does not use customer
// session auth.
//
// Test matrix mirrors the brief:
//   - Happy path → end-to-end terminate + idempotent second call.
//   - 401 on wrong-secret JWT.
//   - 401 on expired (iat > 60s old) JWT.
//   - 401 on team_id-claim ≠ path mismatch.
//   - Razorpay error → still 200, audit row written, razorpay_canceled=false.
//   - 404 on unknown team.

import (
	"bytes"
	"context"
	"database/sql"
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
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/testhelpers"
)

// testInternalTerminateSecret is the worker JWT secret used by every
// test in this file. Deliberately distinct from
// testhelpers.TestJWTSecret so a copy-paste bug between the two
// secrets fails loudly.
const testInternalTerminateSecret = "worker-internal-secret-32-bytes!"

func skipUnlessTerminateDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("internal terminate tests: TEST_DATABASE_URL not set")
	}
}

// newTerminateTestApp builds a Fiber app wired only to the terminate
// handler, with the supplied cancelFn injected. cancelFn==nil → the
// handler skips the Razorpay step entirely (matches the
// "subscription not configured" branch).
func newTerminateTestApp(t *testing.T, db *sql.DB, cancelFn func(string) error) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		WorkerInternalJWTSecret: testInternalTerminateSecret,
		JWTSecret:               testhelpers.TestJWTSecret,
		AESKey:                  testhelpers.TestAESKeyHex,
		Environment:             "test",
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
	h := handlers.NewInternalTerminateHandler(db, cfg, cancelFn)
	app.Post("/internal/teams/:id/terminate", h.Terminate)
	return app
}

// mintInternalTerminateJWT builds a worker-style HS256 token. iatOffset
// shifts the iat claim by a delta — zero means "now". Use a negative
// duration to forge a stale token.
func mintInternalTerminateJWT(t *testing.T, secret, purpose, teamID string, iatOffset time.Duration) string {
	t.Helper()
	claims := jwt.MapClaims{
		"purpose": purpose,
		"team_id": teamID,
		"iat":     time.Now().Add(iatOffset).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(secret))
	require.NoError(t, err)
	return signed
}

// postTerminate POSTs to the route with the given bearer token (if non-empty).
func postTerminate(t *testing.T, app *fiber.App, teamID, bearer string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/internal/teams/"+teamID+"/terminate", bytes.NewReader(nil))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

// setupTerminateTeam inserts a team + an active payment_grace_periods
// row + N active resources. Returns the team's UUID string. Sets the
// stripe_customer_id (= Razorpay subscription id) so the handler hits
// the Razorpay cancel branch. The supplied subscriptionID is suffixed
// with a fresh UUID so concurrent / repeated test runs never collide
// on the teams_stripe_customer_id_key unique index.
func setupTerminateTeam(t *testing.T, db *sql.DB, withResources int, subscriptionID string) string {
	t.Helper()
	ctx := context.Background()
	teamID := uuid.New()
	subID := ""
	if subscriptionID != "" {
		subID = subscriptionID + "_" + teamID.String()[:8]
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO teams (id, name, plan_tier, stripe_customer_id) VALUES ($1, $2, 'pro', $3)
	`, teamID, "test-term-"+teamID.String()[:8], sql.NullString{String: subID, Valid: subID != ""})
	require.NoError(t, err)
	// Active grace row — that's what payment_grace_terminator would
	// have flagged before POSTing here.
	_, err = db.ExecContext(ctx, `
		INSERT INTO payment_grace_periods (team_id, subscription_id, status, started_at, expires_at)
		VALUES ($1, $2, 'active', now() - interval '8 days', now() - interval '1 day')
	`, teamID, "sub_"+teamID.String()[:8])
	require.NoError(t, err)
	for i := 0; i < withResources; i++ {
		_, err = db.ExecContext(ctx, `
			INSERT INTO resources (team_id, resource_type, tier, status)
			VALUES ($1, 'postgres', 'pro', 'active')
		`, teamID)
		require.NoError(t, err)
	}
	return teamID.String()
}

// TestInternalTerminate_HappyPathAndIdempotent: a clean first-call
// terminates the team end-to-end (resources paused, dunning rows
// flipped, tier downgraded to free, Razorpay cancelled, audit row
// emitted). A second call returns 200 with all counts zero AND
// already_terminated=true, and does not re-enter the destructive
// path (the cancel stub records exactly one call).
func TestInternalTerminate_HappyPathAndIdempotent(t *testing.T) {
	skipUnlessTerminateDB(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()

	cancelCalls := 0
	var receivedSubID string
	cancelFn := func(subID string) error {
		cancelCalls++
		receivedSubID = subID
		return nil
	}
	app := newTerminateTestApp(t, db, cancelFn)

	teamID := setupTerminateTeam(t, db, 3, "sub_razorpay_123")
	tok := mintInternalTerminateJWT(t, testInternalTerminateSecret, "internal_terminate", teamID, 0)

	resp := postTerminate(t, app, teamID, tok)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	resp.Body.Close()
	require.True(t, body["ok"].(bool))
	require.Equal(t, teamID, body["team_id"])
	require.EqualValues(t, 3, body["paused_resource_count"])
	require.EqualValues(t, 1, body["dunning_rows_terminated"])
	require.Equal(t, true, body["razorpay_canceled"])
	require.Equal(t, 1, cancelCalls)
	require.Contains(t, receivedSubID, "sub_razorpay_123", "subscription id should be forwarded to cancelFn")

	// DB-state assertions.
	var pausedCount int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM resources WHERE team_id = $1::uuid AND status = 'paused'`, teamID).Scan(&pausedCount))
	require.Equal(t, 3, pausedCount)
	var dunningStatus string
	require.NoError(t, db.QueryRow(`SELECT status FROM payment_grace_periods WHERE team_id = $1::uuid`, teamID).Scan(&dunningStatus))
	require.Equal(t, "terminated", dunningStatus)
	var planTier string
	require.NoError(t, db.QueryRow(`SELECT plan_tier FROM teams WHERE id = $1::uuid`, teamID).Scan(&planTier))
	require.Equal(t, "free", planTier)
	var auditKind, auditActor, auditSummary string
	var auditMeta []byte
	require.NoError(t, db.QueryRow(`
		SELECT kind, actor, summary, metadata FROM audit_log
		 WHERE team_id = $1::uuid AND kind = 'payment.grace_terminated'
	`, teamID).Scan(&auditKind, &auditActor, &auditSummary, &auditMeta))
	require.Equal(t, "payment.grace_terminated", auditKind)
	require.Equal(t, "system", auditActor)
	require.Contains(t, auditSummary, "paused 3 resources")
	var meta map[string]any
	require.NoError(t, json.Unmarshal(auditMeta, &meta))
	require.EqualValues(t, 3, meta["paused_resource_count"])
	require.EqualValues(t, 1, meta["dunning_rows_terminated"])
	require.Equal(t, "pro", meta["previous_plan_tier"])
	require.Equal(t, true, meta["razorpay_canceled"])

	// Second call: same JWT (still within 60s freshness window) →
	// 200 noop. cancelFn must NOT be called again — that's the
	// idempotency proof.
	resp2 := postTerminate(t, app, teamID, tok)
	require.Equal(t, http.StatusOK, resp2.StatusCode)
	var body2 map[string]any
	require.NoError(t, json.NewDecoder(resp2.Body).Decode(&body2))
	resp2.Body.Close()
	require.True(t, body2["ok"].(bool))
	require.EqualValues(t, 0, body2["paused_resource_count"])
	require.EqualValues(t, 0, body2["dunning_rows_terminated"])
	require.Equal(t, false, body2["razorpay_canceled"])
	require.Equal(t, true, body2["already_terminated"])
	require.Equal(t, 1, cancelCalls, "cancelFn must not fire on idempotent retry")
}

// TestInternalTerminate_WrongSecret rejects a JWT signed with a
// different secret. Even though purpose / iat / team_id are all
// otherwise valid, signature verification fails first.
func TestInternalTerminate_WrongSecret(t *testing.T) {
	skipUnlessTerminateDB(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	app := newTerminateTestApp(t, db, func(string) error { return nil })

	teamID := setupTerminateTeam(t, db, 1, "sub_razorpay_x")
	tok := mintInternalTerminateJWT(t, "this-is-the-wrong-secret-32-bytes", "internal_terminate", teamID, 0)

	resp := postTerminate(t, app, teamID, tok)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// DB state must be untouched.
	var activeCount int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM resources WHERE team_id = $1::uuid AND status = 'active'`, teamID).Scan(&activeCount))
	require.Equal(t, 1, activeCount, "wrong-secret call must not pause resources")
}

// TestInternalTerminate_ExpiredIat rejects a JWT with iat > 60s old.
// This is the replay defense — captured worker tokens go stale fast.
func TestInternalTerminate_ExpiredIat(t *testing.T) {
	skipUnlessTerminateDB(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	app := newTerminateTestApp(t, db, func(string) error { return nil })

	teamID := setupTerminateTeam(t, db, 1, "sub_razorpay_y")
	// iat 5 minutes in the past → well outside the 60s window.
	tok := mintInternalTerminateJWT(t, testInternalTerminateSecret, "internal_terminate", teamID, -5*time.Minute)

	resp := postTerminate(t, app, teamID, tok)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestInternalTerminate_TeamIDMismatch rejects a JWT whose team_id
// claim does not equal the path :id. Defends against a stolen
// "team_id=A" token being POSTed to /teams/B/terminate.
func TestInternalTerminate_TeamIDMismatch(t *testing.T) {
	skipUnlessTerminateDB(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	app := newTerminateTestApp(t, db, func(string) error { return nil })

	teamA := setupTerminateTeam(t, db, 1, "sub_razorpay_a")
	teamB := setupTerminateTeam(t, db, 1, "sub_razorpay_b")
	// Token for team A; POST to team B's path.
	tok := mintInternalTerminateJWT(t, testInternalTerminateSecret, "internal_terminate", teamA, 0)

	resp := postTerminate(t, app, teamB, tok)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Neither team should be terminated.
	for _, id := range []string{teamA, teamB} {
		var active int
		require.NoError(t, db.QueryRow(`SELECT count(*) FROM resources WHERE team_id = $1::uuid AND status = 'active'`, id).Scan(&active))
		require.Equal(t, 1, active, "neither team must be touched by team_id-mismatch path: %s", id)
	}
}

// TestInternalTerminate_RazorpayErrorStillSucceeds: the Razorpay
// cancel API returns an error → the handler still returns 200 (the
// destructive DB work has happened), the response surfaces
// razorpay_canceled=false, and the audit row records the Razorpay
// error message.
func TestInternalTerminate_RazorpayErrorStillSucceeds(t *testing.T) {
	skipUnlessTerminateDB(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()

	cancelFn := func(subID string) error {
		return fmt.Errorf("razorpay API down: 503 service unavailable")
	}
	app := newTerminateTestApp(t, db, cancelFn)

	teamID := setupTerminateTeam(t, db, 2, "sub_razorpay_z")
	tok := mintInternalTerminateJWT(t, testInternalTerminateSecret, "internal_terminate", teamID, 0)

	resp := postTerminate(t, app, teamID, tok)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	resp.Body.Close()
	require.True(t, body["ok"].(bool))
	require.EqualValues(t, 2, body["paused_resource_count"])
	require.Equal(t, false, body["razorpay_canceled"])

	// Audit row written and razorpay_error captured.
	var auditMeta []byte
	require.NoError(t, db.QueryRow(`
		SELECT metadata FROM audit_log
		 WHERE team_id = $1::uuid AND kind = 'payment.grace_terminated'
	`, teamID).Scan(&auditMeta))
	var meta map[string]any
	require.NoError(t, json.Unmarshal(auditMeta, &meta))
	require.Equal(t, false, meta["razorpay_canceled"])
	require.Contains(t, meta["razorpay_error"], "razorpay API down")

	// DB state still updated despite Razorpay error.
	var planTier string
	require.NoError(t, db.QueryRow(`SELECT plan_tier FROM teams WHERE id = $1::uuid`, teamID).Scan(&planTier))
	require.Equal(t, "free", planTier)
}

// TestInternalTerminate_UnknownTeam returns 404 on a path :id that
// references no team. The auth gate passes (JWT signature OK,
// team_id claim matches the path) but the team lookup fails.
func TestInternalTerminate_UnknownTeam(t *testing.T) {
	skipUnlessTerminateDB(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	app := newTerminateTestApp(t, db, func(string) error { return nil })

	teamID := uuid.NewString()
	tok := mintInternalTerminateJWT(t, testInternalTerminateSecret, "internal_terminate", teamID, 0)

	resp := postTerminate(t, app, teamID, tok)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	resp.Body.Close()
	require.Equal(t, "team_not_found", body["error"])
}

// TestInternalTerminate_SecretUnsetRejectsAll: when
// WorkerInternalJWTSecret is empty the handler fails closed —
// every call 401s regardless of the supplied JWT. This is the
// fail-closed default that protects the route until an operator
// wires the k8s secret.
func TestInternalTerminate_SecretUnsetRejectsAll(t *testing.T) {
	skipUnlessTerminateDB(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()

	cfg := &config.Config{
		WorkerInternalJWTSecret: "", // intentionally empty
		JWTSecret:               testhelpers.TestJWTSecret,
		AESKey:                  testhelpers.TestAESKeyHex,
		Environment:             "test",
	}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false, "error": "internal_error"})
		},
	})
	h := handlers.NewInternalTerminateHandler(db, cfg, func(string) error { return nil })
	app.Post("/internal/teams/:id/terminate", h.Terminate)

	teamID := setupTerminateTeam(t, db, 1, "sub_razorpay_unset")
	// Even a "valid" token won't pass — the secret-unset gate fires
	// before signature verification. We use the test secret to prove
	// the gate fires first.
	tok := mintInternalTerminateJWT(t, testInternalTerminateSecret, "internal_terminate", teamID, 0)

	resp := postTerminate(t, app, teamID, tok)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestInternalTerminate_MissingBearer: no Authorization header at
// all → 401.
func TestInternalTerminate_MissingBearer(t *testing.T) {
	skipUnlessTerminateDB(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	app := newTerminateTestApp(t, db, func(string) error { return nil })

	teamID := setupTerminateTeam(t, db, 1, "")
	resp := postTerminate(t, app, teamID, "")
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestInternalTerminate_WrongPurpose rejects a token whose purpose
// claim is something other than "internal_terminate" — even when the
// signature is valid. Defends against a future-leak scenario where
// the same secret is reused for a different machine-to-machine token.
func TestInternalTerminate_WrongPurpose(t *testing.T) {
	skipUnlessTerminateDB(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	app := newTerminateTestApp(t, db, func(string) error { return nil })

	teamID := setupTerminateTeam(t, db, 1, "sub_razorpay_q")
	tok := mintInternalTerminateJWT(t, testInternalTerminateSecret, "internal_other_purpose", teamID, 0)

	resp := postTerminate(t, app, teamID, tok)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
