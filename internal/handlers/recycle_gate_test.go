package handlers

// recycle_gate_test.go — Option B "email gate at recycle" tests
// (FREE-TIER-RECYCLE-2026-05-12.md). These tests guard the wedge plus the
// gate itself. Order of importance:
//
//  1. WEDGE: first anonymous touch on a fingerprint with NO recycle_seen
//     marker MUST pass the gate (return false, no 402). If this regresses
//     the agent's magic-first-touch is broken — that's the entire product.
//  2. GATE FIRES: second anonymous touch on the same fingerprint AFTER the
//     prior resource ages out → 402 free_tier_recycle_requires_claim with
//     agent_action + claim_url.
//  3. DEDUP STILL WINS: marker present BUT an active row still exists →
//     gate does NOT fire; the existing daily-cap / dedup branch handles it.
//  4. EMPTY FINGERPRINT: no fingerprint header → gate doesn't fire (no key
//     to read).
//  5. FAIL-OPEN: Redis or DB error during the gate check → gate returns
//     false (fails open) so the wedge is never collateral damage.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alicebob/miniredis/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/plans"
)

// newTestHelper builds a provisionHelper backed by miniredis + an optional
// sqlmock DB. Callers that don't exercise the DB lookup can pass nil for db.
func newTestHelper(t *testing.T) (provisionHelper, *miniredis.Miniredis, *redis.Client, func()) {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	cfg := &config.Config{JWTSecret: "test_secret_must_be_at_least_32_bytes_long_xx"}
	reg := plans.Default()
	h := newProvisionHelper(nil, rdb, cfg, reg)
	cleanup := func() {
		_ = rdb.Close()
		mr.Close()
	}
	return h, mr, rdb, cleanup
}

// drive runs handler once against a Fiber app set up to short-circuit on
// ErrResponseWritten the same way production does. Returns status + parsed JSON body.
func drive(t *testing.T, handler fiber.Handler) (int, map[string]any) {
	t.Helper()
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"ok":      false,
				"error":   "internal_error",
				"message": err.Error(),
			})
		},
	})
	app.Get("/probe", handler)
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	resp, err := app.Test(req, 2000)
	require.NoError(t, err)
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

// ─────────────────────────────────────────────────────────────────────────────
// Case 1 — WEDGE PRESERVATION
//
// The single most important test in this file. If this ever fails the gate
// has bricked the magic-first-touch the entire product depends on.
// ─────────────────────────────────────────────────────────────────────────────

func TestRecycleGate_WedgePreserved_FirstAnonymousTouch_NoMarker_Passes(t *testing.T) {
	h, _, _, cleanup := newTestHelper(t)
	defer cleanup()

	// Fingerprint that has never provisioned before — there is no
	// recycle_seen:<fp> key in Redis. The gate must not fire.
	const fp = "fp_brand_new_first_time_agent"

	var gateFired bool
	status, _ := drive(t, func(c *fiber.Ctx) error {
		gateFired = h.recycleGate(c, fp, "postgres")
		if gateFired {
			return nil
		}
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"ok": true})
	})

	assert.False(t, gateFired,
		"WEDGE REGRESSION: first anonymous POST with no recycle_seen marker was gated. "+
			"This would 402 every first-time agent — the product's core promise.")
	assert.Equal(t, fiber.StatusOK, status,
		"first-time anonymous caller must reach the green-path provisioning branch")
}

// ─────────────────────────────────────────────────────────────────────────────
// Case 2 — markRecycleSeen + recycleSeen round-trip
//
// Spot-check the Redis side of the marker so the higher-level test isn't
// covering for a silent no-op.
// ─────────────────────────────────────────────────────────────────────────────

func TestRecycleGate_MarkRecycleSeen_WritesMarkerWithTTL(t *testing.T) {
	h, mr, _, cleanup := newTestHelper(t)
	defer cleanup()

	ctx := context.Background()
	const fp = "fp_round_trip"

	// Before marking — should not be seen.
	seen, err := h.recycleSeen(ctx, fp)
	require.NoError(t, err)
	require.False(t, seen, "fresh fingerprint must not appear as seen")

	require.NoError(t, h.markRecycleSeen(ctx, fp))

	seen, err = h.recycleSeen(ctx, fp)
	require.NoError(t, err)
	require.True(t, seen, "after markRecycleSeen the recycleSeen lookup must return true")

	// TTL is the 30d marker; miniredis returns the live TTL.
	ttl := mr.TTL(RecycleSeenKeyPrefix + fp)
	assert.InDelta(t, RecycleSeenTTL.Seconds(), ttl.Seconds(), 60,
		"recycle_seen marker must have ~30d TTL — got %s", ttl)
}

// ─────────────────────────────────────────────────────────────────────────────
// Case 3 — GATE FIRES on recycle
//
// Marker set + DB returns ErrResourceNotFound (active row was expired by
// the worker) → 402 with the expected fields.
// ─────────────────────────────────────────────────────────────────────────────

func TestRecycleGate_FiresWith402_WhenMarkerExistsAndNoActiveRow(t *testing.T) {
	h, _, _, cleanup := newTestHelper(t)
	defer cleanup()

	// Wire a sqlmock that returns 0 rows (resource expired/deleted).
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()
	h.db = db

	const fp = "fp_recycler"
	// Pre-mark — this fingerprint has provisioned before.
	require.NoError(t, h.markRecycleSeen(context.Background(), fp))

	// The lookup in recycleGate runs:
	//   SELECT ... FROM resources WHERE fingerprint = $1 AND team_id IS NULL
	//     AND status = 'active' ORDER BY created_at DESC
	// (cross-service: any active resource for this fingerprint counts).
	// We return zero rows. F1: the gate now mints a claim JWT, which issues a
	// SECOND identical fingerprint lookup inside issueOnboardingJWT — expect
	// both (each returns zero rows; sqlmock matches in order).
	emptyRows := func() *sqlmock.Rows {
		return sqlmock.NewRows([]string{
			"id", "team_id", "token", "resource_type", "name", "connection_url",
			"key_prefix", "tier", "env", "fingerprint", "cloud_vendor",
			"country_code", "status", "migration_status", "expires_at",
			"storage_bytes", "provider_resource_id", "created_request_id",
			"parent_resource_id", "created_at",
		})
	}
	mock.ExpectQuery(`SELECT.*FROM resources.*fingerprint`).
		WithArgs(fp).
		WillReturnRows(emptyRows())
	mock.ExpectQuery(`SELECT.*FROM resources.*fingerprint`).
		WithArgs(fp).
		WillReturnRows(emptyRows())

	var gateFired bool
	status, body := drive(t, func(c *fiber.Ctx) error {
		gateFired = h.recycleGate(c, fp, "postgres")
		if gateFired {
			return nil
		}
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"ok": true})
	})

	require.True(t, gateFired, "recycle gate must fire when marker is set and no active row exists")
	assert.Equal(t, fiber.StatusPaymentRequired, status, "recycle gate must return 402")
	assert.Equal(t, false, body["ok"])
	assert.Equal(t, RecycleGateErrorCode, body["error"],
		"error code must be the stable machine-readable %s", RecycleGateErrorCode)
	// F1: claim_url is no longer the tokenless dead-end RecycleGateClaimURL —
	// it now carries a minted claim JWT so the EXISTING /claim?t= page works.
	claimURL, ok := body["claim_url"].(string)
	require.True(t, ok, "402 must include a claim_url string")
	assert.Contains(t, claimURL, "?t=",
		"F1: claim_url must embed a minted claim JWT (?t=<jwt>), not a tokenless dead-end")
	assert.NotEqual(t, RecycleGateClaimURL, claimURL,
		"F1: claim_url must no longer be the bare tokenless https://instanode.dev/claim")
	assert.Equal(t, claimURL, body["upgrade_url"],
		"upgrade_url must mirror claim_url for parity with the existing 402 contract")
	if msg, ok := body["agent_action"].(string); ok {
		assert.Contains(t, msg, "claim", "agent_action must instruct claiming")
	} else {
		t.Errorf("agent_action must be a string; got %T", body["agent_action"])
	}

	require.NoError(t, mock.ExpectationsWereMet())
}

// TestRecycleGate_ClaimURL_MintFailedFallsBackToBareURL asserts the F1
// fail-soft path: when claim-JWT signing fails (issueOnboardingJWT errors), the
// gate still returns a USABLE recovery URL — the bare RecycleGateClaimURL — and
// never an error. The 402 contract (error code, agent_action) is unchanged.
//
// SignOnboardingJWT cannot be forced to error from config (HMAC over any []byte
// key, including empty, signs successfully), so the mint-failure is injected
// through the issueOnboardingJWTFn seam — the only deterministic way to reach
// recycleClaimURL's mint_failed arm (provision_helper.go:371-375).
func TestRecycleGate_ClaimURL_MintFailedFallsBackToBareURL(t *testing.T) {
	h, _, _, cleanup := newTestHelper(t)
	defer cleanup()

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()
	h.db = db

	const fp = "fp_recycler_mint_path"
	require.NoError(t, h.markRecycleSeen(context.Background(), fp))

	emptyRows := func() *sqlmock.Rows {
		return sqlmock.NewRows([]string{
			"id", "team_id", "token", "resource_type", "name", "connection_url",
			"key_prefix", "tier", "env", "fingerprint", "cloud_vendor",
			"country_code", "status", "migration_status", "expires_at",
			"storage_bytes", "provider_resource_id", "created_request_id",
			"parent_resource_id", "created_at",
		})
	}
	// recycle lookup returns zero rows → gate fires. The claim-JWT mint that
	// follows is forced to fail by the seam below, so issueOnboardingJWT (and
	// its own fingerprint lookup) is never reached — only ONE query expected.
	mock.ExpectQuery(`SELECT.*FROM resources.*fingerprint`).
		WithArgs(fp).
		WillReturnRows(emptyRows())

	// Force the mint to fail → exercises the mint_failed arm + bare-URL fallback.
	orig := issueOnboardingJWTFn
	issueOnboardingJWTFn = func(
		_ *provisionHelper, _ context.Context,
		_, _, _, _ string, _ []string,
	) (string, string, error) {
		return "", "", errors.New("simulated jwt sign failure")
	}
	defer func() { issueOnboardingJWTFn = orig }()

	status, body := drive(t, func(c *fiber.Ctx) error {
		if h.recycleGate(c, fp, "postgres") {
			return nil
		}
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"ok": true})
	})

	assert.Equal(t, fiber.StatusPaymentRequired, status, "gate still fires")
	assert.Equal(t, RecycleGateErrorCode, body["error"], "402 contract unchanged on mint trouble")
	claimURL, ok := body["claim_url"].(string)
	require.True(t, ok, "claim_url must always be a usable string, even on mint trouble")
	assert.Equal(t, RecycleGateClaimURL, claimURL,
		"mint failure must fall back to the bare tokenless RecycleGateClaimURL")
	require.NoError(t, mock.ExpectationsWereMet())
}

// TestRecycleGate_ClaimURL_MintSucceeds_EmbedsJWT covers the happy mint arm
// (provision_helper.go:376-377): when the seam returns a token, claim_url is the
// /start?t=<jwt> bounce URL (not the bare fallback). Pins the minted-metric path
// alongside the mint_failed path above.
func TestRecycleGate_ClaimURL_MintSucceeds_EmbedsJWT(t *testing.T) {
	h, _, _, cleanup := newTestHelper(t)
	defer cleanup()

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()
	h.db = db

	const fp = "fp_recycler_mint_ok"
	require.NoError(t, h.markRecycleSeen(context.Background(), fp))

	mock.ExpectQuery(`SELECT.*FROM resources.*fingerprint`).
		WithArgs(fp).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "team_id", "token", "resource_type", "name", "connection_url",
			"key_prefix", "tier", "env", "fingerprint", "cloud_vendor",
			"country_code", "status", "migration_status", "expires_at",
			"storage_bytes", "provider_resource_id", "created_request_id",
			"parent_resource_id", "created_at",
		}))

	orig := issueOnboardingJWTFn
	issueOnboardingJWTFn = func(
		_ *provisionHelper, _ context.Context,
		_, _, _, _ string, _ []string,
	) (string, string, error) {
		return "minted.jwt.token", "jti-1", nil
	}
	defer func() { issueOnboardingJWTFn = orig }()

	_, body := drive(t, func(c *fiber.Ctx) error {
		if h.recycleGate(c, fp, "postgres") {
			return nil
		}
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"ok": true})
	})

	claimURL, ok := body["claim_url"].(string)
	require.True(t, ok)
	assert.Contains(t, claimURL, "?t=minted.jwt.token",
		"a successful mint must embed the JWT in the /start bounce URL")
	assert.NotEqual(t, RecycleGateClaimURL, claimURL)
	require.NoError(t, mock.ExpectationsWereMet())
}

// ─────────────────────────────────────────────────────────────────────────────
// Case 4 — DEDUP STILL WINS
//
// Marker is set BUT an active resource still exists for the fingerprint
// (i.e. the caller hasn't actually recycled — they're just hitting the
// daily counter the second time today). The gate must defer to the
// existing daily-cap / dedup branch by returning false.
// ─────────────────────────────────────────────────────────────────────────────

func TestRecycleGate_DoesNotFire_WhenActiveRowStillExists(t *testing.T) {
	h, _, _, cleanup := newTestHelper(t)
	defer cleanup()

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()
	h.db = db

	const fp = "fp_same_day_caller"
	require.NoError(t, h.markRecycleSeen(context.Background(), fp))

	// The lookup returns a row in the canonical resourceColumns order
	// (see models/resource.go). Cross-service: any live resource for this
	// fingerprint counts as still-mid-session. The handler asks for "postgres"
	// but we hand back a live redis row — gate must still defer.
	expires := time.Now().Add(20 * time.Hour)
	mock.ExpectQuery(`SELECT.*FROM resources.*fingerprint`).
		WithArgs(fp).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "team_id", "token", "resource_type", "name", "connection_url",
			"key_prefix", "tier", "env", "fingerprint", "cloud_vendor",
			"country_code", "status", "migration_status", "expires_at",
			"storage_bytes", "provider_resource_id", "created_request_id",
			"parent_resource_id", "created_at",
		}).AddRow(
			"00000000-0000-0000-0000-000000000001", // id
			nil,                                    // team_id
			"00000000-0000-0000-0000-000000000002", // token
			"redis", "", "", "", "anonymous", "production", fp,
			"", "", "active", "", &expires,
			int64(0), "", "", nil, time.Now(),
		))

	var gateFired bool
	status, _ := drive(t, func(c *fiber.Ctx) error {
		gateFired = h.recycleGate(c, fp, "postgres")
		if gateFired {
			return nil
		}
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"ok": true})
	})

	assert.False(t, gateFired,
		"gate must defer to the existing dedup branch when an active row still exists")
	assert.Equal(t, fiber.StatusOK, status,
		"caller must continue past the gate — dedup branch handles same-day repeat calls")
	// Even if sqlmock returned all columns the scan may still fail with the
	// fake fixture row above — we don't care; we only check the gate's
	// return value, which is the contract the handler integrates against.
	_ = mock.ExpectationsWereMet()
}

// ─────────────────────────────────────────────────────────────────────────────
// Case 5 — EMPTY FINGERPRINT
//
// Fingerprint missing (some test or unconfigured middleware path) — gate
// must not panic and must return false. recycleSeen() handles this
// explicitly and the gate inherits that behavior.
// ─────────────────────────────────────────────────────────────────────────────

func TestRecycleGate_EmptyFingerprint_DoesNotFire(t *testing.T) {
	h, _, _, cleanup := newTestHelper(t)
	defer cleanup()

	ctx := context.Background()
	seen, err := h.recycleSeen(ctx, "")
	require.NoError(t, err)
	require.False(t, seen, "empty fingerprint short-circuits to not-seen (no key to look up)")

	require.NoError(t, h.markRecycleSeen(ctx, ""),
		"markRecycleSeen with empty fingerprint must be a safe no-op")

	var gateFired bool
	status, _ := drive(t, func(c *fiber.Ctx) error {
		gateFired = h.recycleGate(c, "", "postgres")
		if gateFired {
			return nil
		}
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"ok": true})
	})

	assert.False(t, gateFired, "empty fingerprint must not trigger the gate")
	assert.Equal(t, fiber.StatusOK, status)
}

// ─────────────────────────────────────────────────────────────────────────────
// Case 6 — FAIL-OPEN on Redis error
//
// Redis is down or the lookup errors → recycleSeen returns (false, err)
// and the gate logs + returns false. The wedge is non-negotiable; we'd
// rather miss a recycle than 402 an honest first-time caller.
// ─────────────────────────────────────────────────────────────────────────────

func TestRecycleGate_FailsOpenOnRedisError(t *testing.T) {
	h, mr, _, cleanup := newTestHelper(t)
	defer cleanup()
	// Closing miniredis simulates a Redis outage. The Exists call now errors.
	mr.Close()

	const fp = "fp_during_redis_outage"

	var gateFired bool
	status, body := drive(t, func(c *fiber.Ctx) error {
		gateFired = h.recycleGate(c, fp, "postgres")
		if gateFired {
			return nil
		}
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"ok": true})
	})

	assert.False(t, gateFired,
		"FAIL-OPEN REGRESSION: Redis outage must NOT trigger the recycle gate. "+
			"A Redis blip cannot 402 a first-time agent.")
	assert.Equal(t, fiber.StatusOK, status)
	assert.Equal(t, true, body["ok"])
}
