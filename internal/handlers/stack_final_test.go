package handlers_test

// stack_final_test.go — FINAL coverage pass for stack.go. Closes:
//   - NewStackHandler ComputeProvider=="k8s" fallback (95-104): no live cluster
//     → k8s.NewStackProvider errors → warn + noop fallback.
//   - checkStackDeployLimit Redis-pipeline-error arm (180-186) via closed Redis.
//   - stackOwnerCheck anonymous-stack-mismatch arm (199-201).
//   - ConfirmDelete emailClient-nil arm (1043-1047).
//   - consumeApprovedPromote lookup_failed (2396) + execute_failed (2425) via
//     openFaultDB.

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// TestStackFinal_NewHandler_K8sFallback — ComputeProvider="k8s" with no live
// cluster → k8s.NewStackProvider errors → warn + noop fallback (stack.go:97).
func TestStackFinal_NewHandler_K8sFallback(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	cfg := &config.Config{
		JWTSecret:         testhelpers.TestJWTSecret,
		AESKey:            testhelpers.TestAESKeyHex,
		ComputeProvider:   "k8s",
		KubeNamespaceApps: "instant-apps-test",
	}
	h := handlers.NewStackHandler(db, nil, cfg, plans.Default())
	require.NotNil(t, h, "constructor must return a handler even when k8s is unreachable")
}

// TestStackFinal_CheckDeployLimit_RedisError — a closed Redis client → the
// pipeline Exec errors → checkStackDeployLimit returns (false, err)
// (stack.go:180). Fails open (allowed=false) per the rate-limit posture.
func TestStackFinal_CheckDeployLimit_RedisError(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	// A redis client pointed at a dead address → pipeline Exec errors.
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 200 * time.Millisecond})
	t.Cleanup(func() { rdb.Close() })
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex, ComputeProvider: "noop"}
	h := handlers.NewStackHandler(db, rdb, cfg, plans.Default())

	_, err := h.CheckStackDeployLimitForTest(context.Background(), "fp-stackfinal")
	require.Error(t, err, "a dead Redis must surface a pipeline error (handler fails open)")
}

// TestStackFinal_OwnerCheck_AnonStackMismatch — stackOwnerCheck with a nil team
// (anonymous caller) but a stack that HAS a team → 404 (stack.go:199).
func TestStackFinal_OwnerCheck_AnonStackMismatch(t *testing.T) {
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if e == handlers.ErrResponseWritten {
				return nil // response already written by respondError
			}
			return c.Status(fiber.StatusInternalServerError).SendString(e.Error())
		},
	})
	app.Get("/t", func(c *fiber.Ctx) error {
		teamID := uuid.New()
		stack := &models.Stack{TeamID: &teamID}
		// Anonymous caller (team=nil) against a team-owned stack → 404.
		if err := handlers.StackOwnerCheckForTest(c, stack, nil); err != nil {
			return err
		}
		return c.SendString("ok")
	})
	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// stackFaultPromoteApp wires the Promote route against an arbitrary *sql.DB so
// the fault driver can drive consumeApprovedPromote's mid-handler DB-error arms.
func stackFaultPromoteApp(t *testing.T, db *sql.DB) *fiber.App {
	t.Helper()
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex, ComputeProvider: "noop"}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if e == handlers.ErrResponseWritten {
				return nil
			}
			code := fiber.StatusInternalServerError
			if fe, ok := e.(*fiber.Error); ok {
				code = fe.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": e.Error()})
		},
	})
	app.Use(middleware.RequestID())
	sh := handlers.NewStackHandler(db, nil, cfg, plans.Default())
	api := app.Group("/api/v1", middleware.RequireAuth(cfg))
	api.Post("/stacks/:slug/promote", sh.Promote)
	return app
}

// TestStackFinal_ConsumeApproved_LookupError_503 — approval lookup errors
// (stack.go:2396). requireStackTeam(1) + GetStackBySlug(2) succeed,
// GetPromoteApprovalByID(3) errors. failAfter=2.
func TestStackFinal_ConsumeApproved_LookupError_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, seedDB)
	teamIDStr := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "stklookup@example.com")
	slug, _ := seedPromoteSourceStack(t, seedDB, teamIDStr, "staging", "stkfinal-lookup")

	faultDB := openFaultDB(t, 2)
	app := stackFaultPromoteApp(t, faultDB)
	resp := postPromote(t, app, jwt, slug, map[string]any{
		"from": "staging", "to": "production", "approval_id": uuid.NewString(),
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "lookup_failed", decodeErrCode(t, resp))
}

// TestStackFinal_ConsumeApproved_ExecuteError_503 — MarkPromoteApprovalExecuted
// errors after a fully-valid approved row (stack.go:2425). team(1) + stack(2) +
// approval-read(3) succeed; the UPDATE(4) errors. failAfter=3.
func TestStackFinal_ConsumeApproved_ExecuteError_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, seedDB)
	teamIDStr := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	teamID := uuid.MustParse(teamIDStr)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "stkexec@example.com")
	slug, _ := seedPromoteSourceStack(t, seedDB, teamIDStr, "staging", "stkfinal-exec")
	id := mustSeedApprovedPromote(t, seedDB, teamID, "staging", "production")

	faultDB := openFaultDB(t, 3)
	app := stackFaultPromoteApp(t, faultDB)
	resp := postPromote(t, app, jwt, slug, map[string]any{
		"from": "staging", "to": "production", "approval_id": id,
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "execute_failed", decodeErrCode(t, resp))
}

// stackNewApp wires the /stacks/new route against an arbitrary *sql.DB.
func stackNewApp(t *testing.T, db *sql.DB, rdb *redis.Client) *fiber.App {
	t.Helper()
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex, ComputeProvider: "noop"}
	app := fiber.New(fiber.Config{
		BodyLimit: 50 * 1024 * 1024,
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if e == handlers.ErrResponseWritten {
				return nil
			}
			code := fiber.StatusInternalServerError
			if fe, ok := e.(*fiber.Error); ok {
				code = fe.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": e.Error()})
		},
	})
	app.Use(middleware.RequestID())
	app.Use(middleware.Fingerprint())
	h := handlers.NewStackHandler(db, rdb, cfg, plans.Default())
	app.Post("/stacks/new", middleware.OptionalAuth(cfg), h.New)
	return app
}

// TestStackFinal_New_DeploymentLimit_402 — a hobby team (deployments_apps=1)
// that already has one active stack → second create is rejected with 402
// deployment_limit_reached (stack.go:443-450).
func TestStackFinal_New_DeploymentLimit_402(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, db)
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	tid := uuid.MustParse(teamID)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, testhelpers.UniqueEmail(t))
	// Seed one active (healthy) stack to fill the hobby cap.
	st, err := models.CreateStack(context.Background(), db, models.CreateStackParams{
		TeamID: &tid, Slug: "stk-cap-" + teamID[:8], Tier: "hobby", Env: "production",
	})
	require.NoError(t, err)
	_, err = db.Exec(`UPDATE stacks SET status='healthy' WHERE id=$1`, st.ID)
	require.NoError(t, err)

	app := stackNewApp(t, db, nil)
	resp := postStackNew(t, app, jwt, testManifest, map[string][]byte{
		"web": createMinimalTarball(t), "api": createMinimalTarball(t),
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
}

// TestStackFinal_New_CountFailed_503 — CountActiveStacksByTeam errors →
// quota_check_failed (stack.go:438-441). optionalStackTeam team-lookup(1)
// succeeds, the count query(2) errors. failAfter=1.
func TestStackFinal_New_CountFailed_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, seedDB)
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "hobby")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, testhelpers.UniqueEmail(t))

	app := stackNewApp(t, openFaultDB(t, 1), nil)
	resp := postStackNew(t, app, jwt, testManifest, map[string][]byte{
		"web": createMinimalTarball(t), "api": createMinimalTarball(t),
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "quota_check_failed", decodeErrCode(t, resp))
}

// TestStackFinal_ConfirmDelete_EmailDisabled_503 — ConfirmDelete with no email
// client wired → deletion_email_disabled (stack.go:1043).
func TestStackFinal_ConfirmDelete_EmailDisabled_503(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, db)
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, testhelpers.UniqueEmail(t))

	// Build a ConfirmDelete app WITHOUT SetEmailClient.
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex, ComputeProvider: "noop", DeletionConfirmationTTLMinutes: 30}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if e == handlers.ErrResponseWritten {
				return nil
			}
			code := fiber.StatusInternalServerError
			if fe, ok := e.(*fiber.Error); ok {
				code = fe.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": e.Error()})
		},
	})
	app.Use(middleware.RequestID())
	h := handlers.NewStackHandler(db, nil, cfg, plans.Default()) // no SetEmailClient
	api := app.Group("/api/v1", middleware.RequireAuth(cfg))
	api.Post("/stacks/:slug/confirm-deletion", h.ConfirmDelete)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/stacks/anyslug/confirm-deletion", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "deletion_email_disabled", decodeErrCode(t, resp))
}

var _ = os.Getenv
