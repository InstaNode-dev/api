package handlers_test

// deletion_confirm_flow_bvwave_test.go — coverage for the three shared
// two-step-deletion FLOW functions in deletion_confirm.go
// (requestEmailConfirmedDeletion / resolveEmailConfirmedDeletion /
// cancelEmailConfirmedDeletion), reached via the BV* export seams. The pure
// helpers are already covered by deletion_confirm_helpers_coverage_test.go;
// these three are reached in production only through the deploy/stack delete
// endpoints, which the happy-path tests skip when provisioning is unavailable —
// so they were the dominant uncovered arms (deletion_confirm.go ~74.8%).
//
// Each flow function reads c.Context() (the fasthttp request ctx) for its DB
// calls, so the *fiber.Ctx MUST be a fully-initialised one — a bare
// &fasthttp.RequestCtx{} panics in (*RequestCtx).Done() inside database/sql.
// We therefore route every invocation through app.Test() with a one-shot
// handler closure that captures the test-scoped deps and calls the BV seam.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// bvFakeMailer is a deletion-confirmation-aware fake Mailer. It embeds the
// interface (nil) so only the methods we call need overriding.
type bvFakeMailer struct {
	email.Mailer
	sendErr  error
	sendCall int
}

func (m *bvFakeMailer) SendDeletionConfirmationWithKey(ctx context.Context, toEmail, key, label, link string, ttl int) error {
	m.sendCall++
	return m.sendErr
}

// bvInvoke runs fn inside a real fiber request so c.Context() is initialised,
// and returns the resulting HTTP status code.
func bvInvoke(t *testing.T, fn fiber.Handler) int {
	t.Helper()
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal", "message": err.Error()})
		},
	})
	app.Post("/x", fn)
	resp, err := app.Test(httptest.NewRequest(http.MethodPost, "/x", nil), 5000)
	require.NoError(t, err)
	resp.Body.Close()
	return resp.StatusCode
}

func TestDeletionConfirm_RequestFlow_bvwave(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	ownerEmail := testhelpers.UniqueEmail(t)
	require.NoError(t, db.QueryRow(
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id`,
		teamIDStr, ownerEmail,
	).Scan(new(string)))
	team, err := models.GetTeamByID(context.Background(), db, teamID)
	require.NoError(t, err)

	resourceID := uuid.New()

	t.Run("success_202", func(t *testing.T) {
		mailer := &bvFakeMailer{}
		deps := handlers.BVRequestDeletionDeps{DB: db, Email: mailer, APIPublicURL: "https://api.test", TTLMinutes: 15}
		code := bvInvoke(t, func(c *fiber.Ctx) error {
			return handlers.BVRequestEmailConfirmedDeletion(c, deps, team, resourceID, models.PendingDeletionResourceDeploy, "deployment my-app")
		})
		assert.Equal(t, fiber.StatusAccepted, code)
		assert.Equal(t, 1, mailer.sendCall)
	})

	t.Run("already_pending_409", func(t *testing.T) {
		mailer := &bvFakeMailer{}
		deps := handlers.BVRequestDeletionDeps{DB: db, Email: mailer, APIPublicURL: "https://api.test", TTLMinutes: 15}
		code := bvInvoke(t, func(c *fiber.Ctx) error {
			return handlers.BVRequestEmailConfirmedDeletion(c, deps, team, resourceID, models.PendingDeletionResourceDeploy, "deployment my-app")
		})
		assert.Equal(t, fiber.StatusConflict, code)
	})

	t.Run("email_send_fails_503_rolls_back", func(t *testing.T) {
		fresh := uuid.New()
		mailer := &bvFakeMailer{sendErr: errors.New("brevo down")}
		deps := handlers.BVRequestDeletionDeps{DB: db, Email: mailer, APIPublicURL: "https://api.test", TTLMinutes: 15}
		code := bvInvoke(t, func(c *fiber.Ctx) error {
			return handlers.BVRequestEmailConfirmedDeletion(c, deps, team, fresh, models.PendingDeletionResourceDeploy, "deployment x")
		})
		assert.Equal(t, fiber.StatusServiceUnavailable, code)
		assert.Equal(t, 1, mailer.sendCall)
		// Rollback means a re-request for the same resource now succeeds.
		mailer2 := &bvFakeMailer{}
		deps2 := handlers.BVRequestDeletionDeps{DB: db, Email: mailer2, APIPublicURL: "https://api.test", TTLMinutes: 15}
		code = bvInvoke(t, func(c *fiber.Ctx) error {
			return handlers.BVRequestEmailConfirmedDeletion(c, deps2, team, fresh, models.PendingDeletionResourceDeploy, "deployment x")
		})
		assert.Equal(t, fiber.StatusAccepted, code)
	})

	t.Run("no_owner_422", func(t *testing.T) {
		emptyTeamStr := testhelpers.MustCreateTeamDB(t, db, "pro")
		emptyTeam, terr := models.GetTeamByID(context.Background(), db, uuid.MustParse(emptyTeamStr))
		require.NoError(t, terr)
		mailer := &bvFakeMailer{}
		deps := handlers.BVRequestDeletionDeps{DB: db, Email: mailer, APIPublicURL: "https://api.test", TTLMinutes: 15}
		code := bvInvoke(t, func(c *fiber.Ctx) error {
			return handlers.BVRequestEmailConfirmedDeletion(c, deps, emptyTeam, uuid.New(), models.PendingDeletionResourceStack, "stack s")
		})
		assert.Equal(t, fiber.StatusUnprocessableEntity, code)
		assert.Equal(t, 0, mailer.sendCall)
	})
}

func TestDeletionConfirm_ResolveFlow_bvwave(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	ownerEmail := testhelpers.UniqueEmail(t)
	var ownerID string
	require.NoError(t, db.QueryRow(
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id`,
		teamIDStr, ownerEmail,
	).Scan(&ownerID))
	team, err := models.GetTeamByID(context.Background(), db, teamID)
	require.NoError(t, err)

	deps := handlers.BVRequestDeletionDeps{DB: db, TTLMinutes: 15}
	noop := func(ctx context.Context, p *models.PendingDeletion) error { return nil }

	t.Run("missing_token_400", func(t *testing.T) {
		code := bvInvoke(t, func(c *fiber.Ctx) error {
			return handlers.BVResolveEmailConfirmedDeletion(c, deps, team, "  ", noop)
		})
		assert.Equal(t, fiber.StatusBadRequest, code)
	})

	t.Run("token_not_found_410", func(t *testing.T) {
		code := bvInvoke(t, func(c *fiber.Ctx) error {
			return handlers.BVResolveEmailConfirmedDeletion(c, deps, team, "no-such-token", noop)
		})
		assert.Equal(t, fiber.StatusGone, code)
	})

	mkPending := func(t *testing.T, tID uuid.UUID) (uuid.UUID, string) {
		t.Helper()
		rID := uuid.New()
		_, plaintext, cerr := models.CreatePendingDeletion(
			context.Background(), db, rID, models.PendingDeletionResourceDeploy,
			tID, uuid.MustParse(ownerID), ownerEmail, 15*time.Minute)
		require.NoError(t, cerr)
		return rID, plaintext
	}

	t.Run("cross_team_410", func(t *testing.T) {
		_, tok := mkPending(t, teamID)
		otherTeamStr := testhelpers.MustCreateTeamDB(t, db, "pro")
		otherTeam, _ := models.GetTeamByID(context.Background(), db, uuid.MustParse(otherTeamStr))
		code := bvInvoke(t, func(c *fiber.Ctx) error {
			return handlers.BVResolveEmailConfirmedDeletion(c, deps, otherTeam, tok, noop)
		})
		assert.Equal(t, fiber.StatusGone, code)
	})

	t.Run("success_200_then_replay_410", func(t *testing.T) {
		_, tok := mkPending(t, teamID)
		called := 0
		code := bvInvoke(t, func(c *fiber.Ctx) error {
			return handlers.BVResolveEmailConfirmedDeletion(c, deps, team, tok, func(ctx context.Context, p *models.PendingDeletion) error {
				called++
				return nil
			})
		})
		assert.Equal(t, fiber.StatusOK, code)
		assert.Equal(t, 1, called)
		code = bvInvoke(t, func(c *fiber.Ctx) error {
			return handlers.BVResolveEmailConfirmedDeletion(c, deps, team, tok, noop)
		})
		assert.Equal(t, fiber.StatusGone, code)
	})

	t.Run("teardown_failure_still_200_pending", func(t *testing.T) {
		_, tok := mkPending(t, teamID)
		code := bvInvoke(t, func(c *fiber.Ctx) error {
			return handlers.BVResolveEmailConfirmedDeletion(c, deps, team, tok, func(ctx context.Context, p *models.PendingDeletion) error {
				return errors.New("provider teardown boom")
			})
		})
		assert.Equal(t, fiber.StatusOK, code)
	})
}

func TestDeletionConfirm_CancelFlow_bvwave(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	ownerEmail := testhelpers.UniqueEmail(t)
	var ownerID string
	require.NoError(t, db.QueryRow(
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id`,
		teamIDStr, ownerEmail,
	).Scan(&ownerID))
	team, err := models.GetTeamByID(context.Background(), db, teamID)
	require.NoError(t, err)
	deps := handlers.BVRequestDeletionDeps{DB: db, TTLMinutes: 15}

	t.Run("no_pending_404", func(t *testing.T) {
		code := bvInvoke(t, func(c *fiber.Ctx) error {
			return handlers.BVCancelEmailConfirmedDeletion(c, deps, team, uuid.New(), models.PendingDeletionResourceDeploy)
		})
		assert.Equal(t, fiber.StatusNotFound, code)
	})

	t.Run("success_200_then_resolved", func(t *testing.T) {
		rID := uuid.New()
		_, _, cerr := models.CreatePendingDeletion(
			context.Background(), db, rID, models.PendingDeletionResourceDeploy,
			teamID, uuid.MustParse(ownerID), ownerEmail, 15*time.Minute)
		require.NoError(t, cerr)
		code := bvInvoke(t, func(c *fiber.Ctx) error {
			return handlers.BVCancelEmailConfirmedDeletion(c, deps, team, rID, models.PendingDeletionResourceDeploy)
		})
		assert.Equal(t, fiber.StatusOK, code)
		code = bvInvoke(t, func(c *fiber.Ctx) error {
			return handlers.BVCancelEmailConfirmedDeletion(c, deps, team, rID, models.PendingDeletionResourceDeploy)
		})
		assert.Contains(t, []int{fiber.StatusGone, fiber.StatusNotFound}, code)
	})

	t.Run("cross_team_404", func(t *testing.T) {
		rID := uuid.New()
		_, _, cerr := models.CreatePendingDeletion(
			context.Background(), db, rID, models.PendingDeletionResourceStack,
			teamID, uuid.MustParse(ownerID), ownerEmail, 15*time.Minute)
		require.NoError(t, cerr)
		otherTeamStr := testhelpers.MustCreateTeamDB(t, db, "pro")
		otherTeam, _ := models.GetTeamByID(context.Background(), db, uuid.MustParse(otherTeamStr))
		code := bvInvoke(t, func(c *fiber.Ctx) error {
			return handlers.BVCancelEmailConfirmedDeletion(c, deps, otherTeam, rID, models.PendingDeletionResourceStack)
		})
		assert.Equal(t, fiber.StatusNotFound, code)
	})
}
