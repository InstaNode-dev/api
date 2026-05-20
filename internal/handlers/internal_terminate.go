package handlers

// internal_terminate.go — POST /internal/teams/:id/terminate.
//
// Called by the worker's payment_grace_terminator dispatcher when a
// team's 7-day Razorpay-failure grace window has expired. The worker
// HTTP-POSTs to this endpoint with a short-lived HS256 JWT signed by
// WORKER_INTERNAL_JWT_SECRET; this handler verifies the signature,
// pauses every active resource, marks the dunning row(s) terminated,
// downgrades the team's plan_tier to "free", best-effort cancels the
// Razorpay subscription, and emits one `payment.grace_terminated`
// audit row.
//
// The route is NOT dev-only — it runs in production. Its security
// surface is the shared-secret HS256 JWT (separate from the
// customer-facing JWT_SECRET so a leaked session token can never reach
// this codepath). It is also NOT behind /api/v1 because internal
// machine-to-machine traffic should not flow through customer-facing
// auth (team-scoped session JWT verification).
//
// Idempotency: if a prior terminate already swept this team (worker
// retry, network blip), we detect that a terminated payment_grace_periods
// row exists and return 200 with all counts zero. No second pass over
// resources or Razorpay — the destructive work is single-shot.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"

	"instant.dev/internal/config"
	"instant.dev/internal/models"
)

// internalTerminatePurpose is the required `purpose` claim value on the
// worker-minted JWT. Mismatched / missing → 401. A literal string (not a
// shared constant with the worker) is deliberate: the api decides what
// it accepts, the worker must match this exact value when signing.
const internalTerminatePurpose = "internal_terminate"

// internalTerminateMaxClockSkew is the maximum age (and future-skew) of
// the `iat` claim the handler accepts. 60s matches the brief and is
// tight enough that a captured/replayed JWT can't terminate teams
// indefinitely, but loose enough to absorb sub-minute clock drift
// between the worker pod and the api pod.
const internalTerminateMaxClockSkew = 60 * time.Second

// internalTerminateClaims is the worker-minted JWT shape. We require
// all four fields; any missing → 401.
type internalTerminateClaims struct {
	Purpose string `json:"purpose"`
	TeamID  string `json:"team_id"`
	jwt.RegisteredClaims
}

// InternalTerminateHandler wires the dependencies the terminate
// endpoint needs. Constructed once in router.go; the handler closure
// captures it.
type InternalTerminateHandler struct {
	db                 *sql.DB
	cfg                *config.Config
	cancelSubscription func(subscriptionID string) error
}

// NewInternalTerminateHandler constructs the handler. cancelFn may be
// nil — in that case the Razorpay cancel step is skipped and
// razorpay_canceled in the response stays false. router.go injects a
// closure over razorpaybilling.Portal.CancelAtCycleEnd; tests can pass
// a stub or nil.
func NewInternalTerminateHandler(db *sql.DB, cfg *config.Config, cancelFn func(subscriptionID string) error) *InternalTerminateHandler {
	return &InternalTerminateHandler{
		db:                 db,
		cfg:                cfg,
		cancelSubscription: cancelFn,
	}
}

// Terminate is the fiber.Handler for POST /internal/teams/:id/terminate.
//
// Wire flow:
//  1. Parse :id, parse + verify the Bearer JWT.
//  2. Look up the team. 404 if missing.
//  3. Idempotency: if a terminated grace row already exists → return
//     200 with zero counts (no second-pass destructive work).
//  4. Pause every active resource (PauseAllTeamResources).
//  5. Mark every active dunning row 'terminated'.
//  6. Downgrade plan_tier to "free".
//  7. Best-effort: cancel the Razorpay subscription (log + continue on
//     error, mirroring the dashboard cancel path).
//  8. Emit one `payment.grace_terminated` audit row.
//  9. Return 200 JSON.
func (h *InternalTerminateHandler) Terminate(c *fiber.Ctx) error {
	pathID := strings.TrimSpace(c.Params("id"))
	teamID, err := uuid.Parse(pathID)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_team_id", "team_id must be a UUID")
	}

	// Auth: HS256 JWT bound to the configured worker secret. When the
	// secret is unset, EVERY call 401s — operators must wire
	// WORKER_INTERNAL_JWT_SECRET into the api's k8s Secret to enable
	// the route. This is the fail-closed default.
	if h.cfg == nil || strings.TrimSpace(h.cfg.WorkerInternalJWTSecret) == "" {
		slog.Warn("internal.terminate.secret_unset",
			"path_team_id", pathID,
			"reason", "WORKER_INTERNAL_JWT_SECRET is empty; rejecting all calls",
		)
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "worker internal auth not configured")
	}
	if err := verifyInternalTerminateJWT(c, h.cfg.WorkerInternalJWTSecret, teamID); err != nil {
		// verifyInternalTerminateJWT logs the structured reason; the
		// caller only ever sees a generic 401 so this route emits no
		// signal a probe could use to refine an attack.
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "invalid worker token")
	}

	ctx := c.Context()

	// 2. Team lookup. ErrTeamNotFound → 404. Any other DB error → 503.
	team, err := models.GetTeamByID(ctx, h.db, teamID)
	if err != nil {
		var notFound *models.ErrTeamNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "team_not_found", "team not found")
		}
		slog.Error("internal.terminate.team_lookup_failed", "error", err, "team_id", teamID.String())
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "failed to load team")
	}

	// 3. Idempotency. A prior terminate left a terminated grace row;
	// a second call must not re-pause resources or re-cancel Razorpay.
	// We surface zero counts so the worker can tell "first-call" from
	// "redelivery" without losing the 200 result.
	terminatedAlready, err := models.HasTerminatedPaymentGracePeriod(ctx, h.db, teamID)
	if err != nil {
		slog.Error("internal.terminate.idempotency_check_failed", "error", err, "team_id", teamID.String())
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "failed to check termination state")
	}
	if terminatedAlready {
		slog.Info("internal.terminate.idempotent_noop",
			"team_id", teamID.String(),
			"plan_tier", team.PlanTier,
		)
		return c.JSON(fiber.Map{
			"ok":                      true,
			"team_id":                 teamID.String(),
			"paused_resource_count":   0,
			"dunning_rows_terminated": 0,
			"razorpay_canceled":       false,
			"already_terminated":      true,
		})
	}

	// 4. Pause every active resource. Errors here are fatal — the
	// rest of the termination assumes resources are no longer
	// serving traffic.
	pausedCount, err := models.PauseAllTeamResources(ctx, h.db, teamID)
	if err != nil {
		slog.Error("internal.terminate.pause_resources_failed", "error", err, "team_id", teamID.String())
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "failed to pause team resources")
	}

	// 5. Mark every active dunning row terminated. Returns 0 when
	// the team never entered grace (which would be unusual for this
	// codepath — the worker only POSTs after a grace expiry sweep —
	// but we don't gate on it; an admin-initiated termination is a
	// valid future use case).
	dunningTerminated, err := models.TerminateAllPaymentGracePeriodsForTeam(ctx, h.db, teamID, time.Time{})
	if err != nil {
		slog.Error("internal.terminate.dunning_terminate_failed", "error", err, "team_id", teamID.String())
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "failed to terminate dunning rows")
	}

	// 6. Downgrade plan_tier to "free" — the post-paid-failure
	// baseline. "anonymous" would be wrong (that's only for
	// pre-claim resources without a team). The team retains its
	// users + audit history; only the paid entitlements are gone.
	if err := models.UpdatePlanTier(ctx, h.db, teamID, "free"); err != nil {
		slog.Error("internal.terminate.downgrade_failed", "error", err, "team_id", teamID.String())
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "failed to downgrade plan tier")
	}

	// 7. Best-effort Razorpay cancel. Failure here is logged but
	// does NOT fail the request — the customer's resources are
	// already paused and tier downgraded; an operator can reconcile
	// the orphan Razorpay subscription out-of-band via the dashboard.
	// razorpay_canceled in the response tells the worker whether the
	// out-of-band call succeeded.
	razorpayCanceled := false
	razorpayError := ""
	if team.RazorpaySubscriptionID.Valid && strings.TrimSpace(team.RazorpaySubscriptionID.String) != "" {
		if h.cancelSubscription == nil {
			razorpayError = "subscription_canceler_not_configured"
			slog.Warn("internal.terminate.razorpay_skipped",
				"team_id", teamID.String(),
				"subscription_id", team.RazorpaySubscriptionID.String,
				"reason", razorpayError,
			)
		} else {
			subID := strings.TrimSpace(team.RazorpaySubscriptionID.String)
			if err := h.cancelSubscription(subID); err != nil {
				razorpayError = err.Error()
				slog.Warn("internal.terminate.razorpay_cancel_failed",
					"error", err,
					"team_id", teamID.String(),
					"subscription_id", subID,
				)
			} else {
				razorpayCanceled = true
			}
		}
	}

	// 8. Audit-row emit. payment.grace_terminated is the canonical
	// kind for this event (already shipped in PR #66's audit_kinds.go).
	// We run it in the request context (not a goroutine) because
	// correctness matters more than the few ms saved — the worker
	// reads this row to confirm the termination completed.
	meta := internalTerminateAuditMetadata{
		PausedResourceCount:   pausedCount,
		DunningRowsTerminated: dunningTerminated,
		PreviousPlanTier:      team.PlanTier,
		RazorpayCanceled:      razorpayCanceled,
		RazorpayError:         razorpayError,
	}
	metaJSON, _ := json.Marshal(meta)
	auditErr := models.InsertAuditEvent(ctx, h.db, models.AuditEvent{
		TeamID:   teamID,
		Actor:    "system",
		Kind:     models.AuditKindPaymentGraceTerminated,
		Summary:  fmt.Sprintf("payment grace expired; paused %d resources and downgraded to free", pausedCount),
		Metadata: metaJSON,
	})
	if auditErr != nil {
		slog.Warn("internal.terminate.audit_emit_failed", "error", auditErr, "team_id", teamID.String())
	}

	slog.Info("internal.terminate.done",
		"team_id", teamID.String(),
		"paused_resource_count", pausedCount,
		"dunning_rows_terminated", dunningTerminated,
		"previous_plan_tier", team.PlanTier,
		"razorpay_canceled", razorpayCanceled,
	)

	return c.JSON(fiber.Map{
		"ok":                      true,
		"team_id":                 teamID.String(),
		"paused_resource_count":   pausedCount,
		"dunning_rows_terminated": dunningTerminated,
		"razorpay_canceled":       razorpayCanceled,
	})
}

// internalTerminateAuditMetadata is the JSONB payload stamped on the
// `payment.grace_terminated` audit row. Loops / Brevo / admin
// dashboards can read these fields to render "we terminated team X
// with N resources paused" — without re-querying the per-team state.
type internalTerminateAuditMetadata struct {
	PausedResourceCount   int64  `json:"paused_resource_count"`
	DunningRowsTerminated int64  `json:"dunning_rows_terminated"`
	PreviousPlanTier      string `json:"previous_plan_tier"`
	RazorpayCanceled      bool   `json:"razorpay_canceled"`
	RazorpayError         string `json:"razorpay_error,omitempty"`
}

// verifyInternalTerminateJWT parses + validates the bearer token
// against the four checks the brief enforces:
//
//  1. HS256 signed with cfg.WorkerInternalJWTSecret.
//  2. `purpose` claim equals "internal_terminate".
//  3. `iat` claim is within ±internalTerminateMaxClockSkew of now.
//  4. `team_id` claim equals the :id path param.
//
// Every rejection path logs a structured reason BEFORE returning the
// error so an operator can diagnose a misconfigured worker without the
// 401 leaking detail to the caller. The error itself is opaque on the
// wire — callers always see "invalid worker token".
func verifyInternalTerminateJWT(c *fiber.Ctx, secret string, pathTeamID uuid.UUID) error {
	authHeader := strings.TrimSpace(c.Get(fiber.HeaderAuthorization))
	if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		slog.Warn("internal.terminate.auth.missing_bearer",
			"path_team_id", pathTeamID.String(),
		)
		return errors.New("missing bearer token")
	}
	tokenStr := strings.TrimSpace(authHeader[len("Bearer "):])
	if tokenStr == "" {
		slog.Warn("internal.terminate.auth.empty_token",
			"path_team_id", pathTeamID.String(),
		)
		return errors.New("empty bearer token")
	}

	// Parse + verify signature. ParseWithClaims is the parsing entry
	// point that hands us a fully-populated claims struct iff the
	// signature is valid AND every Standard-Claims gate (exp, nbf)
	// passes. We don't set exp on the worker's tokens — the iat
	// freshness check below is the equivalent.
	claims := &internalTerminateClaims{}
	tok, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		// Pin to HS256. A token signed with a different alg (e.g.
		// "none") must NOT verify — otherwise an attacker can drop
		// the signature and impersonate any team.
		// T10 P2-1 (BugHunt 2026-05-20): the bare SigningMethodHMAC
		// type-assert also accepts HS384/HS512 — pair it with
		// jwt.WithValidMethods to truly pin HS256.
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		slog.Warn("internal.terminate.auth.parse_failed",
			"error", err,
			"path_team_id", pathTeamID.String(),
		)
		return err
	}
	if !tok.Valid {
		slog.Warn("internal.terminate.auth.token_invalid",
			"path_team_id", pathTeamID.String(),
		)
		return errors.New("token marked invalid")
	}

	// 2. purpose. Even a structurally-valid customer JWT (signed with
	// the wrong secret) would never reach this branch — but the
	// purpose claim defends against a *future* leak where the same
	// secret somehow gets reused. Defense in depth.
	if claims.Purpose != internalTerminatePurpose {
		slog.Warn("internal.terminate.auth.bad_purpose",
			"purpose", claims.Purpose,
			"expected", internalTerminatePurpose,
			"path_team_id", pathTeamID.String(),
		)
		return errors.New("purpose claim mismatch")
	}

	// 3. iat freshness. We require an iat within ±60s of now. Too
	// old → replay. Too far future → bad clock or forged. Either way
	// 401.
	if claims.IssuedAt == nil {
		slog.Warn("internal.terminate.auth.missing_iat",
			"path_team_id", pathTeamID.String(),
		)
		return errors.New("missing iat claim")
	}
	iat := claims.IssuedAt.Time
	now := time.Now()
	if iat.Before(now.Add(-internalTerminateMaxClockSkew)) {
		slog.Warn("internal.terminate.auth.iat_too_old",
			"iat", iat,
			"now", now,
			"path_team_id", pathTeamID.String(),
		)
		return errors.New("iat too old")
	}
	if iat.After(now.Add(internalTerminateMaxClockSkew)) {
		slog.Warn("internal.terminate.auth.iat_in_future",
			"iat", iat,
			"now", now,
			"path_team_id", pathTeamID.String(),
		)
		return errors.New("iat in future")
	}

	// 4. team_id match. The path :id is the source of truth — the
	// JWT claim is the assertion. A worker that issued a token for
	// team A and POSTed it to /teams/B/terminate gets 401 (no
	// cross-team rewrite). The compare is on the parsed UUID so
	// "ABC-123" vs "abc-123" can't bypass via case.
	claimTeamID, err := uuid.Parse(strings.TrimSpace(claims.TeamID))
	if err != nil {
		slog.Warn("internal.terminate.auth.bad_team_id_claim",
			"team_id_claim", claims.TeamID,
			"path_team_id", pathTeamID.String(),
			"error", err,
		)
		return errors.New("team_id claim is not a UUID")
	}
	if claimTeamID != pathTeamID {
		slog.Warn("internal.terminate.auth.team_id_mismatch",
			"team_id_claim", claimTeamID.String(),
			"path_team_id", pathTeamID.String(),
		)
		return errors.New("team_id claim/path mismatch")
	}

	return nil
}
