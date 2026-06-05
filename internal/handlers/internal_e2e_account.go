package handlers

// internal_e2e_account.go — the CI-only guarded ephemeral-test-account surface.
//
//   POST   /internal/e2e/account            → mint a real test-cohort account
//   DELETE /internal/e2e/account/:team_id    → reap a test-cohort account
//
// WHY THIS EXISTS
//
// CI runs integration tests against PRODUCTION. To do that without polluting
// the real funnel / billing / email surfaces, it mints a *real* account whose
// owning team carries is_test_cohort=true (migration 067) — the single flag
// every background job + funnel/billing path keys off to no-op for synthetic
// traffic — runs the tests, then reaps the account. These two endpoints are
// that mint/reap lifecycle.
//
// SECURITY POSTURE (get the guard exactly right — this is security-sensitive)
//
//  1. Both routes are guarded by the X-E2E-Token header, constant-time-compared
//     (crypto/subtle) against cfg.E2EAccountToken.
//  2. INERT BY DEFAULT: when cfg.E2EAccountToken is empty, OR the header does
//     not match, BOTH routes return 404 — NOT 401/403. A 404 hides the
//     endpoint's existence; a 401/403 would confirm "there is a guarded route
//     here, keep guessing the token". The endpoint cannot mint or reap a
//     single account until an operator wires E2E_ACCOUNT_TOKEN, so the surface
//     ships safe-by-default and is only armed in CI/prod where the secret is set.
//  3. NEVER mint a team-tier (or growth) account — Team is gated until fully
//     built (project_team_plan_not_rolled_out). tier="team"/"growth" → 400.
//  4. Reap can NEVER delete a real team: the handler looks up is_test_cohort
//     and 403s (`not_test_cohort`) on any non-cohort team. This is the critical
//     safety invariant — a CI bug that passes a real team's id must bounce off
//     a 403, never destroy customer data.
//  5. Per-token rate limit (fail-open per CLAUDE.md rule 1): a leaked/abused
//     token can't be used to mint accounts without bound.
//
// The session JWT is minted with the SAME signer the customer auth path uses
// (cfg.JWTSecret + the sessionClaims shape), so the returned token authenticates
// through the ordinary RequireAuth middleware — that is the whole point: CI uses
// it as a normal Bearer. TTL is short (1h) so a captured token expires quickly.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"instant.dev/internal/config"
	"instant.dev/internal/metrics"
	"instant.dev/internal/models"
)

const (
	// e2eAccountTokenHeader is the request header carrying the guard secret.
	e2eAccountTokenHeader = "X-E2E-Token"

	// e2eSessionTTL is how long the minted session JWT is valid. Short on
	// purpose — CI runs a test suite in minutes; a captured token must not
	// outlive the run by long. Independent of the 24h customer-session TTL.
	e2eSessionTTL = 1 * time.Hour

	// e2eMetricOpCreate / e2eMetricOpReap label the instant_e2e_account_total
	// metric's `op` dimension.
	e2eMetricOpCreate = "create"
	e2eMetricOpReap   = "reap"

	// instant_e2e_account_total `result` label values.
	e2eResultOK            = "ok"
	e2eResultUnauthorized  = "unauthorized"
	e2eResultBadRequest    = "bad_request"
	e2eResultNotTestCohort = "not_test_cohort"
	e2eResultRateLimited   = "rate_limited"
	e2eResultError         = "error"

	// e2eAccountEmailDomain is the domain of the synthetic primary-user email.
	// Always @instanode.dev so the address is in-domain (matches the
	// synthetic-cohort convention) but the e2e-cohort+ local part marks it as
	// machine-minted. The +<random> suffix keeps each mint unique under the
	// users unique-email constraint.
	e2eAccountEmailDomain = "instanode.dev"

	// e2eRateLimitMax / e2eRateLimitWindow bound how many accounts a single
	// token may mint+reap per window. Generous enough for a parallel CI matrix,
	// tight enough that a leaked token can't be used to mint unbounded accounts.
	e2eRateLimitMax    = 120
	e2eRateLimitWindow = 1 * time.Hour
)

// e2eDefaultTier is the tier a request lands on when it omits `tier`.
const e2eDefaultTier = "free"

// e2eAllowedTiers is the closed set of tiers the e2e mint will accept.
// team + growth are deliberately ABSENT — Team is gated (must not be
// minted/charged until fully built) and growth shares that "don't mint a
// high/unlimited tier from CI" caution. anonymous is allowed for completeness
// (CI may want to exercise the anon path) but still gets a real team row +
// is_test_cohort so the reap path is uniform.
var e2eAllowedTiers = map[string]bool{
	"anonymous":  true,
	"free":       true,
	"hobby":      true,
	"hobby_plus": true,
	"pro":        true,
}

// e2eBlockedTiers names the tiers we explicitly reject with a tailored message
// (vs an unknown-tier reject) so CI gets an actionable 400.
var e2eBlockedTiers = map[string]bool{
	"team":   true,
	"growth": true,
}

// E2EAccountHandler wires the dependencies the mint/reap endpoints need.
type E2EAccountHandler struct {
	db  *sql.DB
	rdb *redis.Client
	cfg *config.Config
}

// NewE2EAccountHandler constructs the handler. rdb may be nil — the per-token
// rate limit then fails open (no limiting) per CLAUDE.md rule 1, exactly like
// every other Redis-gated check in this codebase.
func NewE2EAccountHandler(db *sql.DB, rdb *redis.Client, cfg *config.Config) *E2EAccountHandler {
	return &E2EAccountHandler{db: db, rdb: rdb, cfg: cfg}
}

// e2eCreateRequest is the POST body. All fields optional.
type e2eCreateRequest struct {
	Tier string `json:"tier"`
	Env  string `json:"env"`
	// WithResources, when true, pre-seeds a small set of FAST resources on the
	// minted team so a CI journey can start from a populated account (a list
	// has rows, a detail page resolves, a delete-then-replace flow has
	// something to delete) without first having to drive a provision.
	//
	// Deliberately minimal + fast: it seeds ONLY row-only resources that need
	// no backend RPC (a webhook receiver + a cache row), inserted directly as
	// active rows at the team's tier. It does NOT provision a dedicated
	// Postgres / Mongo (those are slow and need the provisioner + hot-pool) —
	// a journey that needs those drives the real provision endpoint with the
	// forceAnon hot-pool headers. The seeded rows carry the team's tier
	// snapshot, exactly like a real provision under that tier, and are reaped
	// with the team (team_id→NULL + marked-for-reaper) by ReapAccount.
	WithResources bool `json:"with_resources"`
}

// e2eSeedResourceTypes is the closed set of FAST, row-only resource types the
// with_resources pre-seed creates. Both need no backend provision RPC, so the
// seed is synchronous + sub-millisecond — safe inside the mint request.
// Iterated (not hand-listed at the call site) so adding a type here
// automatically expands what the seed creates AND what the seed test asserts.
var e2eSeedResourceTypes = []string{"webhook", "cache"}

// authorize runs the X-E2E-Token guard. It returns true iff the token is
// configured AND the header matches in constant time. On any failure it has
// ALREADY written the 404 response and bumped the unauthorized metric — the
// caller just returns the error. The 404 (not 401/403) is the existence-hiding
// posture; see the file header.
func (h *E2EAccountHandler) authorize(c *fiber.Ctx, op string) bool {
	want := ""
	if h.cfg != nil {
		want = strings.TrimSpace(h.cfg.E2EAccountToken)
	}
	got := strings.TrimSpace(c.Get(e2eAccountTokenHeader))

	// Inert-by-default: empty configured token → the surface does not exist.
	// We still run the constant-time compare against a non-empty `got` to keep
	// the timing identical to the "configured but wrong" case, but a missing
	// configured secret can never authorize.
	authorized := want != "" &&
		subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1

	if !authorized {
		metrics.E2EAccountTotal.WithLabelValues(op, e2eResultUnauthorized).Inc()
		// 404, not 401/403 — hide the route. No error body detail that could
		// confirm the route's shape.
		slog.Debug("internal.e2e.unauthorized", "op", op, "token_configured", want != "")
		_ = c.SendStatus(fiber.StatusNotFound)
		return false
	}
	return true
}

// CreateAccount handles POST /internal/e2e/account.
func (h *E2EAccountHandler) CreateAccount(c *fiber.Ctx) error {
	if !h.authorize(c, e2eMetricOpCreate) {
		return nil
	}

	// Per-token rate limit (fail-open). Keyed on the token hash so the Redis
	// key never contains the secret in plaintext.
	if limited := h.rateLimited(c.Context(), c.Get(e2eAccountTokenHeader)); limited {
		metrics.E2EAccountTotal.WithLabelValues(e2eMetricOpCreate, e2eResultRateLimited).Inc()
		return respondError(c, fiber.StatusTooManyRequests, "rate_limited",
			"e2e account mint rate limit exceeded for this token")
	}

	var req e2eCreateRequest
	// A missing/empty body is fine — both fields default. Only a malformed
	// (non-JSON) body is a 400. Fiber's BodyParser tolerates an empty body.
	if len(c.Body()) > 0 {
		if err := c.BodyParser(&req); err != nil {
			metrics.E2EAccountTotal.WithLabelValues(e2eMetricOpCreate, e2eResultBadRequest).Inc()
			return respondError(c, fiber.StatusBadRequest, "invalid_body", "JSON body required")
		}
	}

	tier := strings.TrimSpace(strings.ToLower(req.Tier))
	if tier == "" {
		tier = e2eDefaultTier
	}
	if e2eBlockedTiers[tier] {
		metrics.E2EAccountTotal.WithLabelValues(e2eMetricOpCreate, e2eResultBadRequest).Inc()
		return respondError(c, fiber.StatusBadRequest, "tier_not_allowed",
			fmt.Sprintf("tier %q cannot be minted via the e2e surface (Team/Growth are gated)", tier))
	}
	if !e2eAllowedTiers[tier] {
		metrics.E2EAccountTotal.WithLabelValues(e2eMetricOpCreate, e2eResultBadRequest).Inc()
		return respondError(c, fiber.StatusBadRequest, "invalid_tier",
			fmt.Sprintf("tier must be one of anonymous|free|hobby|hobby_plus|pro (got %q)", tier))
	}

	env := strings.TrimSpace(req.Env)

	ctx := c.Context()

	// 1. Create the team as is_test_cohort=true in a single INSERT — there is
	//    never a window where this looks like a real chargeable team.
	teamName := "e2e-cohort-" + time.Now().UTC().Format("20060102T150405")
	team, err := models.CreateTestCohortTeam(ctx, h.db, teamName)
	if err != nil {
		metrics.E2EAccountTotal.WithLabelValues(e2eMetricOpCreate, e2eResultError).Inc()
		slog.Error("internal.e2e.create.team_failed", "error", err)
		return respondError(c, fiber.StatusServiceUnavailable, "team_create_failed", "failed to create test team")
	}

	// 2. Create the primary user with a unique synthetic email, then mark it
	//    verified (CI needs a verified primary so the account behaves like a
	//    real logged-in user).
	rnd, err := e2eRandomSuffix()
	if err != nil {
		metrics.E2EAccountTotal.WithLabelValues(e2eMetricOpCreate, e2eResultError).Inc()
		slog.Error("internal.e2e.create.rand_failed", "error", err)
		return respondError(c, fiber.StatusServiceUnavailable, "rand_failed", "failed to generate account id")
	}
	email := fmt.Sprintf("e2e-cohort+%s@%s", rnd, e2eAccountEmailDomain)
	user, err := models.CreateUser(ctx, h.db, team.ID, email, "", "", "owner")
	if err != nil {
		metrics.E2EAccountTotal.WithLabelValues(e2eMetricOpCreate, e2eResultError).Inc()
		slog.Error("internal.e2e.create.user_failed", "error", err, "team_id", team.ID.String())
		return respondError(c, fiber.StatusServiceUnavailable, "user_create_failed", "failed to create test user")
	}
	if verr := models.SetEmailVerified(ctx, h.db, user.ID); verr != nil {
		// Best-effort: a verify-flip failure must not abort the mint — but log it.
		slog.Warn("internal.e2e.create.verify_failed", "error", verr, "user_id", user.ID.String())
	} else {
		user.EmailVerified = true
	}

	// 3. Set the requested tier via the authoritative upgrade path (the same
	//    one the Razorpay webhook + /internal/set-tier use). anonymous/free
	//    are already the team's tier (CreateTestCohortTeam starts at 'free'),
	//    so only escalate for paid tiers. We never call this for team/growth —
	//    those are rejected above.
	if tier != "free" && tier != "anonymous" {
		if uerr := models.UpgradeTeamAllTiers(ctx, h.db, team.ID, tier); uerr != nil {
			metrics.E2EAccountTotal.WithLabelValues(e2eMetricOpCreate, e2eResultError).Inc()
			slog.Error("internal.e2e.create.tier_failed", "error", uerr, "team_id", team.ID.String(), "tier", tier)
			return respondError(c, fiber.StatusServiceUnavailable, "tier_set_failed", "failed to set tier")
		}
		team.PlanTier = tier
	} else {
		team.PlanTier = tier
	}

	// 3b. Optionally pre-seed a small set of FAST resources so the journey can
	//     start from a populated account. Synchronous (row-only inserts, no
	//     backend RPC) and tier-snapshotted at the team's tier. A seed failure
	//     is a hard error — CI asked for a populated account and got a partial
	//     one, which would make the journey flaky; better to fail the mint
	//     loudly. The rows are reaped with the team.
	var seededTokens []string
	if req.WithResources {
		toks, serr := e2eSeedFastResources(h, ctx, team.ID, tier, env)
		if serr != nil {
			metrics.E2EAccountTotal.WithLabelValues(e2eMetricOpCreate, e2eResultError).Inc()
			slog.Error("internal.e2e.create.seed_failed", "error", serr, "team_id", team.ID.String())
			return respondError(c, fiber.StatusServiceUnavailable, "seed_failed", "failed to seed resources")
		}
		seededTokens = toks
	}

	// 4. Mint the session JWT with the SAME signer + claim shape the customer
	//    auth path uses, so it authenticates through ordinary RequireAuth.
	expiresAt := time.Now().UTC().Add(e2eSessionTTL)
	sessionJWT, err := e2eSignSessionJWT(h.cfg.JWTSecret, user.ID, team.ID, email, expiresAt)
	if err != nil {
		metrics.E2EAccountTotal.WithLabelValues(e2eMetricOpCreate, e2eResultError).Inc()
		slog.Error("internal.e2e.create.jwt_failed", "error", err, "team_id", team.ID.String())
		return respondError(c, fiber.StatusServiceUnavailable, "token_issue_failed", "failed to issue session token")
	}

	// 5. Audit it. Best-effort, in-request so CI can read it back if needed.
	meta, _ := json.Marshal(map[string]any{
		"tier":    tier,
		"env":     env,
		"user_id": user.ID.String(),
		"email":   email,
	})
	if aerr := models.InsertAuditEvent(ctx, h.db, models.AuditEvent{
		TeamID:   team.ID,
		UserID:   uuid.NullUUID{UUID: user.ID, Valid: true},
		Actor:    "system",
		Kind:     models.AuditKindE2EAccountCreated,
		Summary:  fmt.Sprintf("minted e2e test-cohort account (tier=%s)", tier),
		Metadata: meta,
	}); aerr != nil {
		slog.Warn("internal.e2e.create.audit_failed", "error", aerr, "team_id", team.ID.String())
	}

	metrics.E2EAccountTotal.WithLabelValues(e2eMetricOpCreate, e2eResultOK).Inc()
	slog.Info("internal.e2e.create.done", "team_id", team.ID.String(), "tier", tier, "env", env)

	// seededTokens is always present in the response (empty array when
	// with_resources was false) so a CI caller can branch on its length
	// without a nil check.
	if seededTokens == nil {
		seededTokens = []string{}
	}
	return c.JSON(fiber.Map{
		"team_id":       team.ID.String(),
		"user_id":       user.ID.String(),
		"email":         email,
		"tier":          tier,
		"session_jwt":   sessionJWT,
		"expires_at":    expiresAt.Format(time.RFC3339),
		"seeded_tokens": seededTokens,
		"seeded_count":  len(seededTokens),
	})
}

// seedFastResources pre-seeds the with_resources set: one active row per
// e2eSeedResourceTypes entry, owned by teamID, tier-snapshotted at `tier`,
// scoped to `env` (empty → the model's EnvDefault). Returns the seeded tokens.
//
// Each row is created with CreateResource (status=pending) then flipped to
// active via MarkResourceActive — the SAME two-phase lifecycle a real
// provision uses — so the seeded rows are indistinguishable from a normal
// provision under that tier for any read path (list/detail/limits). No backend
// RPC is issued: these types are row-only (a webhook receiver lives in Redis,
// a cache row needs no dedicated infra to satisfy a list/detail journey), so
// the seed is fast and synchronous. Any error aborts (returns it) — the caller
// turns it into a 503 so CI never receives a half-populated account.
//
// A package-var seam (not a direct method call) so a test can force the
// caller's seed_failed (503) arm without needing to make the real resources
// table reject an insert mid-request.
var e2eSeedFastResources = (*E2EAccountHandler).seedFastResources

func (h *E2EAccountHandler) seedFastResources(ctx context.Context, teamID uuid.UUID, tier, env string) ([]string, error) {
	tokens := make([]string, 0, len(e2eSeedResourceTypes))
	for _, rt := range e2eSeedResourceTypes {
		res, err := models.CreateResource(ctx, h.db, models.CreateResourceParams{
			TeamID:       &teamID,
			ResourceType: rt,
			Tier:         tier,
			Env:          env,
		})
		if err != nil {
			return nil, fmt.Errorf("seed %s: %w", rt, err)
		}
		if err := models.MarkResourceActive(ctx, h.db, res.ID); err != nil {
			return nil, fmt.Errorf("activate seeded %s: %w", rt, err)
		}
		tokens = append(tokens, res.Token.String())
	}
	return tokens, nil
}

// ReapAccount handles DELETE /internal/e2e/account/:team_id.
func (h *E2EAccountHandler) ReapAccount(c *fiber.Ctx) error {
	if !h.authorize(c, e2eMetricOpReap) {
		return nil
	}

	teamID, err := uuid.Parse(strings.TrimSpace(c.Params("team_id")))
	if err != nil {
		metrics.E2EAccountTotal.WithLabelValues(e2eMetricOpReap, e2eResultBadRequest).Inc()
		return respondError(c, fiber.StatusBadRequest, "invalid_team_id", "team_id must be a UUID")
	}

	ctx := c.Context()

	// Look up the team. Idempotency: an already-gone team is a clean 200 (the
	// reaper / a previous DELETE already removed it). We treat ErrTeamNotFound
	// as success rather than 404 so a CI retry never sees a spurious failure.
	team, err := models.GetTeamByID(ctx, h.db, teamID)
	if err != nil {
		var notFound *models.ErrTeamNotFound
		if errors.As(err, &notFound) {
			metrics.E2EAccountTotal.WithLabelValues(e2eMetricOpReap, e2eResultOK).Inc()
			slog.Info("internal.e2e.reap.already_gone", "team_id", teamID.String())
			return c.JSON(fiber.Map{"ok": true, "team_id": teamID.String(), "already_gone": true})
		}
		metrics.E2EAccountTotal.WithLabelValues(e2eMetricOpReap, e2eResultError).Inc()
		slog.Error("internal.e2e.reap.lookup_failed", "error", err, "team_id", teamID.String())
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "failed to load team")
	}

	// CRITICAL SAFETY GATE: never delete a real team. If the team is NOT in the
	// test cohort, refuse with 403 — this is the invariant that makes the whole
	// surface safe to expose against production.
	isCohort, err := models.IsTestCohort(ctx, h.db, teamID)
	if err != nil {
		metrics.E2EAccountTotal.WithLabelValues(e2eMetricOpReap, e2eResultError).Inc()
		slog.Error("internal.e2e.reap.cohort_check_failed", "error", err, "team_id", teamID.String())
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "failed to check team cohort")
	}
	if !isCohort {
		metrics.E2EAccountTotal.WithLabelValues(e2eMetricOpReap, e2eResultNotTestCohort).Inc()
		slog.Warn("internal.e2e.reap.refused_non_cohort", "team_id", teamID.String(), "plan_tier", team.PlanTier)
		return respondError(c, fiber.StatusForbidden, "not_test_cohort",
			"refusing to delete a non-test-cohort team")
	}

	// Mark every resource for the worker's TTL reaper (tier=free + expires_at=now)
	// so the real backing infra (customer DB / cache / mongo / etc.) is
	// deprovisioned even for paid-tier test accounts. Then hard-delete the team
	// (cascades audit_log/deployments/stacks/users; resources go team_id→NULL,
	// already marked reapable).
	marked, err := models.MarkTeamResourcesForReaper(ctx, h.db, teamID)
	if err != nil {
		metrics.E2EAccountTotal.WithLabelValues(e2eMetricOpReap, e2eResultError).Inc()
		slog.Error("internal.e2e.reap.mark_resources_failed", "error", err, "team_id", teamID.String())
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "failed to mark resources for reaper")
	}

	// Emit the reap audit BEFORE the DELETE — the DELETE cascades audit_log,
	// so a row written after the delete would have no team to reference (and a
	// row written for a not-yet-deleted team is the honest record of intent).
	meta, _ := json.Marshal(map[string]any{"resources_marked_for_reaper": marked})
	if aerr := models.InsertAuditEvent(ctx, h.db, models.AuditEvent{
		TeamID:   teamID,
		Actor:    "system",
		Kind:     models.AuditKindE2EAccountReaped,
		Summary:  fmt.Sprintf("reaped e2e test-cohort account (%d resources marked for reaper)", marked),
		Metadata: meta,
	}); aerr != nil {
		slog.Warn("internal.e2e.reap.audit_failed", "error", aerr, "team_id", teamID.String())
	}

	deleted, err := models.DeleteTeamHard(ctx, h.db, teamID)
	if err != nil {
		metrics.E2EAccountTotal.WithLabelValues(e2eMetricOpReap, e2eResultError).Inc()
		slog.Error("internal.e2e.reap.delete_failed", "error", err, "team_id", teamID.String())
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "failed to delete team")
	}

	metrics.E2EAccountTotal.WithLabelValues(e2eMetricOpReap, e2eResultOK).Inc()
	slog.Info("internal.e2e.reap.done",
		"team_id", teamID.String(),
		"resources_marked", marked,
		"team_deleted", deleted,
	)
	return c.JSON(fiber.Map{
		"ok":                          true,
		"team_id":                     teamID.String(),
		"resources_marked_for_reaper": marked,
		"team_deleted":                deleted,
	})
}

// rateLimited applies a per-token sliding-window limit. Fails OPEN (returns
// false = not limited) on any Redis error or nil client — per CLAUDE.md rule 1,
// a Redis outage must never block CI's mint path. The Redis key is keyed on the
// SHA-256 of the token so the plaintext secret is never written to Redis.
func (h *E2EAccountHandler) rateLimited(ctx context.Context, token string) bool {
	if h.rdb == nil {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	key := "rl_e2e_account:" + hex.EncodeToString(sum[:])

	now := time.Now()
	cutoff := now.Add(-e2eRateLimitWindow).UnixNano()
	score := now.UnixNano()
	member := fmt.Sprintf("%d:%d", score, score%1000003)

	pipe := h.rdb.Pipeline()
	pipe.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("(%d", cutoff))
	cardCmd := pipe.ZCard(ctx, key)
	pipe.ZAdd(ctx, key, redis.Z{Score: float64(score), Member: member})
	pipe.Expire(ctx, key, e2eRateLimitWindow)
	// go-redis Pipeline.Exec returns the first command error, so a non-nil
	// Exec error already covers the ZCard-failed case — we don't re-check
	// cardCmd.Err() separately (that arm would be dead, since a nil Exec
	// guarantees every queued command succeeded). Fail OPEN on any error per
	// CLAUDE.md rule 1: a Redis outage must never block CI's mint path.
	if _, err := pipe.Exec(ctx); err != nil {
		slog.Warn("internal.e2e.rate_limit.fail_open", "error", err)
		return false
	}
	return cardCmd.Val() >= int64(e2eRateLimitMax)
}

// e2eSignSessionJWT mints a session JWT identical in shape to the one the
// customer auth path issues (sessionClaims signed HS256 with cfg.JWTSecret +
// the canonical audience), but with a caller-supplied (short) expiry. Reusing
// sessionClaims is the point — the token authenticates through the same
// middleware path as a real login.
//
// A package var (not a plain func) so tests can inject a signing failure to
// exercise the token_issue_failed arm — HS256 over a []byte key never errors
// in practice, so without a seam that defensive 503 branch is untestable.
var e2eSignSessionJWT = e2eSignSessionJWTImpl

func e2eSignSessionJWTImpl(jwtSecret string, userID, teamID uuid.UUID, email string, expiresAt time.Time) (string, error) {
	now := time.Now().UTC()
	claims := sessionClaims{
		UserID: userID.String(),
		TeamID: teamID.String(),
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			Audience:  jwt.ClaimStrings{sessionAudience()},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

// e2eRandomSuffix returns a short crypto-random hex string for the synthetic
// email's +tag, keeping each minted account's primary email unique under the
// users unique-email constraint.
func e2eRandomSuffix() (string, error) {
	b := make([]byte, 8)
	if _, err := randRead(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
