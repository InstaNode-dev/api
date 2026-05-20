package handlers

// provision_helper.go — shared logic for all provisioning handlers
// (POST /db/new, POST /cache/new, POST /nosql/new).
//
// Every provisioning endpoint needs:
//  1. Per-fingerprint rate limiting   (checkProvisionLimit)
//  2. Onboarding JWT issuance         (issueOnboardingJWT)
//  3. Active-resource lookup          (models.GetActiveResourceByFingerprint)
//  4. Onboarding event creation       (models.CreateOnboardingEvent)
//  5. Environment selection           (resolveEnv — see provisionRequestBody.Env)
//
// provisionHelper embeds these shared behaviours so each handler
// can embed it instead of duplicating the logic.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"instant.dev/internal/config"
	"instant.dev/internal/crypto"
	"instant.dev/internal/metrics"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/provisioner"
	"instant.dev/internal/urls"
	commonv1 "instant.dev/proto/common/v1"
)

// ─────────────────────────────────────────────────────────────────────────────
// Free-tier recycle gate (Option B from FREE-TIER-RECYCLE-2026-05-12.md)
//
// The "wedge" of instanode is: an agent's very first POST /db/new (or any
// /{service}/new) succeeds with zero auth and returns real credentials in
// seconds. We MUST preserve that. The abuse surface this gate closes is the
// *second* POST from the same fingerprint after the previous free-tier
// resource expired — without this gate, that path returns a fresh 24h
// anonymous resource forever, indefinitely. With this gate, the second
// (recycle) POST is required to claim with email first; the user then falls
// into the existing `free` tier in plans.yaml.
//
// Mechanics:
//   - When an anonymous provision succeeds we SET recycle_seen:<fp> with a
//     30-day TTL. (Set-after-success preserves the wedge — the first
//     anonymous POST has no key, so it can never be gated.)
//   - On every subsequent anonymous POST we read recycle_seen:<fp>. If it
//     exists AND no active anonymous resource is present for the
//     fingerprint, we return 402 free_tier_recycle_requires_claim with a
//     claim URL. The customer claims with email and gets a JWT; the JWT
//     bypasses the gate entirely (auth path skips this check).
//   - 30 days is intentional: long enough that a recycler coming back
//     "next week" is still gated, short enough that an accidental
//     fingerprint hit (e.g. someone moved offices) decays on its own.
//
// Note: the spec lists worker/internal/jobs/expire.go as the trigger, but
// setting the key on PROVISION instead of EXPIRY has identical semantics
// (the key only matters when (a) it exists and (b) no active resource is
// present — both conditions are reached the moment a previously-provisioned
// anonymous resource ages out) and keeps the gate fully inside the api
// module without cross-module coordination. This is the api-side
// implementation of Option B.
// ─────────────────────────────────────────────────────────────────────────────

// RecycleSeenKeyPrefix is the Redis key prefix recording "this fingerprint
// has provisioned anonymously before." Format: recycle_seen:<fingerprint>.
const RecycleSeenKeyPrefix = "recycle_seen:"

// RecycleSeenTTL is the lifetime of the recycle_seen marker.
const RecycleSeenTTL = 30 * 24 * time.Hour

// RecycleGateErrorCode is the stable machine-readable error code the gate
// returns. Programmatic clients should branch on this exact string.
const RecycleGateErrorCode = "free_tier_recycle_requires_claim"

// RecycleGateClaimURL is the URL the agent should send the user to in order
// to clear the gate. Both upgrade_url and claim_url fields point at it.
const RecycleGateClaimURL = "https://instanode.dev/claim"

// RecycleGateAgentAction is the verbatim sentence the calling agent surfaces
// to the human user when the gate fires. Adheres to the U3 contract
// (agent_action.go): "Tell the user" opening, specific reason
// (previous free resource expired), exact action (claim at the URL), full
// https://instanode.dev/ URL, under 280 chars.
const RecycleGateAgentAction = "Tell the user their previous free resource expired and the free tier requires a one-time email claim before re-provisioning. Have them claim at https://instanode.dev/claim — takes 30 seconds, no card."

// RecycleGateMessage is the human-readable explanation accompanying the
// machine error code.
const RecycleGateMessage = "Your previous free resource expired. " +
	"Free tier resources require a one-time email claim before provisioning a replacement."

// provisionHelper holds the shared dependencies used by every provisioning handler.
type provisionHelper struct {
	db    *sql.DB
	rdb   *redis.Client
	cfg   *config.Config
	plans *plans.Registry
}

func newProvisionHelper(db *sql.DB, rdb *redis.Client, cfg *config.Config, reg *plans.Registry) provisionHelper {
	return provisionHelper{db: db, rdb: rdb, cfg: cfg, plans: reg}
}

// startProvisionSpan creates a child span for the infrastructure provision step
// (DB/Redis/Mongo/etc.). Never records connection material — only coarse identifiers.
func (h *provisionHelper) startProvisionSpan(ctx context.Context, resourceType, tier, teamID, fingerprint, resourceToken string) (context.Context, trace.Span) {
	ctx, span := otel.Tracer("instant.dev/handlers").Start(ctx, "provision."+resourceType)
	attrs := []attribute.KeyValue{
		attribute.String("resource_type", resourceType),
		attribute.String("tier", tier),
	}
	if fingerprint != "" {
		attrs = append(attrs, attribute.String("fingerprint", fingerprint))
	}
	if teamID != "" {
		attrs = append(attrs, attribute.String("team_id", teamID))
	}
	if resourceToken != "" {
		attrs = append(attrs, attribute.String("resource.token", resourceToken))
	}
	span.SetAttributes(attrs...)
	return ctx, span
}

// finishProvisionSpan ends a provision span, optionally marking it failed.
func finishProvisionSpan(span trace.Span, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	span.End()
}

// provisionCapExpiry is the TTL on the per-fingerprint daily provision
// counter. 25h (not 24h) so a counter set just before midnight still
// covers a full UTC day and avoids a midnight thundering-herd reset.
const provisionCapExpiry = 25 * time.Hour

// provisionLimitTier is the tier whose provisions_per_day cap governs the
// anonymous provisioning path. All anonymous provisions — across every
// service type — share this single per-fingerprint daily counter.
const provisionLimitTier = "anonymous"

// overCapErrorCode is the machine-stable error code returned when an
// anonymous caller is over the per-fingerprint daily provisioning cap and
// no existing resource is available to dedup against (the burst-race case:
// the winning provisions have claimed their slots via the atomic INCR but
// have not yet committed a `resources` row). Programmatic clients branch
// on this exact string.
const overCapErrorCode = "provision_limit_reached"

// checkProvisionLimit atomically claims a per-fingerprint provisioning slot
// for the current UTC day and reports whether the daily cap is exceeded.
// The cap is shared across ALL service types.
//
// CONCURRENCY (load-test finding F2 / TOCTOU fix 2026-05-19): the gate is
// the atomic Redis INCR itself — the value INCR returns *is* the caller's
// claimed slot number. N concurrent callers from one fingerprint receive N
// distinct, monotonically-increasing slot numbers (1, 2, 3, …) with no
// interleaving, because INCR is single-threaded server-side. Callers whose
// slot number is ≤ cap are cleared to provision; callers whose slot number
// is > cap are over the cap. There is NO check-then-act window: the count
// is never read separately from the increment. Before this fix the
// downstream dedup branch *did* have a TOCTOU window — see
// denyProvisionOverCap for the second half of the fix.
//
// Returns (true, nil)  when this caller's claimed slot is over the cap.
// Returns (false, nil) when this caller's slot is within the cap.
// Returns (false, err) when Redis is unavailable; caller must fail open
//
//	(CLAUDE.md convention #6 — a Redis outage must never block provisioning).
func (h *provisionHelper) checkProvisionLimit(ctx context.Context, fp string) (bool, error) {
	date := time.Now().UTC().Format("2006-01-02")
	key := fmt.Sprintf("prov:%s:%s", fp, date)

	pipe := h.rdb.Pipeline()
	incrCmd := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, provisionCapExpiry)

	if _, err := pipe.Exec(ctx); err != nil {
		return false, fmt.Errorf("checkProvisionLimit redis pipeline: %w", err)
	}

	count, err := incrCmd.Result()
	if err != nil {
		return false, fmt.Errorf("checkProvisionLimit incr result: %w", err)
	}
	return count > int64(h.plans.ProvisionLimit(provisionLimitTier)), nil
}

// denyProvisionOverCap writes the canonical 429 response for an anonymous
// caller that is over the per-fingerprint daily provisioning cap AND for
// which no existing resource could be found to dedup against.
//
// WHY THIS EXISTS (load-test finding F2 — TOCTOU fix 2026-05-19):
// checkProvisionLimit's atomic INCR correctly hands every burst caller a
// distinct slot number, so callers 6..N all see limitExceeded == true.
// The over-cap branch in each handler then tries to look up an existing
// anonymous resource to return instead of provisioning fresh. But during a
// *simultaneous* burst the ≤5 winning callers have not yet committed their
// `resources` rows — so GetActiveResourceByFingerprintType AND the
// cross-service GetActiveResourceByFingerprint both return ErrResourceNotFound.
// Before this fix, when both lookups missed, control FELL THROUGH the
// limitExceeded block to CreateResource — and every one of the 30 burst
// callers minted a fresh token, blowing the cap (observed: 22–29 tokens
// instead of 5).
//
// The fix closes the fall-through: an over-cap caller that finds no
// existing resource is genuinely over the cap (its slot number proved it)
// — the absence of a committed row only means the winners are still
// in-flight. Such a caller MUST be rejected with 429, never allowed to
// provision fresh. Handlers call this on the no-existing-resource path
// instead of falling through.
//
// The atomic INCR (the slot claim) plus this hard deny (no fall-through)
// together make the cap race-safe: at most `cap` callers ever reach
// CreateResource; callers 6..N either dedup onto a committed winner or get
// a clean 429 here.
func (h *provisionHelper) denyProvisionOverCap(c *fiber.Ctx, fp, resourceType string) error {
	metrics.FingerprintAbuseBlocked.Inc()
	slog.Info("provision.cap_reached.no_existing_resource",
		"fingerprint", fp, "resource_type", resourceType,
		"cap", h.plans.ProvisionLimit(provisionLimitTier))
	return respondError(c, fiber.StatusTooManyRequests, overCapErrorCode,
		"Daily anonymous provisioning limit reached for this network. Sign up at "+urls.StartURLPrefix)
}

// recycleSeen returns true if the recycle_seen:<fp> marker exists for this
// fingerprint. On Redis error this returns (false, err); callers MUST fail
// open — a Redis outage must never block the magic-first-touch wedge.
func (h *provisionHelper) recycleSeen(ctx context.Context, fp string) (bool, error) {
	if fp == "" {
		return false, nil
	}
	exists, err := h.rdb.Exists(ctx, RecycleSeenKeyPrefix+fp).Result()
	if err != nil {
		return false, fmt.Errorf("recycleSeen: %w", err)
	}
	return exists > 0, nil
}

// markRecycleSeen sets recycle_seen:<fp> with the standard TTL. Called by
// every anonymous-path handler immediately after a successful provision.
// Errors are returned but callers should log+continue — the gate is a
// best-effort defence and a Redis blip must not block a successful provision.
func (h *provisionHelper) markRecycleSeen(ctx context.Context, fp string) error {
	if fp == "" {
		return nil
	}
	if err := h.rdb.Set(ctx, RecycleSeenKeyPrefix+fp, "1", RecycleSeenTTL).Err(); err != nil {
		return fmt.Errorf("markRecycleSeen: %w", err)
	}
	return nil
}

// recycleGate returns true and writes a 402 response when the anonymous
// caller is attempting to recycle the free tier after a prior expiry on the
// same fingerprint. Returns false (and does NOT write a response) when the
// caller is allowed to proceed — either because this is the first
// anonymous touch on this fingerprint (no marker), or because there is
// already an active resource of ANY type (the caller is still inside
// their original 24h session and just adding a complementary service).
//
// Always read AFTER checkProvisionLimit so the daily-cap dedup branch
// still wins on its existing path. The recycle gate only fires when:
//
//	(a) the recycle_seen:<fp> marker is present, AND
//	(b) ZERO active anonymous resources exist for this fingerprint
//	    (across all service types — not just the requested one).
//
// (b) is cross-service on purpose: provisioning 5 Postgres then a Redis is
// a single agent session, not a recycle. A recycle is specifically the
// shape "I had something yesterday, it aged out, give me a new one today" —
// which only matches when the resource lookup returns zero rows.
//
// Fails OPEN: Redis errors or lookup errors return (false, nil) — the
// magic-first-touch wedge is non-negotiable. We'd rather miss a recycle
// than 402 an honest first-time caller.
func (h *provisionHelper) recycleGate(c *fiber.Ctx, fp, resourceType string) bool {
	ctx := c.UserContext()
	seen, err := h.recycleSeen(ctx, fp)
	if err != nil {
		slog.Warn("provision.recycle_gate.redis_failed",
			"error", err, "fingerprint", fp, "resource_type", resourceType)
		metrics.RedisErrors.WithLabelValues("recycle_gate").Inc()
		return false
	}
	if !seen {
		return false
	}

	// Marker exists. If ANY active anonymous resource is still around we
	// let the existing dedup / multi-service path handle it. The gate
	// fires only when this fingerprint has zero live resources of any
	// type and is asking for a new one.
	existing, lookupErr := models.GetAllActiveResourcesByFingerprint(ctx, h.db, fp)
	if lookupErr != nil {
		// A real DB error — fail open. We are not going to 402 an honest
		// caller just because Postgres blipped.
		slog.Warn("provision.recycle_gate.lookup_failed",
			"error", lookupErr, "fingerprint", fp, "resource_type", resourceType)
		return false
	}
	if len(existing) > 0 {
		return false // still mid-session across one or more services; not a recycle
	}

	// Confirmed recycle: marker set, no active row. Gate.
	metrics.RecycleGateBlocked.WithLabelValues(resourceType).Inc()
	slog.Info("provision.recycle_gate.blocked",
		"fingerprint", fp, "resource_type", resourceType)
	// Route through the canonical ErrorResponse envelope (request_id +
	// retry_after_seconds + claim_url) instead of a hand-built fiber.Map.
	_ = respondRecycleGate(c, RecycleGateErrorCode, RecycleGateMessage,
		RecycleGateAgentAction, RecycleGateClaimURL)
	return true
}

// deprovisionBestEffort tears down a just-provisioned backend object after a
// post-RPC persistence failure (MR-P0-3 cleanup path). Best-effort: a failure
// is logged at WARN and swallowed — the soft-delete + 503 still happen. A nil
// provClient (local-provider mode) is a no-op; the local providers have no
// async backend object that outlives the request.
func deprovisionBestEffort(ctx context.Context, provClient *provisioner.Client, token, providerResourceID, resourceType, logPrefix string) {
	if provClient == nil {
		return
	}
	resType := resourceTypeToProto(resourceType)
	if resType == commonv1.ResourceType_RESOURCE_TYPE_UNSPECIFIED {
		return
	}
	if err := provClient.DeprovisionResource(ctx, token, providerResourceID, resType); err != nil {
		slog.Warn(logPrefix+".cleanup_deprovision_failed",
			"error", err, "token", token, "resource_type", resourceType)
	}
}

// errProvisionPersistFailed is the sentinel finalizeProvision returns when a
// post-RPC persistence step (connection-URL encrypt/store, provider-resource-id
// store) or the pending→active flip failed. The handler maps it to a 503 via
// respondProvisionFailed — never a 201. See MR-P0-3.
var errProvisionPersistFailed = errors.New("provision persistence failed")

// finalizeProvision is the second phase of the MR-P0-2 / MR-P0-3 two-phase
// provision lifecycle. The caller runs it AFTER the backend provision RPC has
// succeeded; it:
//
//  1. Encrypts and persists the connection URL.
//  2. Persists the provider_resource_id.
//  3. Flips the resource row from 'pending' → 'active' (models.MarkResourceActive).
//
// If ANY of those steps fails the resource is NOT addressable by the platform
// (no stored URL → the customer can never recover credentials; no PRID → the
// platform can't deprovision; still 'pending' → it is not usable) — returning a
// 201 for such a row is the MR-P0-3 orphan-generator bug. So on any failure
// this helper:
//
//   - runs the caller-supplied cleanup closure (best-effort backend deprovision),
//   - soft-deletes the resource row,
//   - returns errProvisionPersistFailed.
//
// The caller treats a non-nil return as a hard provision failure
// (respondProvisionFailed → 503), never a success.
//
// keyPrefix is the optional provisioner ACL namespace (Redis); pass "" for
// resource types that have none. cleanup may be nil for status-only resources
// (webhook) that have no backend object to tear down. logPrefix is the
// per-handler slog key prefix (e.g. "db.new", "cache.new") so log lines stay
// attributable.
func (h *provisionHelper) finalizeProvision(
	ctx context.Context,
	resource *models.Resource,
	connectionURL, keyPrefix, providerResourceID, requestID, logPrefix string,
	cleanup func(),
) error {
	persistFailed := false

	// 0. Persist the provisioner key_prefix (Redis ACL namespace). A missing
	//    key_prefix breaks the dedup path's ability to return the correct
	//    namespace — hard failure.
	if !persistFailed && keyPrefix != "" {
		if kpErr := models.UpdateKeyPrefix(ctx, h.db, resource.ID, keyPrefix); kpErr != nil {
			slog.Error(logPrefix+".update_key_prefix_failed", "error", kpErr, "request_id", requestID,
				"resource_id", resource.ID)
			persistFailed = true
		}
	}

	// 1. Encrypt + persist the connection URL. A missing stored URL means the
	//    customer can never recover credentials beyond the single 201 body —
	//    treat any failure here as a hard provision failure.
	if !persistFailed && connectionURL != "" {
		aesKey, keyErr := crypto.ParseAESKey(h.cfg.AESKey)
		if keyErr != nil {
			slog.Error(logPrefix+".aes_key_parse_failed", "error", keyErr, "request_id", requestID,
				"resource_id", resource.ID)
			persistFailed = true
		} else if encryptedURL, encErr := crypto.Encrypt(aesKey, connectionURL); encErr != nil {
			slog.Error(logPrefix+".encrypt_url_failed", "error", encErr, "request_id", requestID,
				"resource_id", resource.ID)
			persistFailed = true
		} else if upErr := models.UpdateConnectionURL(ctx, h.db, resource.ID, encryptedURL); upErr != nil {
			slog.Error(logPrefix+".update_connection_url_failed", "error", upErr, "request_id", requestID,
				"resource_id", resource.ID)
			persistFailed = true
		}
	}

	// 2. Persist provider_resource_id. A missing PRID means Deprovision /
	//    StorageBytes target the wrong backend object — the resource becomes
	//    un-droppable. Hard failure.
	if !persistFailed {
		if upErr := models.UpdateProviderResourceID(ctx, h.db, resource.ID, providerResourceID); upErr != nil {
			slog.Error(logPrefix+".update_provider_resource_id_failed", "error", upErr, "request_id", requestID,
				"resource_id", resource.ID)
			persistFailed = true
		}
	}

	// 3. Flip pending → active. Only a fully-persisted resource becomes usable.
	if !persistFailed {
		if actErr := models.MarkResourceActive(ctx, h.db, resource.ID); actErr != nil {
			slog.Error(logPrefix+".mark_active_failed", "error", actErr, "request_id", requestID,
				"resource_id", resource.ID)
			persistFailed = true
		}
	}

	if !persistFailed {
		return nil
	}

	// Persistence failed — the resource is unreachable / un-addressable. Tear
	// down the backend object (best-effort) and soft-delete the row so the
	// platform is not left billing an orphan, then signal a hard failure.
	if cleanup != nil {
		cleanup()
	}
	if delErr := models.SoftDeleteResource(ctx, h.db, resource.ID); delErr != nil {
		slog.Error(logPrefix+".cleanup_soft_delete_failed", "error", delErr,
			"resource_id", resource.ID, "request_id", requestID)
	}

	// MR-P0-3: emit the operator-alert audit row. This is the moment the
	// platform produced an unreachable resource — the backend object existed
	// (briefly), the platform DB could not address it, and the deprovision +
	// soft-delete is the compensation. Operators key on this kind to
	// reconstruct the exact request, find the upstream failure cause
	// (DB unreachable / encrypt failure / etc.), and audit-trace any backend
	// objects that escaped the best-effort cleanup. Best-effort emit: audit-
	// log errors must never block the 503 — the customer needs a clean answer.
	emitProvisionPersistenceFailedAudit(ctx, h.db, resource, providerResourceID, requestID, logPrefix)

	return errProvisionPersistFailed
}

// emitProvisionPersistenceFailedAudit emits the
// AuditKindProvisionPersistenceFailed row. Best-effort: any audit-write error
// is logged at WARN and swallowed — the caller already runs the cleanup +
// soft-delete and returns 503 to the customer. We never want an audit-store
// blip to wedge the response. Synchronous (not goroutine'd) so the row lands
// before the request goroutine returns; the row is small (< 1 KB), the DB hit
// is sub-millisecond on a healthy platform, and the bound on request latency
// is already dominated by the backend RPC that just succeeded.
func emitProvisionPersistenceFailedAudit(
	ctx context.Context,
	db *sql.DB,
	res *models.Resource,
	providerResourceID, requestID, logPrefix string,
) {
	var teamID uuid.UUID
	if res.TeamID.Valid {
		teamID = res.TeamID.UUID
	}

	// JSONB metadata so operator queries can pivot by resource_type / log_prefix
	// / provider_resource_id. Hand-constructed via fmt.Sprintf with %q
	// formatting so each field is JSON-string-escaped — avoids a json package
	// import here. Keys are stable contract: the NR Log dashboard queries them
	// by literal name.
	meta := fmt.Sprintf(
		`{"resource_id":%q,"resource_type":%q,"log_prefix":%q,"provider_resource_id":%q,"request_id":%q,"tier":%q,"env":%q}`,
		res.ID.String(),
		res.ResourceType,
		logPrefix,
		providerResourceID,
		requestID,
		res.Tier,
		res.Env,
	)

	if auditErr := models.InsertAuditEvent(ctx, db, models.AuditEvent{
		TeamID:       teamID,
		Actor:        "system",
		Kind:         models.AuditKindProvisionPersistenceFailed,
		ResourceType: res.ResourceType,
		ResourceID:   uuid.NullUUID{UUID: res.ID, Valid: true},
		Summary: "provision succeeded downstream but platform persistence failed; " +
			"backend object torn down (best-effort), resource soft-deleted, " +
			"503 returned to caller",
		Metadata: []byte(meta),
	}); auditErr != nil {
		slog.Warn(logPrefix+".persistence_failed_audit_emit_failed",
			"error", auditErr, "resource_id", res.ID, "request_id", requestID)
	}
}

// issueOnboardingJWT signs a short-lived JWT for the upgrade CTA.
// It looks up ALL active resources for the fingerprint so the landing page
// reflects the full session (not just the current service).
// Returns ("", "", err) if signing fails — callers treat this as a soft error
// and proceed without the JWT (upgrade URL will be empty).
func (h *provisionHelper) issueOnboardingJWT(
	ctx context.Context,
	fp, country, vendor string,
	resourceType string,
	tokens []string,
) (jwtToken, jti string, err error) {
	// Look up all active resources for this fingerprint so the JWT captures
	// every service provisioned in one agent session.
	allResources, lookupErr := models.GetAllActiveResourcesByFingerprint(ctx, h.db, fp)
	if lookupErr != nil {
		slog.Warn("issueOnboardingJWT: fingerprint lookup failed (using current token only)",
			"error", lookupErr, "fingerprint", fp)
	}

	allTokens := tokens
	allTypes := []string{resourceType}
	// Use "type:" prefix consistently for type dedup keys to avoid collision
	// with token UUID strings (which have no prefix).
	seen := map[string]bool{"type:" + resourceType: true}
	for _, tok := range tokens {
		seen[tok] = true
	}
	for _, r := range allResources {
		// Skip resource types that are not enabled in config. The JWT should only
		// advertise claimable services.
		if !h.cfg.IsServiceEnabled(r.ResourceType) {
			continue
		}
		tokStr := r.Token.String()
		if !seen[tokStr] {
			allTokens = append(allTokens, tokStr)
			seen[tokStr] = true
		}
		if !seen["type:"+r.ResourceType] {
			allTypes = append(allTypes, r.ResourceType)
			seen["type:"+r.ResourceType] = true
		}
	}

	secret := []byte(h.cfg.JWTSecret)
	claims := crypto.OnboardingClaims{
		Fingerprint:   fp,
		Country:       country,
		CloudVendor:   vendor,
		Tokens:        allTokens,
		ResourceTypes: allTypes,
		SuggestedPlan: "hobby",
	}
	jwtToken, jti, err = crypto.SignOnboardingJWT(secret, claims)
	if err != nil {
		return "", "", fmt.Errorf("issueOnboardingJWT: %w", err)
	}
	return jwtToken, jti, nil
}

// createOnboardingEvent persists the onboarding event row.
// Errors are logged by the caller but never block the response.
func (h *provisionHelper) createOnboardingEvent(
	ctx context.Context,
	fp, jti string,
	resourceToken uuid.UUID,
) error {
	expiresAt := time.Now().UTC().Add(7 * 24 * time.Hour)
	_, err := models.CreateOnboardingEvent(ctx, h.db, fp, jti, expiresAt, []uuid.UUID{resourceToken})
	return err
}

// upgradeNote builds the note string for a freshly provisioned anonymous resource.
//
// Copy reflects the "anonymous is the trial" model: anonymous tier runs 24h
// for free; claiming converts to a paid tier starting at $9/mo. There is no
// 14-day trial on the paid tiers — the trial framing belongs only to the
// anonymous slice.
func upgradeNote(upgradeURL string) string {
	if upgradeURL != "" {
		return fmt.Sprintf("Works for 24h free. Claim to keep — from $9/mo: %s", upgradeURL)
	}
	return "Works for 24h free. Claim to keep — from $9/mo: " + urls.StartURLPrefix
}

// limitExceededNote builds the note for the rate-limit-exceeded path.
// Pass expiresAt as a non-zero time to include expiry info in the message.
func limitExceededNote(upgradeURL string, expiresAt time.Time) string {
	expiry := ""
	if !expiresAt.IsZero() {
		remaining := time.Until(expiresAt).Round(time.Minute)
		expiry = fmt.Sprintf(" Expires in %s.", formatDuration(remaining))
	}
	if upgradeURL != "" {
		return fmt.Sprintf("Returning your existing resource.%s Claim to keep — from $9/mo: %s", expiry, upgradeURL)
	}
	return fmt.Sprintf("Returning your existing resource.%s Claim to keep — from $9/mo: %s", expiry, urls.StartURLPrefix)
}

// formatDuration formats a duration as "Xh Ym" or "Xm".
func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "less than a minute"
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h > 0 && m > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	if h > 0 {
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dm", m)
}

// provisionRequestBody is the optional JSON body accepted by all POST /{service}/new endpoints.
type provisionRequestBody struct {
	// Name is a human-readable label (max 120 chars).
	// Returned in the response so callers can distinguish multiple resources.
	Name string `json:"name"`

	// Dedicated requests a fully isolated, single-tenant resource (one k8s pod per token,
	// own namespace, own PVC). Requires an authenticated team-tier token.
	// Anonymous callers receive a 402 with an upgrade URL.
	Dedicated bool `json:"dedicated"`

	// Env scopes the resource to a named environment (dev/staging/production/...).
	// Empty defaults to "development" (flipped from "production" by migration
	// 026 — see models.EnvDefault). Validated against ^[a-z0-9-]{1,32}$.
	// Body field is overridden by the ?env= query string when both are set.
	Env string `json:"env"`

	// ParentResourceID links the new resource into an existing env-twin
	// family. The new row becomes a sibling of the parent (same family
	// root, different env). Validated against same-team + same-type +
	// no-duplicate-twin before provisioning. Empty / zero UUID means
	// "no family link — this row stands alone" (backwards compatible
	// with every caller that pre-dates slice 2).
	ParentResourceID string `json:"parent_resource_id"`
}

// sanitizeName trims, length-caps, and strips HTML-dangerous characters
// from a user-supplied resource name. The strip is defence-in-depth:
// resource names land in audit_log.summary (which the dashboard renders
// via dangerouslySetInnerHTML on its activity-feed fallback path,
// dashboard/src/api/index.ts fetchActivity), in JSON responses, and in
// future surfaces (email subjects, slack notifications) we don't want
// to have to audit one-by-one. Rather than trust every downstream
// renderer, we reject the four HTML-special characters at the
// provisioning boundary — `<`, `>`, `"`, `'`. `&` is allowed (legitimate
// in names like "Smith & Co Postgres") because React's text rendering
// already escapes it; the strip targets the script-tag sink specifically.
//
// Wave FIX-D additions (#Q70/#Q71):
//   - Invalid UTF-8 → rejected with an error. Go's JSON decoder silently
//     replaces invalid bytes with U+FFFD (the replacement character), which
//     means a hostile or malformed name slipped past sanitizeName before.
//     We now reject at the boundary so resources.name only ever holds valid
//     UTF-8.
//   - Control characters (U+0000–U+001F, U+007F DEL) → silently stripped.
//     CRLF, NUL, BEL, etc. in a name break log lines, terminal output, and
//     audit summaries; they have no legitimate use in a human-readable
//     label. Strip rather than reject so a stray \r from a copy-pasted name
//     doesn't 400 the caller.
//
// We deliberately do NOT HTML-escape (replace `<` with `&lt;`) because the
// resource name is also displayed in CLI output, slack messages, and email
// subjects where the user expects the original characters. Stripping is
// the only transformation that's safe across every downstream renderer.
//
// Returns (name, nil) on success, ("", ErrResponseWritten) when the caller
// MUST stop — the 400 response has already been written via respondError.
// The Fiber-aware variant lives in sanitizeNameForRequest below.
func sanitizeName(name string) (string, error) {
	if name == "" {
		return "", nil
	}
	if !utf8.ValidString(name) {
		return "", errInvalidUTF8Name
	}
	// Strip control characters first (CRLF, NUL, BEL, ...). These have no
	// legitimate place in a human-readable name; CRLF in particular would
	// inject newlines into structured log lines and audit summaries.
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, name)
	// Strip HTML-injection vectors. Replace with empty string rather than
	// a placeholder so a paste of "<bad>name" cleanly becomes "name"
	// rather than something like "[stripped]name" the user must explain.
	stripper := strings.NewReplacer(
		"<", "",
		">", "",
		"\"", "",
		"'", "",
	)
	name = stripper.Replace(name)
	// B18 M2 (BugBash 2026-05-20): the 120-BYTE silent truncation that lived
	// here was a footgun. requireName already enforces the 64-RUNE limit via
	// utf8.RuneCountInString below — having a second, looser, silent cap at
	// 120 bytes meant a multi-byte name landing between 65 and 120 runes
	// after the strip would be silently truncated instead of cleanly
	// rejected with `invalid_name`. The regex (`^[A-Za-z0-9][A-Za-z0-9 _-]*$`)
	// rejects all non-ASCII today, so the silent path was unreachable — but
	// any future relaxation of the regex would reopen the gap. The single
	// 64-rune gate in requireName is now the authoritative length contract.
	return name, nil
}

// errInvalidUTF8Name is the sentinel sanitizeName returns when the input
// contains invalid UTF-8 bytes. Handlers convert this into the canonical
// 400 invalid_name response via sanitizeNameForRequest.
var errInvalidUTF8Name = errors.New("name contains invalid UTF-8 bytes")

// ─────────────────────────────────────────────────────────────────────────────
// Mandatory resource naming (BREAKING contract change — 2026-05-16).
//
// `name` is now STRICTLY REQUIRED on every provisioning endpoint
// (POST /db/new, /cache/new, /nosql/new, /queue/new, /storage/new,
// /webhook/new, /deploy/new, /stacks/new). A missing/empty name leaves the
// dashboard rendering raw hashes like `db_fcb890cde09d`, which is
// unacceptable UX. Callers MUST supply a short human label.
//
// Validation contract:
//   - Trim surrounding whitespace.
//   - After trim: 1–64 chars matching nameValidationRegex.
//   - Missing / empty-after-trim → 400 `name_required`.
//   - Present but bad format/length → 400 `invalid_name`.
// ─────────────────────────────────────────────────────────────────────────────

// errCodeNameRequired is the machine-stable error code returned when a
// provisioning request omits `name` or sends an empty/whitespace-only value.
const errCodeNameRequired = "name_required"

// errCodeInvalidName is the machine-stable error code returned when `name`
// is present but fails the length / format validation.
const errCodeInvalidName = "invalid_name"

// nameMinLength and nameMaxLength are the inclusive length bounds for a
// resource name, measured in runes after trimming surrounding whitespace.
const (
	nameMinLength = 1
	nameMaxLength = 64
)

// nameValidationPattern is the regex a resource name must match after
// trimming: starts with an alphanumeric, followed by any mix of letters,
// digits, spaces, underscores and hyphens.
const nameValidationPattern = `^[A-Za-z0-9][A-Za-z0-9 _-]*$`

// nameValidationRegex is the compiled form of nameValidationPattern, compiled
// once at package init.
var nameValidationRegex = regexp.MustCompile(nameValidationPattern)

// nameRequiredAgentAction is the verbatim sentence the calling agent surfaces
// when `name` is missing. Adheres to the U3 contract (agent_action.go):
// "Tell the user" opening, specific reason, concrete next action.
const nameRequiredAgentAction = "Tell the user the provisioning request is missing a name. Add a 'name' field with a short human label (1-64 chars; letters, numbers, spaces, dashes) — e.g. \"My App DB\" — and retry."

// invalidNameAgentAction is the verbatim sentence surfaced when `name` is
// present but invalid (wrong characters or too long).
const invalidNameAgentAction = "Tell the user the 'name' field is invalid. Use a short human label of 1-64 chars that starts with a letter or digit and contains only letters, numbers, spaces, underscores or dashes — e.g. \"My App DB\" — and retry."

// requireName validates a user-supplied resource name against the mandatory
// naming contract and returns the trimmed, sanitized name on success.
//
// On failure it writes the canonical 400 response (name_required or
// invalid_name, with the matching agent_action) via respondErrorWithAgentAction
// and returns ("", ErrResponseWritten). Standard caller pattern:
//
//	name, err := requireName(c, body.Name)
//	if err != nil { return err }
//
// requireName runs sanitizeName first (strips control chars / HTML-special
// chars, rejects invalid UTF-8) so the persisted value is safe across every
// downstream renderer, then enforces the trim + length + regex contract.
func requireName(c *fiber.Ctx, raw string) (string, error) {
	clean, sanErr := sanitizeName(raw)
	if sanErr != nil {
		if errors.Is(sanErr, errInvalidUTF8Name) {
			return "", respondErrorWithAgentAction(c, fiber.StatusBadRequest,
				errCodeInvalidName,
				"Field 'name' contains invalid UTF-8 bytes. Use only valid UTF-8 text.",
				invalidNameAgentAction, "")
		}
		return "", respondErrorWithAgentAction(c, fiber.StatusBadRequest,
			errCodeInvalidName,
			"Field 'name' could not be sanitized: "+sanErr.Error(),
			invalidNameAgentAction, "")
	}

	trimmed := strings.TrimSpace(clean)
	if trimmed == "" {
		return "", respondErrorWithAgentAction(c, fiber.StatusBadRequest,
			errCodeNameRequired,
			"Field 'name' is required — provide a short human label (1-64 chars) for this resource.",
			nameRequiredAgentAction, "")
	}

	if n := utf8.RuneCountInString(trimmed); n < nameMinLength || n > nameMaxLength {
		return "", respondErrorWithAgentAction(c, fiber.StatusBadRequest,
			errCodeInvalidName,
			fmt.Sprintf("Field 'name' must be %d-%d characters after trimming.", nameMinLength, nameMaxLength),
			invalidNameAgentAction, "")
	}

	if !nameValidationRegex.MatchString(trimmed) {
		return "", respondErrorWithAgentAction(c, fiber.StatusBadRequest,
			errCodeInvalidName,
			"Field 'name' must start with a letter or digit and contain only letters, numbers, spaces, underscores or dashes.",
			invalidNameAgentAction, "")
	}

	// B18 L1 (BugBash 2026-05-20): if sanitizeName mutated the input (CRLF /
	// tab / NUL / HTML-special chars stripped), surface an X-Instant-Notice
	// response header so the calling agent can detect "the persisted name
	// is not what I sent" without parsing prose. Previously the strip was
	// silent — an agent looking up `db_for_user\n` later by exact name
	// would never find the persisted `db_for_user`. We deliberately do not
	// fail the request; the strip is a deliberate hardening on top of the
	// regex, and a 400 here would break legitimate-but-sloppy callers.
	if trimmedRaw := strings.TrimSpace(raw); trimmedRaw != trimmed && trimmedRaw != "" {
		// Only emit when the change is structural — not when only outer
		// whitespace was trimmed (which is documented in the agent_action).
		if c != nil {
			c.Set("X-Instant-Notice", "name_normalized: control/HTML-special characters were stripped from your name input")
		}
		// B18 L1 (wave 3, 2026-05-21): also emit a structured slog line so an
		// operator scanning NR sees the per-request normalisation without
		// having to inspect the response header. Logged at INFO (not WARN)
		// because the strip is by-design hardening, not anomalous traffic.
		// `raw_len` / `clean_len` are byte counts of the pre-strip and
		// post-strip values; the actual values are NEVER logged (they may
		// contain CRLF / NUL bytes that would corrupt the log line — that
		// is precisely why we stripped them).
		slog.InfoContext(c.UserContext(), "provision.name_normalized",
			"raw_len", len(raw),
			"clean_len", len(trimmed),
		)
	}

	return trimmed, nil
}

// sanitizeNameForRequest wraps sanitizeName with Fiber-aware error handling.
// On invalid UTF-8 it writes a 400 invalid_name response via respondError
// and returns ErrResponseWritten — the caller's standard error propagation
// (`if err != nil { return err }`) does the right thing.
//
// Use this from every POST handler that accepts a `name` body field. The
// plain sanitizeName remains exported within the package for non-Fiber
// callers (k8s job naming, future internal use).
func sanitizeNameForRequest(c *fiber.Ctx, name string) (string, error) {
	clean, err := sanitizeName(name)
	if err == nil {
		return clean, nil
	}
	if errors.Is(err, errInvalidUTF8Name) {
		return "", respondError(c, fiber.StatusBadRequest, "invalid_name",
			"Field 'name' contains invalid UTF-8 bytes. Use only valid UTF-8 text.")
	}
	// Unknown sanitize error — surface as 400 rather than 500. The only
	// failure mode today is invalid UTF-8; future additions land here.
	return "", respondError(c, fiber.StatusBadRequest, "invalid_name",
		"Field 'name' could not be sanitized: "+err.Error())
}

// parseProvisionBody reads and parses the optional JSON request body into v.
// Empty bodies are tolerated (every provisioning endpoint accepts a bare
// POST with no body). Non-empty bodies that fail to parse — BOM-prefixed
// JSON, comments, trailing commas, wrong-type fields, invalid UTF-8 —
// produce a 400 invalid_body response instead of being silently swallowed.
//
// Wave FIX-D (#125 / #S18 / #Q67 / #Q70 / #Q71): before this helper every
// provisioning handler did `_ = c.BodyParser(&body)` which silently ate
// every parse error. The result was a 201 with empty fields and zero-value
// coercions (name: 12345 → name: ""), which is indistinguishable from a
// bare POST and hides real bugs in client code.
//
// Invalid-UTF-8 (#Q70): Go's encoding/json package silently rewrites
// invalid UTF-8 bytes in string literals as U+FFFD (the Unicode replacement
// character) during Unmarshal. By the time c.BodyParser hands us the
// decoded struct the original bytes are gone. The only place to reject
// invalid UTF-8 is the raw request body — we do that here, BEFORE the
// JSON decoder gets a chance to coerce.
//
// On error this helper writes the response via respondError and returns
// ErrResponseWritten. Standard caller pattern:
//
//	if err := parseProvisionBody(c, &body); err != nil { return err }
func parseProvisionBody(c *fiber.Ctx, v any) error {
	raw := c.Body()
	if len(raw) == 0 {
		return nil
	}
	// B18 L2 (BugBash 2026-05-20): when a non-empty body arrives with an
	// explicit non-JSON Content-Type (application/xml, text/xml,
	// application/x-www-form-urlencoded, etc.), return 415
	// `unsupported_media_type` BEFORE attempting UTF-8 / JSON validation.
	// Pre-fix, sending `<x>hello</x>` with `Content-Type: application/xml`
	// returned `400 name_required` — a misleading code that cost the
	// caller one extra debugging cycle to discover the real issue is the
	// Content-Type. The OpenAPI spec declares `application/json` only;
	// 415 is the RFC-correct status. application/json, no Content-Type,
	// and text/plain (legacy "raw POST" senders) all continue through
	// the JSON path; only declared non-JSON types are rejected.
	ct := strings.ToLower(strings.TrimSpace(c.Get("Content-Type")))
	// Strip any "; charset=..." suffix.
	if idx := strings.Index(ct, ";"); idx >= 0 {
		ct = strings.TrimSpace(ct[:idx])
	}
	if ct != "" && ct != "application/json" && ct != "text/plain" && ct != "text/json" {
		return respondError(c, fiber.StatusUnsupportedMediaType, "unsupported_media_type",
			"Request body Content-Type "+ct+" is not supported. Use application/json.")
	}
	if !utf8.Valid(raw) {
		return respondError(c, fiber.StatusBadRequest, "invalid_body",
			"Request body contains invalid UTF-8 bytes. Send valid UTF-8 JSON.")
	}
	if err := c.BodyParser(v); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body",
			"Request body could not be parsed as JSON: "+err.Error())
	}
	return nil
}

// resolveEnv extracts the requested environment from the request, preferring
// the ?env= query string over the JSON/form body field. Returns the normalised
// env on success, or an empty string and a 400 response when validation fails.
//
// Empty input is treated as "development" (post-migration 026 — see
// models.EnvDefault). Callers that pre-date the env feature land in the
// lowest-stakes bucket instead of silently writing to production.
// resolveEnv validates the env scope from the URL query (preferred) or
// request body (fallback). On success returns (env, nil). On failure it
// writes the 400 response via respondError and returns (\"\", ErrResponseWritten).
// Callers use the standard pattern:
//
//	env, err := resolveEnv(c, body.Env)
//	if err != nil { return err }
//
// The ErrResponseWritten sentinel propagates up; the ErrorHandler
// recognises it and does not overwrite the response.
//
// Side effect (Wave FIX-D, #Q15): when the resolved env differs from what
// the caller supplied — today that only happens when the caller sent
// nothing and we defaulted to "development" per migration 026 — this
// stashes a short machine-readable reason in c.Locals under
// envOverrideReasonKey. Callers wire that reason into their JSON
// response via decorateEnvOverride so an agent can tell the difference
// between "I wrote to dev intentionally" and "I sent no env and the API
// defaulted me to dev." We don't 4xx on override (back-compat): the
// signal is a response field, not a refusal.
func resolveEnv(c *fiber.Ctx, bodyEnv string) (string, error) {
	rawQuery := c.Query("env")
	raw := rawQuery
	if raw == "" {
		raw = bodyEnv
	}
	env, ok := models.NormalizeEnv(raw)
	if !ok {
		return "", respondError(c, fiber.StatusBadRequest, "invalid_env",
			"env must match ^[a-z0-9-]{1,32}$ (lowercase letters, digits, dashes; max 32 chars)")
	}
	if reason := envOverrideReason(rawQuery, bodyEnv, env); reason != "" {
		c.Locals(envOverrideReasonKey, reason)
	}
	return env, nil
}

// envOverrideReasonKey is the Locals key under which resolveEnv stashes the
// machine-readable reason for any env override applied to a request. Read
// via decorateEnvOverride; tests can assert it directly.
const envOverrideReasonKey = "env_override_reason"

// envOverrideReason returns the short machine-readable reason for any env
// override applied to a request. Returns "" when the caller's input was
// used verbatim (no override happened).
//
// Current triggers:
//   - "default_no_env_specified" — caller sent no env, defaulted to
//     EnvDefault ("development") per migration 026.
//
// Future triggers (placeholder — none wired today): tier_policy_downgrade
// when a tier-policy refuses production and rewrites to staging, etc.
func envOverrideReason(rawQuery, rawBody, resolved string) string {
	if rawQuery == "" && rawBody == "" && resolved == models.EnvDefault {
		return "default_no_env_specified"
	}
	return ""
}

// decorateEnvOverride injects "env_override_reason" into a response map
// when resolveEnv stashed one on the request. No-op when the caller passed
// an explicit env, so existing happy-path responses keep their compact
// shape. Pass every fiber.Map the handler returns via c.JSON / c.Status.JSON.
func decorateEnvOverride(c *fiber.Ctx, resp fiber.Map) fiber.Map {
	if v, ok := c.Locals(envOverrideReasonKey).(string); ok && v != "" {
		resp["env_override_reason"] = v
	}
	return resp
}

// respondCreated writes a 201 JSON response after applying any pending
// env-override decoration. Single chokepoint so handlers don't have to
// remember to call decorateEnvOverride at every response site.
//
// Use:
//
//	return respondCreated(c, fiber.Map{ "ok": true, "id": ..., "env": env })
//
// Equivalent to the prior c.Status(fiber.StatusCreated).JSON(resp), but
// also stamps env_override_reason when resolveEnv flagged the request.
func respondCreated(c *fiber.Ctx, resp fiber.Map) error {
	return c.Status(fiber.StatusCreated).JSON(decorateEnvOverride(c, resp))
}

// respondOK writes a 200 JSON response with the same env-override decoration.
// Mirror of respondCreated for endpoints that re-emit existing resources
// (e.g. the fingerprint-dedup branch returns the existing resource at 200).
func respondOK(c *fiber.Ctx, resp fiber.Map) error {
	return c.JSON(decorateEnvOverride(c, resp))
}

// resolveFamilyParent parses the body's optional parent_resource_id and
// validates that linking a child of (resourceType, env) is legal for the
// caller's team. Returns:
//
//	(nil, nil)       — no parent_resource_id requested (standalone resource)
//	(*uuid, nil)     — parent valid; *uuid is the FAMILY ROOT id to store
//	(nil, fiberErr)  — caller-facing error; response already written
//
// The handlers wire this between the env resolution and CreateResource:
//
//	parentID, perr := resolveFamilyParent(c, h.db, body.ParentResourceID,
//	                                       teamID, resourceType, env)
//	if perr != nil { return perr }
//	// ...then pass parentID to CreateResourceParams.ParentResourceID
//
// HTTP status mapping by FamilyLinkError.Reason:
//
//	cross_team       → 403  (we know it exists, but caller can't see it)
//	cross_type       → 400  (caller error — wrong shape)
//	duplicate_twin   → 409  (resource already there in this env)
//	deleted_parent   → 404  (parent doesn't exist / was deleted)
func resolveFamilyParent(
	c *fiber.Ctx, db *sql.DB, bodyParentID string,
	teamID uuid.UUID, resourceType, env string,
) (*uuid.UUID, error) {
	if bodyParentID == "" {
		return nil, nil
	}
	parentID, parseErr := uuid.Parse(bodyParentID)
	if parseErr != nil || parentID == uuid.Nil {
		return nil, respondError(c, fiber.StatusBadRequest, "invalid_parent_resource_id",
			"parent_resource_id must be a valid UUID")
	}

	rootID, err := models.ValidateFamilyParent(c.Context(), db, parentID, teamID, resourceType, env)
	if err != nil {
		var linkErr *models.FamilyLinkError
		if errors.As(err, &linkErr) {
			switch linkErr.Reason {
			case "cross_team":
				return nil, respondError(c, fiber.StatusForbidden, "forbidden_parent_resource",
					"parent_resource_id belongs to a different team")
			case "cross_type":
				return nil, respondError(c, fiber.StatusBadRequest, "type_mismatch",
					linkErr.Detail)
			case "duplicate_twin":
				return nil, respondError(c, fiber.StatusConflict, "twin_exists",
					linkErr.Detail)
			case "deleted_parent":
				return nil, respondError(c, fiber.StatusNotFound, "parent_not_found",
					linkErr.Detail)
			}
		}
		// Unrecognised failure — log + 503 so we don't accidentally green-
		// light a provision with an unresolved family relationship.
		slog.Error("resource.family.validate_failed",
			"error", err,
			"parent_resource_id", parentID,
			"team_id", teamID,
			"resource_type", resourceType,
			"env", env,
		)
		return nil, respondError(c, fiber.StatusServiceUnavailable, "family_validate_failed",
			"Failed to validate parent_resource_id")
	}
	return &rootID, nil
}
