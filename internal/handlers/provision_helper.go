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
	"fmt"
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"instant.dev/internal/config"
	"instant.dev/internal/crypto"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/urls"
)

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

// checkProvisionLimit checks the per-fingerprint daily provisioning rate limit.
// The limit is shared across ALL service types.
//
// Returns (true, nil)  when limit is exceeded.
// Returns (false, nil) when the provision is allowed.
// Returns (false, err) when Redis is unavailable; caller must fail open.
func (h *provisionHelper) checkProvisionLimit(ctx context.Context, fp string) (bool, error) {
	date := time.Now().UTC().Format("2006-01-02")
	key := fmt.Sprintf("prov:%s:%s", fp, date)

	pipe := h.rdb.Pipeline()
	incrCmd := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, 25*time.Hour) // 25h avoids midnight thundering-herd

	if _, err := pipe.Exec(ctx); err != nil {
		return false, fmt.Errorf("checkProvisionLimit redis pipeline: %w", err)
	}

	count, err := incrCmd.Result()
	if err != nil {
		return false, fmt.Errorf("checkProvisionLimit incr result: %w", err)
	}
	return count > int64(h.plans.ProvisionLimit("anonymous")), nil
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
	// Empty defaults to "production". Validated against ^[a-z0-9-]{1,32}$.
	// Body field is overridden by the ?env= query string when both are set.
	Env string `json:"env"`
}

func sanitizeName(name string) string {
	if len(name) > 120 {
		return name[:120]
	}
	return name
}

// resolveEnv extracts the requested environment from the request, preferring
// the ?env= query string over the JSON/form body field. Returns the normalised
// env on success, or an empty string and a 400 response when validation fails.
//
// Empty input is treated as "production" — this preserves backwards compatibility
// for every caller that pre-dates the env feature.
func resolveEnv(c *fiber.Ctx, bodyEnv string) (string, error) {
	raw := c.Query("env")
	if raw == "" {
		raw = bodyEnv
	}
	env, ok := models.NormalizeEnv(raw)
	if !ok {
		return "", respondError(c, fiber.StatusBadRequest, "invalid_env",
			"env must match ^[a-z0-9-]{1,32}$ (lowercase letters, digits, dashes; max 32 chars)")
	}
	return env, nil
}
