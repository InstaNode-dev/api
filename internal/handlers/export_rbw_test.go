package handlers

// export_rbw_test.go — re-exports for the resource/billing/webhook/onboarding/
// admin/readyz coverage slice (_rbw suffix). Kept separate from the shared
// export_test.go to avoid collisions with the concurrent provisioning-arm
// coverage work.

import (
	"context"
	"database/sql"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"instant.dev/common/readiness"
)

// ── webhook.go re-exports ──

func WebhookMaxStoredForTest(h *WebhookHandler, tier string) int64 { return h.webhookMaxStored(tier) }

func StoreEncryptedURLForTest(h *WebhookHandler, ctx context.Context, resourceID uuid.UUID, rURL, requestID string) error {
	return h.storeEncryptedURL(ctx, resourceID, rURL, requestID)
}

func DecryptWebhookURLForTest(h *WebhookHandler, encrypted, requestID string) string {
	return h.decryptWebhookURL(encrypted, requestID)
}

func LookupIdempotentReceiveForTest(h *WebhookHandler, ctx context.Context, token, key string) (fiber.Map, bool) {
	return h.lookupIdempotentReceive(ctx, token, key)
}

func StoreIdempotentReceiveForTest(h *WebhookHandler, ctx context.Context, token, key string, resp fiber.Map, ttl time.Duration) {
	h.storeIdempotentReceive(ctx, token, key, resp, ttl)
}

func VerifyWebhookHMACForTest(secret string, body []byte, header string) bool {
	return verifyWebhookHMAC(secret, body, header)
}

func WebhookRedisForTest(h *WebhookHandler) *redis.Client { return h.rdb }

func WebhookIdempotencyKeyForTest(token, key string) string { return webhookIdempotencyKey(token, key) }

// ── onboarding.go re-exports ──

func IsValidEmailForTest(s string) bool { return isValidEmail(s) }

func MaskEmailForLogForTest(s string) string { return maskEmailForLog(s) }

func EmitOnboardingClaimedAuditForTest(db *sql.DB, teamID, userID uuid.UUID, n int, email string) {
	emitOnboardingClaimedAudit(db, teamID, userID, n, email)
}

// claimMailerForTest is a test double for the claimVerificationEmailMailer.
type ClaimMailerForTest struct {
	Err    error
	Called bool
}

func (m *ClaimMailerForTest) SendMagicLink(ctx context.Context, to, link string) error {
	m.Called = true
	return m.Err
}

func SendClaimVerificationEmailForTest(db *sql.DB, mailer *ClaimMailerForTest, email, returnTo string) {
	if mailer == nil {
		sendClaimVerificationEmail(db, nil, email, returnTo)
		return
	}
	sendClaimVerificationEmail(db, mailer, email, returnTo)
}

// ── admin_customers.go / admin_promos_audit.go re-exports ──

func AdminParseTierFilterForTest(raw string) ([]string, bool) { return adminParseTierFilter(raw) }
func AdminParseLimitForTest(raw string, def, max int) int     { return adminParseLimit(raw, def, max) }
func AdminParseOffsetForTest(raw string) int                  { return adminParseOffset(raw) }
func AdminOrderClauseForTest(sortBy string) (string, error)   { return adminOrderClause(sortBy) }
func EscapeLikePatternForTest(s string) string                { return escapeLikePattern(s) }
func ComputeMRRForTest(h *AdminCustomersHandler, tier string) (int, int) {
	return h.computeMRR(tier)
}
func ParsePromoAuditSinceForTest(raw string) (time.Time, error) { return parsePromoAuditSince(raw) }

// ── billing.go pure-helper re-exports ──

func FormatChargedAmountForTest(amountMinor int64, currency string) string {
	return formatChargedAmount(amountMinor, currency)
}

// resetOpenAPIOnceForTest resets the cached-prod-spec sync.Once to a fresh
// zero value so a test can re-exercise ServeOpenAPI's Do() body. Assigning a
// zero-value Once is copylocks-clean (no existing lock is copied).
func resetOpenAPIOnceForTest() { openAPISpecOnce = sync.Once{} }

// CustomerDBCheckForTest exposes the unexported customerDBCheck CheckFunc so a
// test can drive the empty-DSN defensive arm directly (the public path only
// wires the check when CustomerDatabaseURL != "").
func CustomerDBCheckForTest(h *ReadyzHandler) func(context.Context) readiness.CheckResult {
	fn := h.customerDBCheck()
	return func(ctx context.Context) readiness.CheckResult { return fn(ctx) }
}

// StatusToFloatForTest exposes statusToFloat for direct enum-walk coverage.
func StatusToFloatForTest(s readiness.Status) float64 { return statusToFloat(s) }

// SetReadyzSQLOpenForTest swaps the customer-DB sql.Open seam and returns a
// restore func.
func SetReadyzSQLOpenForTest(fn func(string, string) (*sql.DB, error)) (restore func()) {
	prev := readyzSQLOpen
	readyzSQLOpen = fn
	return func() { readyzSQLOpen = prev }
}
