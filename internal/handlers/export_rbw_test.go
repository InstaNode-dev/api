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
