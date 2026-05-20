package handlers

// dedup_replay.go — B13-F4 (BugBash 2026-05-20).
// Handler-internal dedup paths set X-Idempotent-Replay: true +
// X-Idempotency-Source: handler-dedup so SDKs that branch on the
// header see consistent shape regardless of which dedup layer
// (middleware vs handler) fired.

import "github.com/gofiber/fiber/v2"

const (
	idempotentReplayHeaderKey     = "X-Idempotent-Replay"
	idempotencySourceHeaderKey    = "X-Idempotency-Source"
	idempotencySourceHandlerDedup = "handler-dedup"
)

// respondDedupReplay writes a 200 dedup response with the canonical
// replay headers stamped. Use on every handler-internal fingerprint
// dedup branch (db.go / cache.go / nosql.go / queue.go / storage.go /
// vector.go / webhook.go).
func respondDedupReplay(c *fiber.Ctx, resp fiber.Map) error {
	c.Set(idempotentReplayHeaderKey, "true")
	c.Set(idempotencySourceHeaderKey, idempotencySourceHandlerDedup)
	return c.JSON(decorateEnvOverride(c, resp))
}
