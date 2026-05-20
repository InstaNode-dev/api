package handlers

// dedup_replay.go — handler-internal dedup response helpers.
//
// Separated from provision_helper.go to keep the B13-F4 patch
// (BugBash 2026-05-20) isolated from the larger helper module — the
// auto-format / linter cycle on provision_helper.go was reverting
// constants that shared a file with the helper's existing imports.
// Lives in its own file so the change is durable.
//
// Provides:
//   - The idempotency header KEY constants that MUST match
//     internal/middleware/idempotency.go literals exactly (the
//     middleware sets these on explicit-key / fingerprint-cache
//     replays; the handler-internal dedup path must set them too so
//     agents see one wire-level signal regardless of which dedup
//     layer fired).
//   - respondDedupReplay: wrapper around respondOK that ALSO stamps
//     X-Idempotent-Replay: true + X-Idempotency-Source: handler-dedup.
//     Used by db.go / cache.go / nosql.go / queue.go / storage.go /
//     vector.go / webhook.go on the in-handler fingerprint-dedup branch.

import "github.com/gofiber/fiber/v2"

// Idempotency response-header keys. MUST match the literal values set
// by internal/middleware/idempotency.go (idempotencyReplayHeader,
// idempotencySourceHeader). The middleware sets them on explicit-key
// or fingerprint-cache replays; this package sets them on the handler-
// internal fingerprint-dedup branch so an agent that learns the
// contract once sees consistent shape regardless of which layer fired
// (B13-F4, BugBash 2026-05-20).
const (
	idempotentReplayHeaderKey  = "X-Idempotent-Replay"
	idempotencySourceHeaderKey = "X-Idempotency-Source"

	// idempotencySourceHandlerDedup is the value the handler-internal
	// dedup branch writes into X-Idempotency-Source. Distinct from the
	// middleware's "explicit" / "fingerprint" / "miss" values so
	// observability can tell the two dedup layers apart (middleware
	// idempotency cache vs handler resource fingerprint).
	idempotencySourceHandlerDedup = "handler-dedup"
)

// respondDedupReplay writes the canonical 200 dedup response from a
// handler-internal fingerprint-dedup branch AND stamps the
// X-Idempotent-Replay: true + X-Idempotency-Source: handler-dedup
// response headers per the OpenAPI preamble's "replay headers are
// universal" contract (B13-F4, BugBash 2026-05-20).
//
// Before this helper, handler-internal dedup paths called respondOK
// which writes 200 + body but no replay headers. The body's `note`
// said "Returning your existing resource" but the wire-level signal
// SDKs read — X-Idempotent-Replay — was absent. CLI/SDK code branching
// on the header treated dedup hits as fresh provisions and double-
// consumed quota budgets.
//
// Use on every handler-internal dedup path that returns 200 with an
// existing resource. Continue using respondOK for genuinely-fresh
// 200 responses (e.g. storage presign signed-URL minting).
func respondDedupReplay(c *fiber.Ctx, resp fiber.Map) error {
	c.Set(idempotentReplayHeaderKey, "true")
	c.Set(idempotencySourceHeaderKey, idempotencySourceHandlerDedup)
	return c.JSON(decorateEnvOverride(c, resp))
}
