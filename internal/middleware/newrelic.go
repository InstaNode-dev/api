package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/newrelic/go-agent/v3/newrelic"
)

// LocalKeyNRTxn is the Fiber locals key under which the per-request New
// Relic transaction is stored. Handlers that want to add custom
// attributes / segments to the active transaction read this key.
const LocalKeyNRTxn = "nr_txn"

// NewRelic returns a Fiber middleware that opens a New Relic transaction
// per request (named after the matched route path, e.g. "/db/new") and
// ends it when the handler returns. The transaction is stashed in Fiber
// locals under LocalKeyNRTxn for downstream handler use.
//
// nrApp may be nil — when the license key was missing or invalid the
// agent init returned nil and we degrade to a no-op middleware so the
// rest of the stack runs unchanged (fail-open contract, matching
// telemetry.InitTracer).
func NewRelic(nrApp *newrelic.Application) fiber.Handler {
	if nrApp == nil {
		return func(c *fiber.Ctx) error { return c.Next() }
	}
	return func(c *fiber.Ctx) error {
		// c.Route() is reliable from inside a handler chain — Fiber has
		// already matched the route by the time middleware runs. Fall
		// back to the raw path if for some reason the route is empty
		// (e.g. 404 path) so the transaction name is never blank.
		name := c.Route().Path
		if name == "" {
			name = c.Path()
		}
		txn := nrApp.StartTransaction(name)
		defer txn.End()

		// Make the transaction visible to handler code (custom segments,
		// custom attributes) without forcing every handler to look up
		// the agent app.
		c.Locals(LocalKeyNRTxn, txn)

		err := c.Next()
		if err != nil {
			txn.NoticeError(err)
		}
		// Stamp the response status so the transaction's web breakdown
		// reflects the real HTTP outcome (Fiber writes the status
		// during c.Next() so c.Response().StatusCode() is final here).
		txn.SetWebResponse(nil).WriteHeader(c.Response().StatusCode())
		return err
	}
}

// GetNRTxn returns the New Relic transaction attached to the current
// Fiber context, or nil when the agent is disabled. Safe for handlers
// to call unconditionally; NR's API treats nil as a no-op.
func GetNRTxn(c *fiber.Ctx) *newrelic.Transaction {
	if v, ok := c.Locals(LocalKeyNRTxn).(*newrelic.Transaction); ok {
		return v
	}
	return nil
}
