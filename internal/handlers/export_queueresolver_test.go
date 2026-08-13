package handlers

// export_queueresolver_test.go — test-only re-exports for the NATS
// resolver-pusher wiring slice (queue_provider.go attachResolverPusher /
// natsSystemURL / isolationUnavailable / unavailableCredProvider and
// queue.go failQueueCredIssue).
//
// Kept in its own file (not the shared export_provarms_test.go) so concurrent
// work on other handler slices never collides here. Go only compiles it in
// test builds.

import (
	"github.com/gofiber/fiber/v2"

	"instant.dev/common/queueprovider"
	natsqp "instant.dev/common/queueprovider/nats"
	"instant.dev/internal/config"
	"instant.dev/internal/models"
	"instant.dev/internal/natsresolver"
)

// SwapResolverPusherFactoryForTest replaces the system-account pusher
// constructor and returns a restore func, so the attach / skip / fail arms of
// attachResolverPusher can be driven without a NATS server.
func SwapResolverPusherFactoryForTest(
	fn func(natsresolver.Config) (natsqp.ResolverPusher, error),
) (restore func()) {
	prev := newResolverPusher
	newResolverPusher = fn
	return func() { newResolverPusher = prev }
}

// NATSSystemURLForTest re-exports natsSystemURL.
func NATSSystemURLForTest(cfg *config.Config) string { return natsSystemURL(cfg) }

// IsolationUnavailableForTest re-exports isolationUnavailable.
func IsolationUnavailableForTest(err error) bool { return isolationUnavailable(err) }

// NewUnavailableCredProviderForTest re-exports the stand-in provider installed
// when isolation is configured but could not be initialised.
func NewUnavailableCredProviderForTest(cause error) queueprovider.QueueCredentialProvider {
	return unavailableCredProvider{cause: cause}
}

// FailQueueCredIssueForTest re-exports QueueHandler.failQueueCredIssue so the
// mark-failed-error log branch can be driven with a closed DB.
func (h *QueueHandler) FailQueueCredIssueForTest(
	c *fiber.Ctx, resource *models.Resource, prid, token, logPrefix string, cause error,
) error {
	return h.failQueueCredIssue(c, resource, prid, token, logPrefix, cause)
}
