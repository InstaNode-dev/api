// Package obs holds observability bootstrap helpers shared across the
// worker binary. Today it has one job: build a New Relic Application from
// env vars and never crash when the license key is missing.
//
// Track 4 of the observability rollout (OBSERVABILITY-PLAN-2026-05-12.md).
// The api and provisioner services have parallel helpers under their own
// internal/obs packages — each owns its own copy to keep service boundaries
// clean. The contract (fail-open, log-only warning, return nil app) is
// identical across all three.
package obs

import (
	"log/slog"
	"os"
	"time"

	"github.com/newrelic/go-agent/v3/newrelic"
)

// nrInitTimeout caps how long ConnectReply may block on bootstrap. The Go
// agent connects async by default, so this is a guard for the rare case where
// caller code waits on `WaitForConnection`.
const nrInitTimeout = 5 * time.Second

// InitNewRelic returns a *newrelic.Application built from environment.
//
// Contract: NEVER crash. NEW_RELIC_LICENSE_KEY is the only required input;
// when it is empty (local dev, CI, k8s pod without the secret mounted yet)
// we log a warning and return (nil, nil). Every caller MUST nil-check the
// returned application before invoking methods on it — `(*nrApp).StartTransaction`
// is a nil-safe no-op in the v3 SDK, but defensive callers should still guard.
//
// The license-key-present path can still fail (network down, malformed key,
// duplicate registration). In that case we log the underlying error and
// return (nil, err) so the caller can surface it but keep running. The worker
// pod must not crashloop because New Relic is unhappy.
func InitNewRelic() (*newrelic.Application, error) {
	licenseKey := os.Getenv("NEW_RELIC_LICENSE_KEY")
	if licenseKey == "" {
		slog.Warn("obs.newrelic.skipped",
			"reason", "NEW_RELIC_LICENSE_KEY not set",
			"behavior", "transactions are no-ops, worker continues")
		return nil, nil
	}

	appName := os.Getenv("NEW_RELIC_APP_NAME")
	if appName == "" {
		appName = "instant-worker"
	}

	app, err := newrelic.NewApplication(
		newrelic.ConfigAppName(appName),
		newrelic.ConfigLicense(licenseKey),
		newrelic.ConfigAppLogForwardingEnabled(true),
		newrelic.ConfigDistributedTracerEnabled(true),
		// Fail-open at the SDK level too: don't crash if the daemon can't be
		// reached, just suppress the noisy harvest-cycle errors.
		func(cfg *newrelic.Config) {
			cfg.ErrorCollector.Enabled = true
			cfg.TransactionTracer.Enabled = true
		},
	)
	if err != nil {
		slog.Warn("obs.newrelic.init_failed",
			"error", err,
			"behavior", "transactions are no-ops, worker continues")
		return nil, err
	}

	slog.Info("obs.newrelic.initialised", "app_name", appName)
	return app, nil
}

// WaitForConnection is a thin wrapper around app.WaitForConnection that does
// nothing when app is nil. Use only from tests or boot code that wants the
// agent fully connected before proceeding; production code paths should never
// block on this.
func WaitForConnection(app *newrelic.Application) {
	if app == nil {
		return
	}
	_ = app.WaitForConnection(nrInitTimeout)
}
