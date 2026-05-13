// Package noop provides a no-op compute Provider that returns placeholder values
// without performing any real work. Used when COMPUTE_PROVIDER is not set or
// set to "noop".
package noop

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"time"

	"instant.dev/internal/providers/compute"
)

// NoopProvider returns placeholder responses without doing any real work.
// Used when COMPUTE_PROVIDER is not set or set to "noop".
type NoopProvider struct{}

// New returns a NoopProvider.
func New() *NoopProvider { return &NoopProvider{} }

// Deploy logs a warning and returns a fake healthy deployment.
func (n *NoopProvider) Deploy(_ context.Context, opts compute.DeployOptions) (*compute.AppDeployment, error) {
	slog.Warn("compute.noop: Deploy called but compute is disabled",
		"app_id", opts.AppID,
		"tier", opts.Tier,
	)
	return &compute.AppDeployment{
		ProviderID: "noop-" + opts.AppID,
		AppURL:     "http://localhost:0",
		Status:     "healthy",
		UpdatedAt:  time.Now(),
	}, nil
}

// Status logs a warning and returns a fake healthy deployment.
func (n *NoopProvider) Status(_ context.Context, providerID string) (*compute.AppDeployment, error) {
	slog.Warn("compute.noop: Status called but compute is disabled",
		"provider_id", providerID,
	)
	return &compute.AppDeployment{
		ProviderID: providerID,
		AppURL:     "http://localhost:0",
		Status:     "healthy",
		UpdatedAt:  time.Now(),
	}, nil
}

// Logs logs a warning and returns an empty reader.
func (n *NoopProvider) Logs(_ context.Context, providerID string, follow bool) (io.ReadCloser, error) {
	slog.Warn("compute.noop: Logs called but compute is disabled",
		"provider_id", providerID,
		"follow", follow,
	)
	return io.NopCloser(strings.NewReader("")), nil
}

// Teardown logs a warning and returns nil.
func (n *NoopProvider) Teardown(_ context.Context, providerID string) error {
	slog.Warn("compute.noop: Teardown called but compute is disabled",
		"provider_id", providerID,
	)
	return nil
}

// Redeploy logs a warning and returns a fake healthy deployment.
func (n *NoopProvider) Redeploy(_ context.Context, providerID string, _ []byte, _ map[string]string) (*compute.AppDeployment, error) {
	slog.Warn("compute.noop: Redeploy called but compute is disabled",
		"provider_id", providerID,
	)
	return &compute.AppDeployment{
		ProviderID: providerID,
		AppURL:     "http://localhost:0",
		Status:     "healthy",
		UpdatedAt:  time.Now(),
	}, nil
}

// UpdateAccessControl logs a warning and returns nil. Tests use this — the
// DB-only update is the user-visible change.
func (n *NoopProvider) UpdateAccessControl(_ context.Context, appID string, private bool, allowedIPs []string) error {
	slog.Warn("compute.noop: UpdateAccessControl called but compute is disabled",
		"app_id", appID,
		"private", private,
		"allowed_ip_count", len(allowedIPs),
	)
	return nil
}
