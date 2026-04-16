package noop

import (
	"context"
	"io"
	"log/slog"
	"strings"

	"instant.dev/internal/providers/compute"
)

// NoopStackProvider returns placeholder responses without doing any real work.
// Used when COMPUTE_PROVIDER is "noop" or unset.
type NoopStackProvider struct{}

// NewStack returns a NoopStackProvider.
func NewStack() *NoopStackProvider { return &NoopStackProvider{} }

// DeployStack logs a warning and immediately reports all services as healthy.
func (n *NoopStackProvider) DeployStack(_ context.Context, opts compute.StackDeployOptions, onUpdate func(svcName, status, appURL, errMsg string)) error {
	slog.Warn("compute.noop: DeployStack called but compute is disabled",
		"stack_id", opts.StackID,
		"tier", opts.Tier,
		"services", len(opts.Services),
	)
	for _, svc := range opts.Services {
		onUpdate(svc.Name, "building", "", "")
		onUpdate(svc.Name, "deploying", "", "")
		onUpdate(svc.Name, "healthy", "", "")
	}
	return nil
}

// TeardownStack logs a warning and returns nil.
func (n *NoopStackProvider) TeardownStack(_ context.Context, stackNamespace string) error {
	slog.Warn("compute.noop: TeardownStack called but compute is disabled",
		"namespace", stackNamespace,
	)
	return nil
}

// ServiceLogs logs a warning and returns an empty reader.
func (n *NoopStackProvider) ServiceLogs(_ context.Context, stackNamespace, svcName string, follow bool) (io.ReadCloser, error) {
	slog.Warn("compute.noop: ServiceLogs called but compute is disabled",
		"namespace", stackNamespace,
		"service", svcName,
		"follow", follow,
	)
	return io.NopCloser(strings.NewReader("noop: no logs available")), nil
}

// RedeployStack logs a warning and immediately reports all services as healthy.
func (n *NoopStackProvider) RedeployStack(_ context.Context, stackNamespace string, services []compute.StackServiceDef, onUpdate func(svcName, status, appURL, errMsg string)) error {
	slog.Warn("compute.noop: RedeployStack called but compute is disabled",
		"namespace", stackNamespace,
		"services", len(services),
	)
	for _, svc := range services {
		onUpdate(svc.Name, "building", "", "")
		onUpdate(svc.Name, "deploying", "", "")
		onUpdate(svc.Name, "healthy", "", "")
	}
	return nil
}
