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
//
// Fires onImageBuilt with either svc.ImageRef (promote-style deploy with a
// pre-built image) or a synthetic "noop://<stack>/<svc>" reference so tests
// asserting that image_ref gets persisted on the standard build path can
// match against a non-empty value without spinning up kaniko.
func (n *NoopStackProvider) DeployStack(_ context.Context, opts compute.StackDeployOptions, onUpdate func(svcName, status, appURL, errMsg string), onImageBuilt func(svcName, imageRef string)) error {
	slog.Warn("compute.noop: DeployStack called but compute is disabled",
		"stack_id", opts.StackID,
		"tier", opts.Tier,
		"services", len(opts.Services),
	)
	for _, svc := range opts.Services {
		onUpdate(svc.Name, "building", "", "")
		ref := svc.ImageRef
		if ref == "" {
			ref = "noop://" + opts.StackID + "/" + svc.Name
		}
		if onImageBuilt != nil {
			onImageBuilt(svc.Name, ref)
		}
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
func (n *NoopStackProvider) RedeployStack(_ context.Context, stackNamespace string, services []compute.StackServiceDef, onUpdate func(svcName, status, appURL, errMsg string), onImageBuilt func(svcName, imageRef string)) error {
	slog.Warn("compute.noop: RedeployStack called but compute is disabled",
		"namespace", stackNamespace,
		"services", len(services),
	)
	for _, svc := range services {
		onUpdate(svc.Name, "building", "", "")
		ref := svc.ImageRef
		if ref == "" {
			ref = "noop://" + stackNamespace + "/" + svc.Name
		}
		if onImageBuilt != nil {
			onImageBuilt(svc.Name, ref)
		}
		onUpdate(svc.Name, "deploying", "", "")
		onUpdate(svc.Name, "healthy", "", "")
	}
	return nil
}
