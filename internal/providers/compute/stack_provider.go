package compute

import (
	"context"
	"io"
)

// StackServiceDef describes one service within a stack deployment.
//
// ImageRef + SkipBuild together let the /promote path re-use a source
// stack's cached image instead of building a new one. When SkipBuild is true
// the provider MUST NOT invoke kaniko; it deploys using ImageRef directly.
// The handler sets these only when copying services off a source stack —
// /stacks/new and /stacks/:slug/redeploy always leave them at the zero value
// so the provider builds normally.
type StackServiceDef struct {
	Name      string            // matches service key in instant.yaml; used as k8s Deployment/Service name
	Tarball   []byte            // gzipped tar of the build context (ignored when SkipBuild=true)
	Port      int               // port the service listens on (default 8080)
	Expose    bool              // if true: create k8s Ingress for external access
	EnvVars   map[string]string // all env vars, already resolved (service:// replaced)
	ImageRef  string            // when SkipBuild=true: deploy this image instead of building
	SkipBuild bool              // when true: skip the build step and use ImageRef
}

// StackDeployOptions carries everything needed to deploy a multi-service stack.
type StackDeployOptions struct {
	StackID  string            // stack slug, used to derive namespace: "instant-stack-"+StackID
	TeamID   string            // owning team UUID — used to scope the NetworkPolicy DB-port egress rule to the team's own customer-resource namespaces (pentest fix 2026-05-16)
	Tier     string            // "hobby"|"pro"|"team"
	Services []StackServiceDef // must be non-empty
}

// StackNamespace returns the k8s namespace for a stack.
func StackNamespace(stackID string) string {
	return "instant-stack-" + stackID
}

// StackProvider manages multi-service k8s stacks.
//
// The onImageBuilt callback parameter on DeployStack and RedeployStack is
// fired once per service after a successful image build (or once per service
// at provider entry when SkipBuild=true). The handler uses it to persist
// the image reference into stack_services.image_ref so subsequent /promote
// calls can re-use the image instead of rebuilding.
type StackProvider interface {
	// DeployStack builds all images in parallel (bounded concurrency), creates the
	// stack namespace with security primitives, injects credentials as a k8s Secret,
	// and creates all service Deployments + Services + optional Ingresses.
	// onUpdate is called for each status transition: (serviceName, status, appURL, errMsg).
	// status values: "building" → "deploying" → "healthy" | "failed"
	// onImageBuilt is called once per service immediately after the build step
	// completes (or once per service at entry if SkipBuild=true) with the image
	// reference the provider intends to deploy. Persist into stack_services.image_ref.
	// Blocks until all pods are healthy or timeout (10 min). Returns error on failure.
	// On failure: attempts best-effort namespace teardown before returning.
	DeployStack(ctx context.Context, opts StackDeployOptions, onUpdate func(svcName, status, appURL, errMsg string), onImageBuilt func(svcName, imageRef string)) error

	// TeardownStack deletes the stack namespace (atomically removes all resources inside).
	TeardownStack(ctx context.Context, stackNamespace string) error

	// ServiceLogs streams logs from a specific service within a stack.
	// follow=true tails the stream; follow=false returns current buffer.
	ServiceLogs(ctx context.Context, stackNamespace, svcName string, follow bool) (io.ReadCloser, error)

	// RedeployStack rebuilds and re-deploys all services. Calls onUpdate per service.
	// onImageBuilt fires per service after each successful rebuild — same contract
	// as DeployStack so the handler can keep image_ref current across redeploys.
	RedeployStack(ctx context.Context, stackNamespace string, services []StackServiceDef, onUpdate func(svcName, status, appURL, errMsg string), onImageBuilt func(svcName, imageRef string)) error
}
