package compute

import (
	"context"
	"io"
)

// StackServiceDef describes one service within a stack deployment.
type StackServiceDef struct {
	Name    string            // matches service key in instant.yaml; used as k8s Deployment/Service name
	Tarball []byte            // gzipped tar of the build context
	Port    int               // port the service listens on (default 8080)
	Expose  bool              // if true: create k8s Ingress for external access
	EnvVars map[string]string // all env vars, already resolved (service:// replaced)
}

// StackDeployOptions carries everything needed to deploy a multi-service stack.
type StackDeployOptions struct {
	StackID  string            // stack slug, used to derive namespace: "instant-stack-"+StackID
	Tier     string            // "hobby"|"pro"|"team"
	Services []StackServiceDef // must be non-empty
}

// StackNamespace returns the k8s namespace for a stack.
func StackNamespace(stackID string) string {
	return "instant-stack-" + stackID
}

// StackProvider manages multi-service k8s stacks.
type StackProvider interface {
	// DeployStack builds all images in parallel (bounded concurrency), creates the
	// stack namespace with security primitives, injects credentials as a k8s Secret,
	// and creates all service Deployments + Services + optional Ingresses.
	// onUpdate is called for each status transition: (serviceName, status, appURL, errMsg).
	// status values: "building" → "deploying" → "healthy" | "failed"
	// Blocks until all pods are healthy or timeout (10 min). Returns error on failure.
	// On failure: attempts best-effort namespace teardown before returning.
	DeployStack(ctx context.Context, opts StackDeployOptions, onUpdate func(svcName, status, appURL, errMsg string)) error

	// TeardownStack deletes the stack namespace (atomically removes all resources inside).
	TeardownStack(ctx context.Context, stackNamespace string) error

	// ServiceLogs streams logs from a specific service within a stack.
	// follow=true tails the stream; follow=false returns current buffer.
	ServiceLogs(ctx context.Context, stackNamespace, svcName string, follow bool) (io.ReadCloser, error)

	// RedeployStack rebuilds and re-deploys all services. Calls onUpdate per service.
	RedeployStack(ctx context.Context, stackNamespace string, services []StackServiceDef, onUpdate func(svcName, status, appURL, errMsg string)) error
}
