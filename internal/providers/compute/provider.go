package compute

import (
	"context"
	"io"
	"time"
)

// DeployOptions describes an app deployment request.
type DeployOptions struct {
	AppID   string            // short slug, used as k8s Deployment name and subdomain
	Token   string            // instant.dev resource token (for env var injection)
	Tarball []byte            // gzipped tar archive of the source directory (must contain Dockerfile)
	EnvVars map[string]string // merged: infra resource URLs + user-defined vars
	Port    int               // port the app listens on (default 8080)
	Tier    string            // hobby|pro|team → resource requests/limits
}

// AppDeployment represents the live state of a deployed app.
type AppDeployment struct {
	ProviderID string    // k8s Deployment name
	AppURL     string    // http://localhost:{nodePort} (local) or https://{appID}.instant.dev
	Status     string    // building|deploying|healthy|failed|stopped
	UpdatedAt  time.Time
}

// Provider is the compute backend interface.
type Provider interface {
	// Deploy builds the container image and creates/updates the k8s Deployment.
	// Returns immediately with Status="building"; caller polls Status().
	Deploy(ctx context.Context, opts DeployOptions) (*AppDeployment, error)

	// Status returns the current deployment state.
	Status(ctx context.Context, providerID string) (*AppDeployment, error)

	// Logs returns a ReadCloser streaming build/runtime logs.
	// follow=true tails the logs; follow=false returns current buffer.
	Logs(ctx context.Context, providerID string, follow bool) (io.ReadCloser, error)

	// Teardown stops and deletes the Deployment and Service.
	Teardown(ctx context.Context, providerID string) error

	// Redeploy rebuilds the image from a new tarball and rolls out.
	Redeploy(ctx context.Context, providerID string, tarball []byte, envVars map[string]string) (*AppDeployment, error)
}

// TierResources returns k8s resource requests/limits for a tier.
func TierResources(tier string) (memoryRequest, memoryLimit, cpuRequest string) {
	switch tier {
	case "pro":
		return "256Mi", "512Mi", "250m"
	case "team":
		return "512Mi", "2Gi", "500m"
	default: // hobby + anonymous
		return "64Mi", "256Mi", "50m"
	}
}
