package compute

import (
	"context"
	"io"
	"time"
)

// DeployOptions describes an app deployment request.
//
// Private / AllowedIPs are the access-control fields wired by Track A of the
// private-deploys feature (migration 020). The compute provider treats them
// as a single unit: when Private is true, the resulting Ingress carries the
// nginx whitelist annotation with AllowedIPs comma-joined; when false (the
// zero value), the Ingress is created exactly as before — no annotation, no
// behaviour change for existing public deploys.
//
// Validation of AllowedIPs (CIDR / IP parsing, max 32 entries, non-empty
// when Private=true) lives in the handler — the compute layer trusts the
// caller and is reused unchanged for both public and private deploys.
type DeployOptions struct {
	AppID      string            // short slug, used as k8s Deployment name and subdomain
	Token      string            // instant.dev resource token (for env var injection)
	TeamID     string            // owning team UUID — used to scope the NetworkPolicy DB-port egress rule to the team's own customer-resource namespaces (pentest fix 2026-05-16)
	Tarball    []byte            // gzipped tar archive of the source directory (must contain Dockerfile). Empty when Source=="image".
	EnvVars    map[string]string // merged: infra resource URLs + user-defined vars
	Port       int               // port the app listens on (default 8080)
	Tier       string            // hobby|pro|team → resource requests/limits
	Private    bool              // true → Ingress carries whitelist-source-range annotation
	AllowedIPs []string          // CIDRs / IPs allowed when Private=true; ignored otherwise

	// Source selects how the app image is obtained: "tarball" (default — build
	// the uploaded Tarball with Kaniko) or "image" (BYO — deploy ImageRef
	// directly, no build pod). Empty is treated as "tarball" for back-compat.
	Source string
	// ImageRef is the fully-qualified prebuilt image (host/path[:tag][@digest])
	// deployed directly when Source=="image". Ignored otherwise.
	ImageRef string
	// RegistryAuth is an optional docker config JSON for pulling a private
	// ImageRef. Empty → the namespace's default ghcr-pull secret is used.
	RegistryAuth string
	// GitURL is the clone URL built directly by Kaniko's git context when
	// Source=="git" (no tarball upload). Ignored otherwise.
	GitURL string
	// GitRef is the branch/tag/commit Kaniko checks out; empty → default branch.
	GitRef string
	// GitAuth is an optional read-only token for a private GitURL, injected as
	// Kaniko's GIT_PASSWORD. Empty → the repo is treated as public.
	GitAuth string
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

	// Scale patches the app's k8s Deployment replica count in place — no
	// image rebuild, no namespace change. Backs scale-to-zero (Task #54):
	// the worker idle-scaler calls Scale(appID, 0) to deschedule an idle app
	// (~$0 compute), and the wake path calls Scale(appID, 1) to bring it back.
	// Implementations on backends without a real Deployment concept (noop,
	// local-dev without a cluster) should return nil after a slog.Warn — the
	// DB-only state flip (deployments.scaled_to_zero) is the user-visible
	// change. A NotFound Deployment is NOT an error: an app whose namespace
	// was already torn down is treated as a no-op so a stale idle row can't
	// wedge the scaler.
	Scale(ctx context.Context, appID string, replicas int32) error

	// UpdateAccessControl patches the access-control annotations on an
	// existing deploy's Ingress in place — no image rebuild, no pod restart.
	// Backs PATCH /api/v1/deployments/:id for the private + allowed_ips
	// edit flow. private=false strips the whitelist annotation; private=true
	// with non-empty allowedIPs sets it (REPLACE semantics — the supplied
	// list is the new truth). Implementations on backends without a real
	// Ingress concept (noop, local-dev without DEPLOY_DOMAIN) should return
	// nil after a slog.Warn — the DB-only update is the user-visible change.
	UpdateAccessControl(ctx context.Context, appID string, private bool, allowedIPs []string) error
}

// BuildLogFetcher is an optional, server-side-only interface that compute
// providers may implement so the platform can SNAPSHOT build-job logs at the
// moment of failure. Handlers type-assert against it so non-k8s providers
// (noop, test doubles) silently opt out without changing the core Provider
// interface.
//
// IMPORTANT — this is NOT an exposure surface:
//
//   - It is called exactly once, server-side, inside the async runDeploy
//     goroutine, the instant a build fails. The lines it returns are persisted
//     into deployment_events.last_lines (a column in the platform DB).
//   - GET /deploy/:id then serves that stored snapshot straight from the
//     platform DB — it never calls back into k8s, never proxies the cluster,
//     and never hands the caller a path or credential into build infra.
//   - This mirrors how GitHub Actions / CircleCI / Render capture build logs:
//     run → capture → persist snapshot → serve the snapshot from the product's
//     own store. The build infrastructure stays fully behind the API boundary.
//
// Do NOT wire FetchBuildLogs into an HTTP route. The user-facing contract is
// the immutable "failure.last_lines" snapshot on GET /deploy/:id, not a live
// tail of the build cluster.
//
// FetchBuildLogs lists pods for the build job named "build-<appID>" in the
// deploy namespace "instant-deploy-<appID>", reads the "kaniko" container's
// stdout, and returns the last ≤200 lines. If the pod is already gone or logs
// cannot be fetched for any reason, implementations MUST return (nil, err)
// — callers treat nil as "logs unavailable" and write the autopsy row with
// an empty last_lines slice (fail-soft).
type BuildLogFetcher interface {
	FetchBuildLogs(ctx context.Context, appID string) ([]string, error)
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

// TierEphemeralStorage returns the ephemeral-storage request and limit for a
// tier. Ephemeral storage bounds the container's writable layer + /tmp usage;
// without it a single rogue pod can fill the node disk and trigger cluster-wide
// DiskPressure → pod eviction across all tenants (noisy-neighbour DoS).
//
// Values are deliberately conservative for shared tiers (hobby/anonymous):
//   - request 512Mi: scheduler can place the pod on a node with enough runway
//   - limit   2Gi:   k8s evicts THIS pod (only) when it exceeds the cap
//
// Pro and team tiers get proportionally more headroom.
func TierEphemeralStorage(tier string) (ephemeralStorageRequest, ephemeralStorageLimit string) {
	switch tier {
	case "pro":
		return "1Gi", "4Gi"
	case "team":
		return "2Gi", "8Gi"
	default: // hobby + anonymous
		return "512Mi", "2Gi"
	}
}
