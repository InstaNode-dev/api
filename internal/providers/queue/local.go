package queue

// Package queue handles NATS JetStream provisioning.
//
// NATS runs without authentication (no --auth flag). Any connection is accepted.
// Provision verifies NATS is reachable via its monitoring API before returning
// a connection URL. Subject isolation is by prefix: callers must use subjects
// under their assigned prefix (e.g. "a1b2c3d4.orders", "a1b2c3d4.events").
//
// Connection URL format: nats://{host}:4222
// Subject prefix:        {full_token}.  (dashes stripped — see subjident.go)
//
// Deprovision is a no-op — the NATS server has no per-user state to clean up
// because it runs without authentication.

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// Credentials holds the NATS connection details returned after provisioning.
type Credentials struct {
	// URL is the nats:// connection string. Format: nats://{host}:4222
	// NATS runs without authentication — no credentials are embedded.
	URL string

	// SubjectPrefix is the subject namespace for this resource. It is derived
	// from the FULL token (dashes stripped) — see subjident.go. On the shared
	// no-auth NATS backend this prefix is the ONLY tenant-isolation boundary,
	// so it must NOT be truncated (P1-W4-04). Callers must use subjects of the
	// form "{SubjectPrefix}{event-name}".
	SubjectPrefix string

	// ProviderResourceID is the k8s namespace for dedicated (pro/team) provisions.
	// Empty for shared NATS cluster provisions.
	ProviderResourceID string
}

// Provider manages NATS JetStream provisioning.
type Provider struct {
	natsHost string // e.g. "nats.instant-data.svc.cluster.local"
	httpClient *http.Client
}

// New creates a Provider.
func New(natsHost string) *Provider {
	if natsHost == "" {
		natsHost = "localhost"
	}
	return &Provider{
		natsHost: natsHost,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

// monitorHealthURL builds the NATS monitoring /healthz URL for a host. It is a
// package var (not a method) purely as a test seam: tests point it at an
// httptest.Server so the reachable/healthy and unhealthy-status branches of
// Provision can be exercised without a real NATS pod. Production keeps the real
// "http://{host}:8222/healthz" form.
var monitorHealthURL = func(natsHost string) string {
	return fmt.Sprintf("http://%s:8222/healthz", natsHost)
}

// Provision verifies NATS is reachable and returns a connection URL for the token.
//
// NATS runs without authentication — the returned URL requires no credentials.
// The SubjectPrefix field defines the subject namespace for this resource.
// If NATS is unreachable, Provision returns an error (synchronous provisioning
// principle: never return a URL for a server that isn't running).
func (p *Provider) Provision(ctx context.Context, token, tier string) (*Credentials, error) {
	// Verify NATS is reachable via monitoring API.
	monitorURL := monitorHealthURL(p.natsHost)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, monitorURL, nil)
	if err != nil {
		return nil, fmt.Errorf("queue.Provision: build health request: %w", err)
	}
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("queue.Provision: NATS health check failed (%s): %w — is the NATS pod running?", monitorURL, err)
	}
	_ = resp.Body.Close() // health check only reads StatusCode; body discarded
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("queue.Provision: NATS unhealthy (HTTP %d from %s)", resp.StatusCode, monitorURL)
	}

	// SubjectPrefix is derived from the FULL token (subjident.go). On the
	// shared no-auth NATS backend this prefix is the ONLY tenant-isolation
	// boundary — truncating it to token[:8] let any two tokens that share 8
	// hex chars publish/subscribe to each other's subjects (P1-W4-04).
	subjectPrefix := canonicalSubjectPrefix(token)
	url := fmt.Sprintf("nats://%s:4222", p.natsHost)

	slog.Info("queue.Provision: NATS healthy, connection URL issued",
		"token", token,
		"subject_prefix", subjectPrefix,
		"tier", tier,
	)

	return &Credentials{
		URL:           url,
		SubjectPrefix: subjectPrefix,
	}, nil
}

// Deprovision is a no-op. NATS runs without per-user state — there is nothing
// to delete on the server. The subject prefix is simply abandoned.
func (p *Provider) Deprovision(_ context.Context, token string) error {
	// resolveSubjectPrefix returns the canonical full-token prefix. The shared
	// NATS backend has no per-user server state to delete, so this is a
	// structural no-op; resolving the prefix keeps the log line truthful for
	// resources provisioned both before and after the P1-W4-04 fix.
	slog.Info("queue.Deprovision: subject prefix released (NATS has no per-user state)",
		"token", token,
		"subject_prefix", resolveSubjectPrefix(token, ""),
	)
	return nil
}
