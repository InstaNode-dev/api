package queue

// Package queue handles NATS JetStream provisioning.
//
// NATS runs without authentication (no --auth flag). Any connection is accepted.
// Provision verifies NATS is reachable via its monitoring API before returning
// a connection URL. Subject isolation is by prefix: callers must use subjects
// under their assigned prefix (e.g. "a1b2c3d4.orders", "a1b2c3d4.events").
//
// Connection URL format: nats://{host}:4222
// Subject prefix:        {token_prefix8}.
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

	// SubjectPrefix is the subject namespace for this resource.
	// Callers must use subjects of the form "{SubjectPrefix}{event-name}".
	// Example: if SubjectPrefix is "a1b2c3d4.", use "a1b2c3d4.orders".
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

// Provision verifies NATS is reachable and returns a connection URL for the token.
//
// NATS runs without authentication — the returned URL requires no credentials.
// The SubjectPrefix field defines the subject namespace for this resource.
// If NATS is unreachable, Provision returns an error (synchronous provisioning
// principle: never return a URL for a server that isn't running).
func (p *Provider) Provision(ctx context.Context, token, tier string) (*Credentials, error) {
	// Verify NATS is reachable via monitoring API.
	monitorURL := fmt.Sprintf("http://%s:8222/healthz", p.natsHost)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, monitorURL, nil)
	if err != nil {
		return nil, fmt.Errorf("queue.Provision: build health request: %w", err)
	}
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("queue.Provision: NATS health check failed (%s): %w — is the NATS pod running?", monitorURL, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("queue.Provision: NATS unhealthy (HTTP %d from %s)", resp.StatusCode, monitorURL)
	}

	prefix := token
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	subjectPrefix := prefix + "."
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
	prefix := token
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	slog.Info("queue.Deprovision: subject prefix released (NATS has no per-user state)",
		"token", token,
		"subject_prefix", prefix+".",
	)
	return nil
}
