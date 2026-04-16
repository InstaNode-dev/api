package migratorclient

// client.go — lightweight HTTP client for the migrator service.
// Called from the billing webhook and dev set-tier handler to trigger
// background data migrations when a team upgrades to pro or team tier.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// Client calls the migrator HTTP API.
type Client struct {
	addr   string // e.g. "http://instant-migrator.instant-infra.svc.cluster.local:8090"
	secret string
	http   *http.Client
}

// New creates a Client. If addr is empty the client is a no-op (migrator not configured).
func New(addr, secret string) *Client {
	return &Client{
		addr:   addr,
		secret: secret,
		http:   &http.Client{Timeout: 10 * time.Second},
	}
}

// MigrationRequest holds the parameters for a single resource migration.
type MigrationRequest struct {
	ResourceID   string // UUID of the resource row in the platform DB
	ResourceType string // "postgres" | "redis" | "mongodb"
	Token        string // resource token UUID (used to name the target provisioning call)
	SourceTier   string // current tier before upgrade
	TargetTier   string // target tier after upgrade ("pro" | "team")
	SourceURL    string // plaintext connection URL of the current (shared) resource
	RequestID    string // optional; propagated for log correlation
}

// Trigger fires a migration job and returns immediately — the migrator runs it async.
// Returns nil when the migrator is not configured (addr == ""), so callers can always
// call this without checking.
func (c *Client) Trigger(ctx context.Context, req MigrationRequest) error {
	if c == nil || c.addr == "" {
		return nil
	}

	body := map[string]string{
		"migration_id":  uuid.New().String(),
		"resource_id":   req.ResourceID,
		"resource_type": req.ResourceType,
		"token":         req.Token,
		"source_tier":   req.SourceTier,
		"target_tier":   req.TargetTier,
		"source_url":    req.SourceURL,
		"request_id":    req.RequestID,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("migratorclient.Trigger: marshal: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.addr+"/migrations", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("migratorclient.Trigger: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Migrator-Secret", c.secret)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("migratorclient.Trigger: do: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("migratorclient.Trigger: unexpected status %d", resp.StatusCode)
	}
	return nil
}
