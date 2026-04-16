package db

// neon.go — NeonBackend calls the Neon Management API to provision isolated Postgres projects.
// Uses net/http only — no external SDK dependency.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
)

const (
	neonAPIBase       = "https://console.neon.tech/api/v2"
	defaultNeonRegion = "aws-us-east-1"
)

// NeonBackend provisions Postgres via the Neon Management API.
type NeonBackend struct {
	apiKey   string
	regionID string
	client   *http.Client
}

// newNeonBackend creates a NeonBackend.
func newNeonBackend(apiKey, regionID string) *NeonBackend {
	if regionID == "" {
		regionID = defaultNeonRegion
	}
	return &NeonBackend{
		apiKey:   apiKey,
		regionID: regionID,
		client:   &http.Client{},
	}
}

// Provision creates a new Neon project for the given token.
// POST https://console.neon.tech/api/v2/projects
func (b *NeonBackend) Provision(ctx context.Context, token, tier string) (*Credentials, error) {
	body := map[string]any{
		"project": map[string]any{
			"name":       "instant-" + token,
			"region_id":  b.regionID,
			"pg_version": 16,
		},
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("db.neon.Provision: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, neonAPIBase+"/projects", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("db.neon.Provision: new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+b.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("db.neon.Provision: http: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("db.neon.Provision: read body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("db.neon.Provision: unexpected status %d: %s", resp.StatusCode, string(respBytes))
	}

	var result struct {
		Project struct {
			ID string `json:"id"`
		} `json:"project"`
		ConnectionURIs []struct {
			ConnectionURI string `json:"connection_uri"`
		} `json:"connection_uris"`
	}
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return nil, fmt.Errorf("db.neon.Provision: unmarshal: %w", err)
	}

	if result.Project.ID == "" {
		return nil, fmt.Errorf("db.neon.Provision: empty project ID in response")
	}
	if len(result.ConnectionURIs) == 0 || result.ConnectionURIs[0].ConnectionURI == "" {
		return nil, fmt.Errorf("db.neon.Provision: no connection URI in response")
	}

	slog.Info("db.neon.Provision: provisioned",
		"token", token,
		"project_id", result.Project.ID,
		"tier", tier,
	)

	return &Credentials{
		URL:                result.ConnectionURIs[0].ConnectionURI,
		DatabaseName:       "neondb",
		Username:           "",
		ProviderResourceID: result.Project.ID,
	}, nil
}

// StorageBytes returns data_storage_bytes_hour for the Neon project.
// GET https://console.neon.tech/api/v2/projects/{providerResourceID}
func (b *NeonBackend) StorageBytes(ctx context.Context, token, providerResourceID string) (int64, error) {
	if providerResourceID == "" {
		return 0, fmt.Errorf("db.neon.StorageBytes: empty providerResourceID")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		neonAPIBase+"/projects/"+providerResourceID, nil)
	if err != nil {
		return 0, fmt.Errorf("db.neon.StorageBytes: new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+b.apiKey)

	resp, err := b.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("db.neon.StorageBytes: http: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("db.neon.StorageBytes: read body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("db.neon.StorageBytes: unexpected status %d: %s", resp.StatusCode, string(respBytes))
	}

	var result struct {
		Project struct {
			Usage struct {
				DataStorageBytesHour int64 `json:"data_storage_bytes_hour"`
			} `json:"usage"`
		} `json:"project"`
	}
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return 0, fmt.Errorf("db.neon.StorageBytes: unmarshal: %w", err)
	}

	return result.Project.Usage.DataStorageBytesHour, nil
}

// Deprovision deletes the Neon project.
// DELETE https://console.neon.tech/api/v2/projects/{providerResourceID}
func (b *NeonBackend) Deprovision(ctx context.Context, token, providerResourceID string) error {
	if providerResourceID == "" {
		return fmt.Errorf("db.neon.Deprovision: empty providerResourceID")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		neonAPIBase+"/projects/"+providerResourceID, nil)
	if err != nil {
		return fmt.Errorf("db.neon.Deprovision: new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+b.apiKey)

	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("db.neon.Deprovision: http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("db.neon.Deprovision: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	slog.Info("db.neon.Deprovision: deprovisioned", "token", token, "project_id", providerResourceID)
	return nil
}
