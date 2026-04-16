//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// provisionNewResponse is the shared response shape for /db/new, /cache/new, /nosql/new.
type provisionNewResponse struct {
	OK            bool           `json:"ok"`
	ID            string         `json:"id"`
	Token         string         `json:"token"`
	Name          string         `json:"name"`
	ConnectionURL string         `json:"connection_url"`
	KeyPrefix     string         `json:"key_prefix,omitempty"` // Redis: ACL-enforced key namespace prefix
	Tier          string         `json:"tier"`
	Limits        map[string]any `json:"limits"`
	Note          string         `json:"note"`
	Upgrade       string         `json:"upgrade,omitempty"`
}

// redisKeyPrefix returns the key prefix to use for a provisioned Redis cache.
// When key_prefix is present in the response (pool-based provisioning), that prefix
// is used. Otherwise falls back to token+":" (live provisioning convention).
func (r *provisionNewResponse) redisKeyPrefix() string {
	if r.KeyPrefix != "" {
		return r.KeyPrefix
	}
	return r.Token + ":"
}

// TestE2E_DBProvision_Returns201 verifies that POST /db/new returns 201 with
// the required fields when the postgres service is enabled on the live server.
// The test is skipped (not failed) when the service returns 503 — this is safe
// to run before Phase 2 is live.
func TestE2E_DBProvision_Returns201(t *testing.T) {
	ip := uniqueIP(t)
	resp := post(t, "/db/new", nil, "X-Forwarded-For", ip)

	if resp.StatusCode == http.StatusServiceUnavailable {
		readBody(t, resp)
		t.Skip("service not enabled in Phase 2/3/4")
	}

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /db/new: want 201, got %d\n%s", resp.StatusCode, readBody(t, resp))
	}

	var body provisionNewResponse
	decodeJSON(t, resp, &body)

	if !body.OK {
		t.Error("ok field must be true")
	}
	if body.Token == "" {
		t.Error("token field must not be empty")
	}
	if body.ConnectionURL == "" {
		t.Error("connection_url field must not be empty")
	}
	if !strings.HasPrefix(body.ConnectionURL, "postgres://") {
		t.Errorf("connection_url must start with postgres://; got %q", body.ConnectionURL)
	}
	if body.Tier == "" {
		t.Error("tier field must not be empty")
	}
	if body.Limits == nil {
		t.Error("limits field must not be nil")
	}
}

// TestE2E_DBProvision_XInstantUpgradeHeader verifies that POST /db/new sets the
// X-Instant-Upgrade response header on a successful provision.
func TestE2E_DBProvision_XInstantUpgradeHeader(t *testing.T) {
	ip := uniqueIP(t)
	resp := post(t, "/db/new", nil, "X-Forwarded-For", ip)

	if resp.StatusCode == http.StatusServiceUnavailable {
		readBody(t, resp)
		t.Skip("service not enabled in Phase 2/3/4")
	}

	upgrade := resp.Header.Get("X-Instant-Upgrade")
	readBody(t, resp)

	if upgrade == "" {
		t.Fatal("POST /db/new: X-Instant-Upgrade header must be present")
	}
	if !strings.Contains(upgrade, "/start?t=") {
		t.Errorf("X-Instant-Upgrade must contain /start?t=, got: %q", upgrade)
	}
}

// TestE2E_DBProvision_TokenIsValidUUID verifies that the token returned by
// POST /db/new is a valid UUID.
func TestE2E_DBProvision_TokenIsValidUUID(t *testing.T) {
	ip := uniqueIP(t)
	resp := post(t, "/db/new", nil, "X-Forwarded-For", ip)

	if resp.StatusCode == http.StatusServiceUnavailable {
		readBody(t, resp)
		t.Skip("service not enabled in Phase 2/3/4")
	}

	var body provisionNewResponse
	decodeJSON(t, resp, &body)

	if _, err := uuid.Parse(body.Token); err != nil {
		t.Errorf("token %q must be a valid UUID: %v", body.Token, err)
	}
}
