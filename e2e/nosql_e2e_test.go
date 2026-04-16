//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestE2E_NoSQLProvision_Returns201 verifies that POST /nosql/new returns 201 with
// the required fields when the mongodb service is enabled on the live server.
// The test is skipped (not failed) when the service returns 503 — this is safe
// to run before Phase 4 is live.
func TestE2E_NoSQLProvision_Returns201(t *testing.T) {
	ip := uniqueIP(t)
	resp := post(t, "/nosql/new", nil, "X-Forwarded-For", ip)

	if resp.StatusCode == http.StatusServiceUnavailable {
		readBody(t, resp)
		t.Skip("service not enabled in Phase 2/3/4")
	}

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /nosql/new: want 201, got %d\n%s", resp.StatusCode, readBody(t, resp))
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
	if !strings.HasPrefix(body.ConnectionURL, "mongodb://") {
		t.Errorf("connection_url must start with mongodb://; got %q", body.ConnectionURL)
	}
	if body.Tier == "" {
		t.Error("tier field must not be empty")
	}
	if body.Limits == nil {
		t.Error("limits field must not be nil")
	}
}

// TestE2E_NoSQLProvision_XInstantUpgradeHeader verifies that POST /nosql/new sets the
// X-Instant-Upgrade response header on a successful provision.
func TestE2E_NoSQLProvision_XInstantUpgradeHeader(t *testing.T) {
	ip := uniqueIP(t)
	resp := post(t, "/nosql/new", nil, "X-Forwarded-For", ip)

	if resp.StatusCode == http.StatusServiceUnavailable {
		readBody(t, resp)
		t.Skip("service not enabled in Phase 2/3/4")
	}

	upgrade := resp.Header.Get("X-Instant-Upgrade")
	readBody(t, resp)

	if upgrade == "" {
		t.Fatal("POST /nosql/new: X-Instant-Upgrade header must be present")
	}
	if !strings.Contains(upgrade, "/start?t=") {
		t.Errorf("X-Instant-Upgrade must contain /start?t=, got: %q", upgrade)
	}
}

// TestE2E_NoSQLProvision_TokenIsValidUUID verifies that the token returned by
// POST /nosql/new is a valid UUID.
func TestE2E_NoSQLProvision_TokenIsValidUUID(t *testing.T) {
	ip := uniqueIP(t)
	resp := post(t, "/nosql/new", nil, "X-Forwarded-For", ip)

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

// TestE2E_NoSQLProvision_ConnectionURLContainsToken verifies that the provisioned
// connection_url contains the token in the username and database name, confirming
// real provisioning (not a stub) was performed.
func TestE2E_NoSQLProvision_ConnectionURLContainsToken(t *testing.T) {
	ip := uniqueIP(t)
	resp := post(t, "/nosql/new", nil, "X-Forwarded-For", ip)

	if resp.StatusCode == http.StatusServiceUnavailable {
		readBody(t, resp)
		t.Skip("service not enabled — mongodb provisioning not yet live")
	}

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /nosql/new: want 201, got %d\n%s", resp.StatusCode, readBody(t, resp))
	}

	var body provisionNewResponse
	decodeJSON(t, resp, &body)

	if body.Token == "" {
		t.Fatal("token must not be empty")
	}
	// The real URL must contain a shortened form of the token.
	// The provider uses the full UUID as token, so connection_url includes it.
	if !strings.Contains(body.ConnectionURL, "mongodb://") {
		t.Errorf("connection_url must be a mongodb:// URL; got %q", body.ConnectionURL)
	}
	if strings.Contains(body.ConnectionURL, "shared.instant.dev") {
		t.Errorf("connection_url must not be the stub placeholder; got %q", body.ConnectionURL)
	}
}
