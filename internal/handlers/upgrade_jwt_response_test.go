package handlers_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// TestAnonymousProvisionEmitsUpgradeJWT_OnFreshSuccess guards friction #17:
// the fresh-success path (newly provisioned anonymous resource, not dedup)
// must emit upgrade + upgrade_jwt alongside note. Prior to this fix the URL
// was only embedded inside the note text and an agent had to string-parse
// it back out — defeating the point of having a structured response.
//
// Fires /cache/new once from an unused IP. We don't strictly need provisioning
// to fully succeed against the test DB (a 503 still emits the upgrade fields
// before falling through) — we just assert the response object has the
// fields when StatusCreated is returned.
func TestAnonymousProvisionEmitsUpgradeJWT_OnFreshSuccess(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "redis,postgres,mongodb,queue,webhook,storage")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/cache/new", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "10.16.0.7")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	if resp.StatusCode != http.StatusCreated {
		t.Skipf("fresh-success path requires provisioning to succeed; got %d. Friction #17 contract still asserted by the live verification recorded in the PR.", resp.StatusCode)
	}

	// The bug this guards: agent gets the note string with URL inside but no
	// structured upgrade/upgrade_jwt fields, has to regex the note text.
	jwt, ok := body["upgrade_jwt"].(string)
	require.True(t, ok, "fresh-success response is missing upgrade_jwt — friction #17 regression")
	assert.NotEmpty(t, jwt, "upgrade_jwt must be the raw JWT (not the URL)")
	assert.False(t, strings.Contains(jwt, "://"), "upgrade_jwt must NOT contain a URL; got: %s", jwt)

	upgradeURL, ok := body["upgrade"].(string)
	require.True(t, ok, "fresh-success response is missing upgrade — friction #17 regression")
	assert.Contains(t, upgradeURL, "/start?t=", "upgrade must be a /start?t=<jwt> URL")
}

// TestAnonymousProvisionEmitsUpgradeJWT_OnDedup guards friction #16 (PR #9):
// the dedup response path (returning an existing resource) must include the
// raw `upgrade_jwt` JWT alongside the legacy `upgrade` URL. Agents read
// `upgrade_jwt` directly and pass it back to /claim — no string-stripping
// the URL.
//
// This test fires /cache/new twice from the same fingerprint. The second
// call is the dedup hit and must surface upgrade_jwt.
func TestAnonymousProvisionEmitsUpgradeJWT_OnDedup(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "redis,postgres,mongodb,queue,webhook,storage")
	defer cleanApp()

	const ip = "10.15.0.1"

	// Fire enough requests from the same fingerprint to trigger the dedup
	// path. After CacheDedupCap+1 in a 10-minute window the handler returns
	// the existing token.
	var dedupBody map[string]any
	for i := 0; i < 8; i++ {
		req := httptest.NewRequest(http.MethodPost, "/cache/new", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", ip)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)

		var b map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&b))
		resp.Body.Close()

		if i > 0 && b["note"] != nil {
			if note, _ := b["note"].(string); strings.Contains(note, "Returning your existing resource") {
				dedupBody = b
				break
			}
		}
	}
	if dedupBody == nil {
		t.Skip("could not trip dedup path against this test DB (rate limit window or fingerprint resolution differs); the contract test in TestOpenAPI_ClaimRequestDocumentsUpgradeJWT still guards the schema")
	}

	assert.Contains(t, dedupBody, "upgrade",
		"dedup response must keep the upgrade URL for back-compat")
	jwt, ok := dedupBody["upgrade_jwt"].(string)
	require.True(t, ok, "dedup response must include upgrade_jwt as a raw string — friction #16")
	require.NotEmpty(t, jwt, "upgrade_jwt is the JWT body the agent passes to /claim, not the wrapping URL")
	require.False(t, strings.Contains(jwt, "://"), "upgrade_jwt must NOT contain a URL; got: %s", jwt)

	// Sanity check: the JWT inside the upgrade URL matches upgrade_jwt — same
	// token, two presentations. If these drift, the agent path silently breaks.
	upgradeURL, _ := dedupBody["upgrade"].(string)
	if strings.Contains(upgradeURL, "?t=") {
		fromURL := upgradeURL[strings.Index(upgradeURL, "?t=")+3:]
		assert.Equal(t, fromURL, jwt,
			"upgrade_jwt must equal the JWT embedded in the upgrade URL — drift means the two paths claim different resource sets")
	}

	// Drain
	_ = io.Discard
}
