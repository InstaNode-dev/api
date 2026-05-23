package handlers_test

// vector_dedup_coverage_test.go — drives the anonymous dedup path of /vector/new
// (vectorAnonymousLimits + decryptConnectionURL on the limit-exceeded branch),
// which only fires after the per-fingerprint daily provision cap is hit. Needs
// the pgvector CI image so the underlying provisions succeed; skips if the
// customers backend is unavailable.

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

func TestVector_AnonymousDedup_AfterCap(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,vector,redis")
	defer cleanApp()

	const ip = "10.95.0.1"
	post := func() *http.Response {
		req := httptest.NewRequest(http.MethodPost, "/vector/new", strings.NewReader(`{"name":"v"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", ip)
		resp, err := app.Test(req, 15000)
		require.NoError(t, err)
		return resp
	}

	// First provision establishes a real vector resource for this fingerprint.
	first := post()
	if first.StatusCode == http.StatusServiceUnavailable {
		body, _ := io.ReadAll(first.Body)
		first.Body.Close()
		t.Skipf("vector dedup: pgvector/customers backend unavailable — skipping (%s)", body)
	}
	require.Equal(t, http.StatusCreated, first.StatusCode)
	first.Body.Close()

	// Hammer the same fingerprint past the daily cap (5/fp). The over-cap call
	// returns the existing resource (dedup) — exercising vectorAnonymousLimits
	// + decryptConnectionURL on the limit-exceeded branch — OR a 429 over-cap
	// deny. Either is the limit machinery; assert we never get a fresh 201
	// without bound.
	var sawDedupOrLimit bool
	for i := 0; i < 8; i++ {
		resp := post()
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusTooManyRequests {
			sawDedupOrLimit = true
			// On a 200 dedup hit, the body echoes the existing connection_url.
			if resp.StatusCode == http.StatusOK {
				var body struct {
					Token string `json:"token"`
				}
				_ = json.NewDecoder(resp.Body).Decode(&body)
				assert.NotEmpty(t, body.Token)
			}
			resp.Body.Close()
			break
		}
		resp.Body.Close()
	}
	assert.True(t, sawDedupOrLimit, "expected a dedup (200) or over-cap (429) after exceeding the per-fingerprint cap")
}
