package handlers_test

// vector_authenticated_coverage_test.go — covers the authenticated provision
// path (newVectorAuthenticated) of the /vector/new handler, which the existing
// vector_test.go (anonymous-only) leaves uncovered. Requires the pgvector
// postgres image (CI now uses pgvector/pgvector:pg16) so CREATE EXTENSION
// vector succeeds; skips cleanly if the customers backend is unreachable.

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

func TestVector_Authenticated_Provision(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,vector,redis")
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, "vec-user", teamID, "vec@example.com")

	req := httptest.NewRequest(http.MethodPost, "/vector/new", strings.NewReader(`{"name":"embeddings","dimensions":768}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.90.0.1")
	resp, err := app.Test(req, 15000)
	require.NoError(t, err)

	if resp.StatusCode == http.StatusServiceUnavailable {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Skipf("vector authenticated provision: postgres-customers/pgvector unavailable — skipping (%s)", body)
	}
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var body struct {
		OK    bool   `json:"ok"`
		Token string `json:"token"`
		Tier  string `json:"tier"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	resp.Body.Close()
	assert.True(t, body.OK)
	assert.Equal(t, "pro", body.Tier)

	var rtype, tier string
	require.NoError(t, db.QueryRow(
		`SELECT resource_type, tier FROM resources WHERE token=$1::uuid`, body.Token,
	).Scan(&rtype, &tier))
	assert.Equal(t, "vector", rtype)
	assert.Equal(t, "pro", tier)
}
