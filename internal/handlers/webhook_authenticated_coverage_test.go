package handlers_test

// webhook_authenticated_coverage_test.go — covers the authenticated provision
// path (newWebhookAuthenticated) + the Receive verb/query arms of webhook.go,
// which the anonymous-path tests don't reach. DB + Redis only.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

func TestWebhook_Authenticated_Provision(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, "webhook-user", teamID, "wh@example.com")

	req := httptest.NewRequest(http.MethodPost, "/webhook/new", strings.NewReader(`{"name":"orders"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.80.0.1")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var body struct {
		OK         bool   `json:"ok"`
		Token      string `json:"token"`
		ReceiveURL string `json:"receive_url"`
		Tier       string `json:"tier"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	resp.Body.Close()
	assert.True(t, body.OK)
	assert.Equal(t, "pro", body.Tier)
	require.NotEmpty(t, body.Token)
	assert.Contains(t, body.ReceiveURL, "/webhook/receive/")

	// Persisted as a team-owned webhook resource at the team tier.
	var rtype, tier string
	require.NoError(t, db.QueryRow(
		`SELECT resource_type, tier FROM resources WHERE token=$1::uuid`, body.Token,
	).Scan(&rtype, &tier))
	assert.Equal(t, "webhook", rtype)
	assert.Equal(t, "pro", tier)

	// Receive against the new token via several verbs + a query string.
	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPut} {
		rcv := httptest.NewRequest(m, "/webhook/receive/"+body.Token+"?shop=acme&evt=order.created", strings.NewReader(`{"hi":1}`))
		rcv.Header.Set("Content-Type", "application/json")
		rcv.Header.Set("Authorization", "Bearer secret-should-be-redacted")
		rresp, rerr := app.Test(rcv, 5000)
		require.NoError(t, rerr)
		assert.Less(t, rresp.StatusCode, 500, "verb=%s", m)
		rresp.Body.Close()
	}

	// List the stored requests — the public token-as-credential path.
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/webhooks/"+body.Token+"/requests", nil)
	lresp, lerr := app.Test(listReq, 5000)
	require.NoError(t, lerr)
	assert.Equal(t, http.StatusOK, lresp.StatusCode)
	lresp.Body.Close()
}
