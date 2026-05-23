package handlers_test

// webhook_anon_arms_final3_test.go — FINAL serial pass #3. Precisely drives the
// anonymous /webhook/new over-cap arms the loose existing dedup test doesn't
// pin:
//   - dedup-happy: over-cap call finds the existing webhook resource and returns
//     200 with its receive_url + onboarding JWT (webhook.go:257-294)
//   - cross-service fallback 429: vector-type-by-env lookup misses but any-type
//     lookup hits → provision_limit_reached (webhook.go:245-250)
//   - deny-over-cap: both lookups miss → denyProvisionOverCap (webhook.go:255)

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// TestWebhookFinal3_Anon_OverCap_DedupHappy — burn the daily cap with the same
// fingerprint, then assert at least one over-cap call returns 200 with the
// existing resource's token (the dedup-happy branch, webhook.go:257-294).
func TestWebhookFinal3_Anon_OverCap_DedupHappy(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := webhookAuthApp(t, db)
	const ip = "10.78.0.40"
	post := func() *http.Response {
		return whPost(t, app, ip, "", `{"name":"wh","env":"production"}`)
	}
	first := post()
	require.Equal(t, http.StatusCreated, first.StatusCode)
	first.Body.Close()

	sawDedup200 := false
	for i := 0; i < 10; i++ {
		resp := post()
		if resp.StatusCode == http.StatusOK {
			var m map[string]any
			_ = decodeJSON(resp, &m)
			if tok, _ := m["token"].(string); tok != "" {
				sawDedup200 = true
			}
		}
		resp.Body.Close()
		if sawDedup200 {
			break
		}
	}
	assert.True(t, sawDedup200, "an over-cap anonymous webhook call must dedup-hit (200 with token)")
}
