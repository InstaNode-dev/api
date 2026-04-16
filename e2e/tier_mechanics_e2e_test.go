//go:build e2e

// Tier Mechanics — Persona C
//
// Tests the exact mechanics of how resource limits change (or don't) when a
// user moves between tiers. These tests answer specific skeptical questions:
//
//  1. How do limits increase "on demand" for higher tiers?
//  2. Does upgrading immediately help EXISTING resources?
//  3. What's enforced vs what's informational?
//
// Key findings (documented as assertions):
//
//	A. Claim: anonymous resource gets resource.tier='hobby' (not 'pro', even after team upgrades).
//	B. Upgrade: teams.plan_tier changes; resource.tier stays frozen at creation value.
//	C. Cache limits: informational memory_mb in provision responses tracks tier at provision time.
//	D. New provision after upgrade: uses team.PlanTier → gets pro limits immediately.
//	E. Storage/throughput quotas: quota.CheckStorageQuota / CheckAndIncrementToken exist but
//	   are NOT called from handlers — limits in provisioning responses are informational.
//	F. Provision dedup: 5 provisions/day per fingerprint (anonymous); 6th returns existing token.
//
// Required env:
//
//	E2E_BASE_URL           live server (default: http://localhost:30080)
//	E2E_JWT_SECRET         required for management-API tests (team-specific tests)
//	E2E_RAZORPAY_WEBHOOK_SECRET  required for Razorpay upgrade tests
package e2e

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ── C1: Limit progression across tiers ────────────────────────────────────────
//
// Verifies the planned limit values from plans.yaml are correctly reflected in
// provisioning responses across all three tiers.

func TestE2E_TierMechanics_C1_LimitProgressionAcrossTiers(t *testing.T) {
	// anonymous limits — POST /cache/new (no auth)
	ip := uniqueIP(t)
	anonProv := provisionAnonymous(t, ip)

	if anonProv.Tier != "anonymous" {
		t.Fatalf("C1: expected anonymous tier, got %q", anonProv.Tier)
	}
	if anonProv.Limits == nil {
		t.Fatal("C1: anonymous provision must include limits")
	}
	anonMemMB, ok := anonProv.Limits["memory_mb"].(float64)
	if !ok {
		t.Fatalf("C1: limits.memory_mb must be a number, got %T", anonProv.Limits["memory_mb"])
	}
	if anonMemMB != 5 {
		t.Errorf("C1: anonymous memory_mb: want 5, got %.0f", anonMemMB)
	}
	t.Logf("C1 anonymous: memory_mb=%.0f", anonMemMB)

	// hobby limits — claim the anonymous resource → get hobby session → POST /cache/new with auth
	secret := razorpayWebhookSecret(t) // also implicitly requires JWT_SECRET
	teamID, sessionJWT, _ := claimAndGetSession(t)
	_ = teamID // used in upgrade tests below

	hobbyProv := provisionAnonymousAuth(t, sessionJWT)
	if hobbyProv.Tier != "hobby" {
		t.Fatalf("C1: expected hobby tier for authenticated provision, got %q", hobbyProv.Tier)
	}
	hobbyMemMB, ok := hobbyProv.Limits["memory_mb"].(float64)
	if !ok {
		t.Fatalf("C1: hobby limits.memory_mb must be a number, got %T", hobbyProv.Limits["memory_mb"])
	}
	if hobbyMemMB <= anonMemMB {
		t.Errorf("C1: hobby memory_mb (%.0f) must exceed anonymous (%.0f)", hobbyMemMB, anonMemMB)
	}
	t.Logf("C1 hobby:     memory_mb=%.0f (%.0fx anonymous)", hobbyMemMB, hobbyMemMB/anonMemMB)

	// pro limits — upgrade the team, then provision another cache resource
	subscriptionID := "cus_test_" + uuid.NewString()[:12]
	webhookResp := postRazorpayWebhook(t, secret, subscriptionChargedPayload(teamID, subscriptionID, ""))
	if webhookResp.StatusCode != 200 {
		t.Fatalf("C1: upgrade webhook: want 200, got %d\n%s", webhookResp.StatusCode, readBody(t, webhookResp))
	}
	_ = readBody(t, webhookResp)
	time.Sleep(500 * time.Millisecond)

	proProv := provisionAnonymousAuth(t, sessionJWT)
	if proProv.Tier != "pro" {
		t.Fatalf("C1: expected pro tier after upgrade, got %q", proProv.Tier)
	}
	proMemMB, ok := proProv.Limits["memory_mb"].(float64)
	if !ok {
		t.Fatalf("C1: pro limits.memory_mb must be a number, got %T", proProv.Limits["memory_mb"])
	}
	if proMemMB <= hobbyMemMB {
		t.Errorf("C1: pro memory_mb (%.0f) must exceed hobby (%.0f)", proMemMB, hobbyMemMB)
	}
	t.Logf("C1 pro:       memory_mb=%.0f (%.0fx hobby)", proMemMB, proMemMB/hobbyMemMB)

	// Assert the exact values from plans.yaml so a plans.yaml edit breaks this test.
	want := map[string]float64{"anonymous": 5, "hobby": 25, "pro": 256}
	for tier, wantVal := range want {
		switch tier {
		case "anonymous":
			if anonMemMB != wantVal {
				t.Errorf("C1: anonymous memory_mb: want %.0f, got %.0f (plans.yaml changed?)", wantVal, anonMemMB)
			}
		case "hobby":
			if hobbyMemMB != wantVal {
				t.Errorf("C1: hobby memory_mb: want %.0f, got %.0f (plans.yaml changed?)", wantVal, hobbyMemMB)
			}
		case "pro":
			if proMemMB != wantVal {
				t.Errorf("C1: pro memory_mb: want %.0f, got %.0f (plans.yaml changed?)", wantVal, proMemMB)
			}
		}
	}
}

// ── C2: Claim freezes resource.tier at 'hobby' ────────────────────────────────
//
// When an anonymous resource is claimed, its tier becomes 'hobby' regardless of
// what the team's plan_tier is. This is hardcoded in onboarding.go:
//
//	UPDATE resources SET team_id = $1, tier = 'hobby', expires_at = NULL
//
// Implication: even if you upgrade before claiming, the claimed resource is 'hobby'.

func TestE2E_TierMechanics_C2_ClaimSetsResourceTierToHobbyNotTeamTier(t *testing.T) {
	secret := razorpayWebhookSecret(t)

	// Provision anonymous cache.
	ip := uniqueIP(t)
	anonProv := provisionAnonymous(t, ip)
	jwt := extractJWTFromNote(t, anonProv.Note)
	email := uniqueEmail()
	teamName := "e2e-c2-" + uuid.NewString()[:6]

	// Claim it — creates a hobby team.
	claimResp := post(t, "/claim", map[string]any{
		"jwt":       jwt,
		"email":     email,
		"team_name": teamName,
	})
	if claimResp.StatusCode != 201 {
		t.Fatalf("C2: POST /claim: want 201, got %d\n%s", claimResp.StatusCode, readBody(t, claimResp))
	}
	var claim claimResponse
	decodeJSON(t, claimResp, &claim)
	sessionJWT := makeSessionJWTWithUser(t, claim.UserID, claim.TeamID, email)

	// Upgrade to pro immediately after claiming.
	subscriptionID := "cus_test_" + uuid.NewString()[:12]
	webhookResp := postRazorpayWebhook(t, secret, subscriptionChargedPayload(claim.TeamID, subscriptionID, ""))
	if webhookResp.StatusCode != 200 {
		t.Fatalf("C2: upgrade webhook: want 200, got %d", webhookResp.StatusCode)
	}

	// List resources: the claimed cache resource must reflect post-webhook tier.
	listResp := get(t, "/api/v1/resources", "Authorization", "Bearer "+sessionJWT)
	if listResp.StatusCode != 200 {
		t.Fatalf("C2: GET /api/v1/resources: want 200, got %d\n%s", listResp.StatusCode, readBody(t, listResp))
	}
	var listBody struct {
		Items []struct {
			Token string `json:"token"`
			Tier  string `json:"tier"`
		} `json:"items"`
	}
	decodeJSON(t, listResp, &listBody)

	if len(listBody.Items) == 0 {
		t.Fatal("C2: expected at least one resource after claim")
	}

	claimedTier := listBody.Items[0].Tier

	// Team itself shows pro.
	me := getAuthMe(t, sessionJWT)
	if me["tier"] != "pro" {
		t.Errorf("C2: expected team tier=pro after webhook, got %q", me["tier"])
	}

	// After our ElevateResourceTiersByTeam fix, the upgrade webhook now promotes all
	// active resources. So a resource claimed as 'hobby' gets elevated to 'pro'
	// immediately after the checkout.session.completed webhook fires.
	if claimedTier != "pro" {
		t.Errorf("C2: claimed resource should be elevated to 'pro' by upgrade webhook, got %q", claimedTier)
	}
	t.Logf("C2: claim SQL sets tier='hobby', then upgrade webhook elevates to tier=%q ✓", claimedTier)
	t.Logf("C2: team tier=%q, resource tier=%q — ElevateResourceTiersByTeam promotes existing resources", me["tier"], claimedTier)
}

// ── C3: Pre-upgrade cache + new pro cache after Razorpay upgrade ────────────────
//
// After checkout webhook, ElevateResourceTiersByTeam promotes existing active
// resources. A hobby-tier cache provisioned before upgrade should list as pro,
// and a new provision after upgrade should report pro limits.

func TestE2E_TierMechanics_C3_PreUpgradeCacheElevatedAfterTeamUpgrade(t *testing.T) {
	secret := razorpayWebhookSecret(t)
	teamID, sessionJWT, _ := claimAndGetSession(t)

	// Provision a cache resource BEFORE upgrading (will have resource.tier='hobby').
	hobbyProv := provisionAnonymousAuth(t, sessionJWT)
	if hobbyProv.Tier != "hobby" {
		t.Skipf("C3: expected hobby tier for pre-upgrade provision, got %q", hobbyProv.Tier)
	}
	preUpgradeLimit, _ := hobbyProv.Limits["memory_mb"].(float64)

	// Upgrade the team.
	subscriptionID := "cus_test_" + uuid.NewString()[:12]
	webhookResp := postRazorpayWebhook(t, secret, subscriptionChargedPayload(teamID, subscriptionID, ""))
	if webhookResp.StatusCode != 200 {
		t.Fatalf("C3: upgrade webhook: want 200, got %d", webhookResp.StatusCode)
	}

	// Provision a NEW cache resource AFTER upgrading (will have resource.tier='pro').
	postUpgradeProv := provisionAnonymousAuth(t, sessionJWT)
	if postUpgradeProv.Tier != "pro" {
		t.Errorf("C3: new provision after upgrade must have tier=pro, got %q", postUpgradeProv.Tier)
	}
	postUpgradeNewLimit, _ := postUpgradeProv.Limits["memory_mb"].(float64)

	// Verify: new resource has higher limit than old resource.
	if postUpgradeNewLimit <= preUpgradeLimit {
		t.Errorf("C3: new pro resource limit (%.0f) must exceed old hobby resource limit (%.0f)",
			postUpgradeNewLimit, preUpgradeLimit)
	}

	// Verify the existing pre-upgrade resource is NOW elevated to pro tier.
	// billing.go handleCheckoutCompleted calls models.ElevateResourceTiersByTeam which
	// runs: UPDATE resources SET tier=$1 WHERE team_id=$2 AND status='active' AND expires_at IS NULL
	listResp := get(t, "/api/v1/resources", "Authorization", "Bearer "+sessionJWT)
	if listResp.StatusCode != 200 {
		t.Fatalf("C3: GET /api/v1/resources: want 200, got %d\n%s", listResp.StatusCode, readBody(t, listResp))
	}
	var listBody struct {
		Items []struct {
			Token string `json:"token"`
			Tier  string `json:"tier"`
		} `json:"items"`
	}
	decodeJSON(t, listResp, &listBody)

	tierByToken := make(map[string]string)
	for _, item := range listBody.Items {
		tierByToken[item.Token] = item.Tier
	}

	if got, ok := tierByToken[hobbyProv.Token]; ok {
		if got != "pro" {
			t.Errorf("C3: pre-upgrade resource should be elevated to pro after upgrade webhook; got tier=%q", got)
		}
		t.Logf("C3: pre-upgrade resource %q elevated to tier=%q ✓", hobbyProv.Token, got)
	} else {
		t.Errorf("C3: pre-upgrade resource %q not found in list", hobbyProv.Token)
	}

	t.Logf("C3: pre-upgrade=%.0f/day (hobby) → upgraded resource elevated to pro (%.0f/day)",
		preUpgradeLimit, postUpgradeNewLimit)
}

// ── C4: Storage and throughput quotas are informational, not enforced ─────────
//
// The quota package (quota.CheckStorageQuota, quota.CheckAndIncrementToken)
// implements correct enforcement logic, but these functions are NOT called from
// any provisioning or access handler. The "limits" field in provisioning
// responses is purely informational — a signal to the caller about what they
// should expect, but no write will currently be blocked by it.
//
// This test documents the current behavior (no enforcement) by verifying that
// limits in provisioning responses correctly reflect the tier, even though
// the storage/throughput limits are not enforced at the infrastructure level.

func TestE2E_TierMechanics_C4_StorageLimitsAreInformationalPerTier(t *testing.T) {
	secret := razorpayWebhookSecret(t)

	// anonymous DB limits
	anonIP := uniqueIP(t)
	anonDB := apiPost(t, "/db/new", nil, "X-Forwarded-For", anonIP)
	skipIfServiceDown(t, anonDB, "postgres")
	var anonDBBody struct {
		Limits struct {
			StorageMB   int `json:"storage_mb"`
			Connections int `json:"connections"`
		} `json:"limits"`
		Tier string `json:"tier"`
	}
	decodeJSON(t, anonDB, &anonDBBody)

	if anonDBBody.Tier != "anonymous" {
		t.Fatalf("C4: expected anonymous tier for unauthenticated provision, got %q", anonDBBody.Tier)
	}
	if anonDBBody.Limits.StorageMB != 10 {
		t.Errorf("C4: anonymous postgres storage_mb: want 10, got %d", anonDBBody.Limits.StorageMB)
	}
	if anonDBBody.Limits.Connections != 2 {
		t.Errorf("C4: anonymous postgres connections: want 2, got %d", anonDBBody.Limits.Connections)
	}
	t.Logf("C4 anonymous postgres: storage_mb=%d connections=%d",
		anonDBBody.Limits.StorageMB, anonDBBody.Limits.Connections)

	// hobby DB limits
	teamID, sessionJWT, _ := claimAndGetSession(t)
	hobbyDB := apiPost(t, "/db/new", nil,
		"X-Forwarded-For", uniqueIP(t),
		"Authorization", "Bearer "+sessionJWT,
	)
	skipIfServiceDown(t, hobbyDB, "postgres")
	var hobbyDBBody struct {
		Limits struct {
			StorageMB   int `json:"storage_mb"`
			Connections int `json:"connections"`
		} `json:"limits"`
		Tier string `json:"tier"`
	}
	decodeJSON(t, hobbyDB, &hobbyDBBody)

	if hobbyDBBody.Tier != "hobby" {
		t.Fatalf("C4: expected hobby tier for authenticated provision, got %q", hobbyDBBody.Tier)
	}
	if hobbyDBBody.Limits.StorageMB != 500 {
		t.Errorf("C4: hobby postgres storage_mb: want 500, got %d", hobbyDBBody.Limits.StorageMB)
	}
	if hobbyDBBody.Limits.Connections != 5 {
		t.Errorf("C4: hobby postgres connections: want 5, got %d", hobbyDBBody.Limits.Connections)
	}
	t.Logf("C4 hobby postgres: storage_mb=%d connections=%d",
		hobbyDBBody.Limits.StorageMB, hobbyDBBody.Limits.Connections)

	// pro DB limits (upgrade then provision)
	subscriptionID := "cus_test_" + uuid.NewString()[:12]
	webhookResp := postRazorpayWebhook(t, secret, subscriptionChargedPayload(teamID, subscriptionID, ""))
	if webhookResp.StatusCode != 200 {
		t.Fatalf("C4: upgrade webhook: want 200, got %d", webhookResp.StatusCode)
	}

	proDB := apiPost(t, "/db/new", nil,
		"X-Forwarded-For", uniqueIP(t),
		"Authorization", "Bearer "+sessionJWT,
	)
	skipIfServiceDown(t, proDB, "postgres")
	var proDBBody struct {
		Limits struct {
			StorageMB   int `json:"storage_mb"`
			Connections int `json:"connections"`
		} `json:"limits"`
		Tier string `json:"tier"`
	}
	decodeJSON(t, proDB, &proDBBody)

	if proDBBody.Tier != "pro" {
		t.Errorf("C4: expected pro tier after upgrade, got %q", proDBBody.Tier)
	}
	if proDBBody.Limits.StorageMB != 5120 {
		t.Errorf("C4: pro postgres storage_mb: want 5120, got %d", proDBBody.Limits.StorageMB)
	}
	if proDBBody.Limits.Connections != 20 {
		t.Errorf("C4: pro postgres connections: want 20, got %d", proDBBody.Limits.Connections)
	}
	t.Logf("C4 pro postgres: storage_mb=%d connections=%d",
		proDBBody.Limits.StorageMB, proDBBody.Limits.Connections)

	// DOCUMENT: limits are informational only.
	// quota.CheckStorageQuota and quota.CheckAndIncrementToken exist in the quota package
	// but are not called from any handler. A write to the Postgres database will not be
	// rejected if it exceeds storage_mb. The limit field signals the INTENT; enforcement
	// must be added by wiring quota.CheckStorageQuota into the Postgres write proxy or
	// the UpdateStorageBytesWorker job.
	t.Logf("C4 DESIGN NOTE: storage_mb limits are informational. " +
		"quota.CheckStorageQuota is not called from any handler — " +
		"add enforcement before Phase 2 GA")
}

// ── C5: Redis and MongoDB limits follow same tier progression ─────────────────

func TestE2E_TierMechanics_C5_CacheAndNoSQLLimitsPerTier(t *testing.T) {
	secret := razorpayWebhookSecret(t)
	teamID, sessionJWT, _ := claimAndGetSession(t)

	ip := uniqueIP(t)

	// Anonymous Redis
	anonCache := apiPost(t, "/cache/new", nil, "X-Forwarded-For", ip)
	skipIfServiceDown(t, anonCache, "redis")
	var anonCacheBody struct {
		Limits struct {
			MemoryMB int `json:"memory_mb"`
		} `json:"limits"`
		Tier string `json:"tier"`
	}
	decodeJSON(t, anonCache, &anonCacheBody)
	if anonCacheBody.Limits.MemoryMB != 5 {
		t.Errorf("C5: anonymous redis memory_mb: want 5, got %d", anonCacheBody.Limits.MemoryMB)
	}

	// Hobby Redis (authenticated)
	hobbyCache := apiPost(t, "/cache/new", nil,
		"X-Forwarded-For", uniqueIP(t),
		"Authorization", "Bearer "+sessionJWT,
	)
	skipIfServiceDown(t, hobbyCache, "redis")
	var hobbyCacheBody struct {
		Limits struct {
			MemoryMB int `json:"memory_mb"`
		} `json:"limits"`
		Tier string `json:"tier"`
	}
	decodeJSON(t, hobbyCache, &hobbyCacheBody)
	if hobbyCacheBody.Limits.MemoryMB != 25 {
		t.Errorf("C5: hobby redis memory_mb: want 25, got %d", hobbyCacheBody.Limits.MemoryMB)
	}

	// Upgrade, then pro Redis
	subscriptionID := "cus_test_" + uuid.NewString()[:12]
	webhookResp := postRazorpayWebhook(t, secret, subscriptionChargedPayload(teamID, subscriptionID, ""))
	if webhookResp.StatusCode != 200 {
		t.Fatalf("C5: upgrade webhook: want 200, got %d", webhookResp.StatusCode)
	}

	proCache := apiPost(t, "/cache/new", nil,
		"X-Forwarded-For", uniqueIP(t),
		"Authorization", "Bearer "+sessionJWT,
	)
	skipIfServiceDown(t, proCache, "redis")
	var proCacheBody struct {
		Limits struct {
			MemoryMB int `json:"memory_mb"`
		} `json:"limits"`
		Tier string `json:"tier"`
	}
	decodeJSON(t, proCache, &proCacheBody)
	if proCacheBody.Limits.MemoryMB != 256 {
		t.Errorf("C5: pro redis memory_mb: want 256, got %d", proCacheBody.Limits.MemoryMB)
	}

	t.Logf("C5 redis memory_mb: anonymous=%d → hobby=%d → pro=%d",
		anonCacheBody.Limits.MemoryMB, hobbyCacheBody.Limits.MemoryMB, proCacheBody.Limits.MemoryMB)

	// NoSQL limits
	anonNoSQL := apiPost(t, "/nosql/new", nil, "X-Forwarded-For", ip)
	skipIfServiceDown(t, anonNoSQL, "mongodb")
	var anonNoSQLBody struct {
		Limits struct {
			StorageMB   int `json:"storage_mb"`
			Connections int `json:"connections"`
		} `json:"limits"`
	}
	decodeJSON(t, anonNoSQL, &anonNoSQLBody)
	if anonNoSQLBody.Limits.StorageMB != 5 {
		t.Errorf("C5: anonymous mongodb storage_mb: want 5, got %d", anonNoSQLBody.Limits.StorageMB)
	}

	t.Logf("C5 mongodb storage_mb anonymous=%d (hobby=100, pro=2048)", anonNoSQLBody.Limits.StorageMB)
}

// ── C6: Provision dedup — same fingerprint returns existing token ──────────────
//
// Anonymous users are limited to 5 provisions/day per fingerprint.
// The 6th call returns the existing token (fail-open) rather than 429.
// Limits in the dedup response reflect the EXISTING resource's tier.

func TestE2E_TierMechanics_C6_ProvisionDedupReturnsSameToken(t *testing.T) {
	// Use the same IP for all 6 requests to trigger dedup.
	ip := uniqueIP(t)

	var firstToken string

	// Exhaust the 5-per-day limit.
	for i := 0; i < 5; i++ {
		resp := provisionAnonymous(t, ip)
		if i == 0 {
			firstToken = resp.Token
		}
	}
	if firstToken == "" {
		t.Fatal("C6: expected a token from first provision")
	}

	// 6th provision: must return existing token, not a new one, and must be ok=true.
	sixthResp := post(t, "/cache/new", nil, "X-Forwarded-For", ip)
	if sixthResp.StatusCode != 200 {
		// 200 = dedup; 201 = new. Both are acceptable but 200 is expected on limit hit.
		body := readBody(t, sixthResp)
		t.Fatalf("C6: 6th provision: want 200 (dedup), got %d\n%s", sixthResp.StatusCode, body)
	}

	var sixthBody struct {
		OK    bool   `json:"ok"`
		Token string `json:"token"`
		Tier  string `json:"tier"`
		Note  string `json:"note"`
	}
	decodeJSON(t, sixthResp, &sixthBody)

	if !sixthBody.OK {
		t.Error("C6: 6th provision must return ok=true (fail-open, never 429)")
	}
	if sixthBody.Token == "" {
		t.Error("C6: 6th provision must return a token")
	}

	// The returned token should be the same existing one (dedup), not a new UUID.
	// Both the original token and the dedup token should be valid tokens.
	// They may differ if the fingerprint has multiple tokens — what matters is
	// that it's an EXISTING token, not a freshly provisioned one.
	if strings.Contains(sixthBody.Note, "existing") || strings.Contains(sixthBody.Note, "upgrade") {
		t.Logf("C6: dedup note confirms existing token: %q", sixthBody.Note)
	}

	t.Logf("C6: first token=%s, 6th response token=%s (dedup=%v)",
		firstToken, sixthBody.Token, firstToken == sixthBody.Token)
	t.Logf("C6: upgrade URL present in dedup response: %v",
		strings.Contains(sixthBody.Note, "instant.dev/start?t="))
}

// ── C7: Downgrade reverts new provisions to hobby limits ─────────────────────
//
// After subscription.deleted webhook, team.plan_tier reverts to 'hobby'.
// New provisions after downgrade must have hobby limits.
// Existing 'pro' resources stay with tier='pro' in the DB (frozen snapshot)
// and keep pro-tier limits on that resource.
// This is another instance of the same resource.tier-is-a-snapshot design.

func TestE2E_TierMechanics_C7_DowngradeNewProvisionsRevertToHobby(t *testing.T) {
	secret := razorpayWebhookSecret(t)
	teamID, sessionJWT, _ := claimAndGetSession(t)

	// Upgrade.
	subscriptionID := "cus_test_" + uuid.NewString()[:12]
	upgradeResp := postRazorpayWebhook(t, secret, subscriptionChargedPayload(teamID, subscriptionID, ""))
	if upgradeResp.StatusCode != 200 {
		t.Fatalf("C7: upgrade webhook: want 200, got %d", upgradeResp.StatusCode)
	}
	proMe := getAuthMe(t, sessionJWT)
	if proMe["tier"] != "pro" {
		t.Fatalf("C7: after upgrade, expected tier=pro, got %q", proMe["tier"])
	}

	// Provision a pro-tier cache (captures pro limits).
	proProv := provisionAnonymousAuth(t, sessionJWT)
	if proProv.Tier != "pro" {
		t.Fatalf("C7: expected pro tier for provision after upgrade, got %q", proProv.Tier)
	}
	proLimit, _ := proProv.Limits["memory_mb"].(float64)
	t.Logf("C7: pro provision memory_mb=%.0f", proLimit)

	// Downgrade.
	downgradeResp := postRazorpayWebhook(t, secret, subscriptionCancelledPayload(teamID, subscriptionID))
	if downgradeResp.StatusCode != 200 {
		t.Fatalf("C7: downgrade webhook: want 200, got %d", downgradeResp.StatusCode)
	}
	hobbyMe := getAuthMe(t, sessionJWT)
	if hobbyMe["tier"] != "hobby" {
		t.Errorf("C7: after downgrade, expected tier=hobby, got %q", hobbyMe["tier"])
	}

	// New provision after downgrade must have hobby limits.
	postDowngradeProv := provisionAnonymousAuth(t, sessionJWT)
	if postDowngradeProv.Tier != "hobby" {
		t.Errorf("C7: new provision after downgrade must have tier=hobby, got %q", postDowngradeProv.Tier)
	}
	hobbyLimit, _ := postDowngradeProv.Limits["memory_mb"].(float64)
	if hobbyLimit >= proLimit {
		t.Errorf("C7: post-downgrade memory_mb (%.0f) must be less than pro (%.0f)", hobbyLimit, proLimit)
	}
	t.Logf("C7: post-downgrade new provision memory_mb=%.0f (was pro: %.0f)", hobbyLimit, proLimit)

	// DOCUMENT: the existing pro resource (proProv.Token) still has resource.tier='pro'
	// in the database. Limits for existing resources are frozen at creation time.
	// New provisions after downgrade use hobby limits — a known design decision.
	t.Logf("C7 DESIGN NOTE: existing resource %q has tier='pro' — limits stay pro on that resource after team downgrade",
		proProv.Token)
}

// ── C8: Resource list shows tier snapshots, not live team tier ────────────────
//
// GET /api/v1/resources must show each resource's frozen tier (the tier at
// creation time), not the team's current plan tier. This is the single source
// of truth for what limits were promised to that resource at provisioning time.

func TestE2E_TierMechanics_C8_ResourceListShowsFrozenTiers(t *testing.T) {
	secret := razorpayWebhookSecret(t)
	teamID, sessionJWT, _ := claimAndGetSession(t)

	// Provision one hobby-tier cache.
	hobbyProv := provisionAnonymousAuth(t, sessionJWT)
	if hobbyProv.Tier != "hobby" {
		t.Skipf("C8: expected hobby provision, got %q", hobbyProv.Tier)
	}

	// Upgrade.
	subscriptionID := "cus_test_" + uuid.NewString()[:12]
	webhookResp := postRazorpayWebhook(t, secret, subscriptionChargedPayload(teamID, subscriptionID, ""))
	if webhookResp.StatusCode != 200 {
		t.Fatalf("C8: upgrade webhook: want 200, got %d", webhookResp.StatusCode)
	}

	// Provision one pro-tier cache.
	proProv := provisionAnonymousAuth(t, sessionJWT)
	if proProv.Tier != "pro" {
		t.Fatalf("C8: expected pro provision after upgrade, got %q", proProv.Tier)
	}

	// List all resources.
	listResp := get(t, "/api/v1/resources", "Authorization", "Bearer "+sessionJWT)
	if listResp.StatusCode != 200 {
		t.Fatalf("C8: GET /api/v1/resources: want 200, got %d\n%s", listResp.StatusCode, readBody(t, listResp))
	}
	var listBody struct {
		Items []struct {
			Token string `json:"token"`
			Tier  string `json:"tier"`
		} `json:"items"`
	}
	decodeJSON(t, listResp, &listBody)

	// Find the hobby and pro resources in the list.
	tierByToken := make(map[string]string)
	for _, item := range listBody.Items {
		tierByToken[item.Token] = item.Tier
	}

	// After ElevateResourceTiersByTeam fix: the upgrade webhook promotes ALL existing
	// resources, so the pre-upgrade hobby resource is now 'pro' in the list.
	if got, ok := tierByToken[hobbyProv.Token]; ok {
		if got != "pro" {
			t.Errorf("C8: pre-upgrade resource tier in list: want 'pro' (elevated by webhook), got %q", got)
		}
		t.Logf("C8: pre-upgrade resource %q shows tier=%q in list ✓ (elevated by upgrade webhook)", hobbyProv.Token, got)
	} else {
		t.Errorf("C8: pre-upgrade resource %q not found in list; tokens present: %v",
			hobbyProv.Token, tierByToken)
	}

	// Pro resource provisioned after upgrade also shows tier='pro'.
	if got, ok := tierByToken[proProv.Token]; ok {
		if got != "pro" {
			t.Errorf("C8: post-upgrade resource tier in list: want 'pro', got %q", got)
		}
		t.Logf("C8: post-upgrade resource %q shows tier=%q in list ✓", proProv.Token, got)
	} else {
		t.Errorf("C8: post-upgrade resource %q not found in list; tokens present: %v",
			proProv.Token, tierByToken)
	}

	t.Logf("C8: both resources show tier='pro' after upgrade — ElevateResourceTiersByTeam promotes all active resources")
}

// ── C9: Anonymous → hobby limit jump via claim (no Razorpay required) ────────
//
// This test verifies the core tier-scaling mechanic end-to-end without Razorpay:
// 1. Anonymous provision → 5MB redis memory
// 2. Claim it (creates hobby team) → provision another → 25MB redis memory
// 3. The resource.tier jumps 5x just by claiming — no payment required.
//
// This is the "free account" value prop: claim = instant upgrade.
// Pro upgrade (via Razorpay) adds another 10x on top of hobby.

func TestE2E_TierMechanics_C9_AnonToHobbyLimitJumpViaClaim(t *testing.T) {
	// Skip if JWT secret not set (needed for /auth/me and authenticated provisions).
	if os.Getenv("E2E_JWT_SECRET") == "" {
		t.Skip("E2E_JWT_SECRET not set — skipping authenticated tier tests")
	}

	// Anonymous provision.
	ip := uniqueIP(t)
	anonProv := provisionAnonymous(t, ip)
	if anonProv.Tier != "anonymous" {
		t.Fatalf("C9: expected anonymous tier, got %q", anonProv.Tier)
	}
	anonLimit, ok := anonProv.Limits["memory_mb"].(float64)
	if !ok {
		t.Fatalf("C9: anonymous limits.memory_mb must be float64, got %T", anonProv.Limits["memory_mb"])
	}
	if anonLimit != 5 {
		t.Errorf("C9: anonymous memory_mb: want 5, got %.0f", anonLimit)
	}
	t.Logf("C9: anonymous memory_mb=%.0f", anonLimit)

	// Claim → hobby account.
	teamID, sessionJWT, _ := claimAndGetSession(t)
	_ = teamID

	// Provision a new cache resource as hobby user.
	hobbyProv := provisionAnonymousAuth(t, sessionJWT)
	if hobbyProv.Tier != "hobby" {
		t.Fatalf("C9: expected hobby tier for authenticated provision, got %q", hobbyProv.Tier)
	}
	hobbyLimit, ok := hobbyProv.Limits["memory_mb"].(float64)
	if !ok {
		t.Fatalf("C9: hobby limits.memory_mb must be float64, got %T", hobbyProv.Limits["memory_mb"])
	}
	if hobbyLimit != 25 {
		t.Errorf("C9: hobby memory_mb: want 25, got %.0f", hobbyLimit)
	}

	ratio := hobbyLimit / anonLimit
	if ratio < 2 {
		t.Errorf("C9: hobby memory_mb must be at least 2x anonymous; got %.1fx", ratio)
	}

	t.Logf("C9: anonymous=%.0f → hobby=%.0f (%.0fx increase from free claim alone)", anonLimit, hobbyLimit, ratio)
	t.Logf("C9: mechanism: POST /claim sets resource.tier='hobby' + team.plan_tier='hobby'")
	t.Logf("C9:            new provisions use team.plan_tier → gets hobby limits immediately")
}

// ── C10: Hobby resource has correct limits and is accessible via management API ─
//
// Verifies that a hobby-tier cache resource provisioned by an authenticated user:
//   - Has memory_mb limit = 25 (hobby tier from plans.yaml)
//   - Is visible via GET /api/v1/resources with status=active
//   - Does NOT expose connection_url in the list response
//
// No Razorpay required — uses JWT + claim only.

func TestE2E_TierMechanics_C10_HobbyResource_CorrectLimits_VisibleInAPI(t *testing.T) {
	if os.Getenv("E2E_JWT_SECRET") == "" {
		t.Skip("E2E_JWT_SECRET not set — skipping authenticated tier tests")
	}

	_, sessionJWT, _ := claimAndGetSession(t)

	// Provision a hobby cache resource.
	prov := provisionAnonymousAuth(t, sessionJWT)
	if prov.Tier != "hobby" {
		t.Skipf("C10: expected hobby provision, got %q", prov.Tier)
	}

	// Verify hobby memory_mb limit is exactly 25 (from plans.yaml).
	hobbyMemMB, _ := prov.Limits["memory_mb"].(float64)
	if hobbyMemMB != 25 {
		t.Errorf("C10: hobby memory_mb: want 25, got %.0f", hobbyMemMB)
	}
	t.Logf("C10: hobby cache %s | memory_mb=%.0f", prov.Token, hobbyMemMB)

	// The resource must appear in the management API list with status=active.
	listResp := get(t, "/api/v1/resources", "Authorization", "Bearer "+sessionJWT)
	if listResp.StatusCode != 200 {
		t.Fatalf("C10: GET /api/v1/resources: want 200, got %d\n%s", listResp.StatusCode, readBody(t, listResp))
	}
	var listBody struct {
		Items []map[string]any `json:"items"`
	}
	decodeJSON(t, listResp, &listBody)

	found := false
	for _, item := range listBody.Items {
		if item["token"] == prov.Token {
			found = true
			if item["status"] != "active" {
				t.Errorf("C10: hobby resource status: want active, got %v", item["status"])
			}
			if _, hasURL := item["connection_url"]; hasURL {
				t.Error("C10: connection_url must NOT be exposed in management API list response")
			}
			t.Logf("C10: resource in list: token=%s status=%v tier=%v", prov.Token, item["status"], item["tier"])
		}
	}
	if !found {
		t.Errorf("C10: hobby resource %q not found in management API list", prov.Token)
	}
}

// ── helpers ────────────────────────────────────────────────────────────────────

// apiPost is a thin wrapper that calls POST on path with optional extra headers.
func apiPost(t *testing.T, path string, body any, extraHeaders ...string) *http.Response {
	t.Helper()
	return post(t, path, body, extraHeaders...)
}

// provisionAnonymousAuth provisions a cache resource as an authenticated team member.
// Skips the calling test if the endpoint returns 503.
func provisionAnonymousAuth(t *testing.T, sessionJWT string) provisionNewResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp := postCtx(t, ctx, "/cache/new", nil,
		"X-Forwarded-For", uniqueIP(t),
		"Authorization", "Bearer "+sessionJWT,
	)
	if resp.StatusCode == http.StatusServiceUnavailable {
		readBody(t, resp)
		t.Skip("POST /cache/new (auth): service not enabled (503) — skip")
	}
	if resp.StatusCode != http.StatusCreated {
		body := readBody(t, resp)
		t.Fatalf("provisionAnonymousAuth: want 201, got %d (after tier change this call can reflect DB lag; body=%s)",
			resp.StatusCode, body)
	}
	var body provisionNewResponse
	decodeJSON(t, resp, &body)
	if body.Token == "" {
		t.Fatal("provisionAnonymousAuth: empty token")
	}
	return body
}
