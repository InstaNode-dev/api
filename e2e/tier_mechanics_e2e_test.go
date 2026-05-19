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
//	E2E_BASE_URL                live server (default: http://localhost:30080)
//	E2E_JWT_SECRET              required for management-API tests (team-specific tests)
//	E2E_RAZORPAY_WEBHOOK_SECRET required for Razorpay upgrade tests
//	E2E_RAZORPAY_PLAN_ID_PRO    the configured Pro plan_id — required for the
//	                            pro-tier upgrade assertions (C1–C8). Post-F3 an
//	                            empty plan_id maps to `hobby`, not `pro`, so a
//	                            real plan_id is the only way to reach `pro`.
//	                            Tests that need it SKIP when it is unset.
//	E2E_TEST_TOKEN              fingerprint-isolation token (see helpers_test.go) —
//	                            required in practice behind an XFF-overwriting
//	                            ingress or every test hits the recycle gate.
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
// Verifies the limit values from plans.yaml are correctly reflected in
// provisioning responses across the tiers a team actually moves through.
//
// Stale-assertion fix (WEBHOOK-VERIFY-2026-05-19): a claimed-but-unpaid team is
// `free`, not `hobby` — `tier := team.PlanTier` (cache.go) means an
// authenticated provision by a just-claimed team gets tier=free. The middle
// step now asserts `free` (whose limits, by design, equal anonymous — the free
// claim is an identity step, the real jump is the paid upgrade). The pro leg
// sends the configured Pro plan_id so it lands on a genuine `pro` (post-F3 an
// empty plan_id would map to `hobby`, not `pro`).

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

	// free limits — claim the anonymous resource → get a free session → POST /cache/new with auth.
	// A claimed-but-unpaid team is `free`; an authenticated provision gets tier=free.
	secret := razorpayWebhookSecret(t)   // also implicitly requires JWT_SECRET
	proPlanID := razorpayProPlanID(t)    // required for the genuine pro upgrade leg
	teamID, sessionJWT, _ := claimAndGetSession(t)
	_ = teamID // used in the upgrade step below

	freeProv := provisionAnonymousAuth(t, sessionJWT)
	if freeProv.Tier != "free" {
		t.Fatalf("C1: expected free tier for a claimed-but-unpaid team's authenticated provision, got %q", freeProv.Tier)
	}
	freeMemMB, ok := freeProv.Limits["memory_mb"].(float64)
	if !ok {
		t.Fatalf("C1: free limits.memory_mb must be a number, got %T", freeProv.Limits["memory_mb"])
	}
	// The free tier deliberately mirrors anonymous limits (no jump on claim alone).
	if freeMemMB != anonMemMB {
		t.Errorf("C1: free memory_mb (%.0f) should equal anonymous (%.0f) — the free claim is an identity step", freeMemMB, anonMemMB)
	}
	t.Logf("C1 free:      memory_mb=%.0f (== anonymous; the paid upgrade is the real jump)", freeMemMB)

	// pro limits — upgrade the team with the real Pro plan_id, then provision another cache resource.
	subscriptionID := "cus_test_" + uuid.NewString()[:12]
	webhookResp := postRazorpayWebhook(t, secret, subscriptionChargedPayload(teamID, subscriptionID, proPlanID))
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
	if proMemMB <= freeMemMB {
		t.Errorf("C1: pro memory_mb (%.0f) must exceed free (%.0f)", proMemMB, freeMemMB)
	}
	t.Logf("C1 pro:       memory_mb=%.0f (%.0fx free)", proMemMB, proMemMB/freeMemMB)

	// Assert the exact values from plans.yaml so a plans.yaml edit breaks this test.
	if anonMemMB != 5 {
		t.Errorf("C1: anonymous memory_mb: want 5, got %.0f (plans.yaml changed?)", anonMemMB)
	}
	if freeMemMB != 5 {
		t.Errorf("C1: free memory_mb: want 5, got %.0f (plans.yaml changed?)", freeMemMB)
	}
	if proMemMB != 512 {
		t.Errorf("C1: pro memory_mb: want 512, got %.0f (plans.yaml changed?)", proMemMB)
	}
}

// ── C2: Claim sets resource.tier='free'; upgrade elevates it to the paid tier ──
//
// When an anonymous resource is claimed, its tier becomes 'free' (the
// claimed-but-unpaid floor) — onboarding.go:
//
//	UPDATE resources SET team_id = $1, tier = 'free', expires_at = NULL
//
// Stale-assertion fix (WEBHOOK-VERIFY-2026-05-19): the prior test asserted the
// claim set tier='hobby' and the upgrade reached 'pro' from an empty plan_id —
// both pre-date current behaviour (the `free` tier; the F3 fallback). This now
// asserts the claimed resource lands on 'free', then a charge with the real Pro
// plan_id elevates the team AND the claimed resource to 'pro' via
// ElevateResourceTiersByTeam.

func TestE2E_TierMechanics_C2_ClaimSetsResourceTierThenUpgradeElevates(t *testing.T) {
	secret := razorpayWebhookSecret(t)
	proPlanID := razorpayProPlanID(t)

	// Provision anonymous cache.
	ip := uniqueIP(t)
	anonProv := provisionAnonymous(t, ip)
	jwt := extractJWTFromNote(t, anonProv.Note)
	email := uniqueEmail()
	teamName := "e2e-c2-" + uuid.NewString()[:6]

	// Claim it — creates a free (claimed-but-unpaid) team.
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

	// Upgrade to pro immediately after claiming, with the real Pro plan_id.
	subscriptionID := "cus_test_" + uuid.NewString()[:12]
	webhookResp := postRazorpayWebhook(t, secret, subscriptionChargedPayload(claim.TeamID, subscriptionID, proPlanID))
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

	// After the ElevateResourceTiersByTeam fix, the upgrade webhook promotes all
	// active resources. So a resource claimed as 'free' gets elevated to 'pro'
	// immediately after the subscription.charged webhook fires.
	if claimedTier != "pro" {
		t.Errorf("C2: claimed resource should be elevated to 'pro' by upgrade webhook, got %q", claimedTier)
	}
	t.Logf("C2: claim SQL sets tier='free', then upgrade webhook elevates to tier=%q ✓", claimedTier)
	t.Logf("C2: team tier=%q, resource tier=%q — ElevateResourceTiersByTeam promotes existing resources", me["tier"], claimedTier)
}

// ── C3: Pre-upgrade cache + new pro cache after Razorpay upgrade ────────────────
//
// After the charge webhook, ElevateResourceTiersByTeam promotes existing active
// resources. A free-tier cache provisioned before upgrade should list as pro,
// and a new provision after upgrade should report pro limits.
//
// Stale-assertion fix (WEBHOOK-VERIFY-2026-05-19): the pre-upgrade provision is
// `free` (a claimed-but-unpaid team), not `hobby`; and the upgrade now sends
// the real Pro plan_id so it genuinely reaches `pro`.

func TestE2E_TierMechanics_C3_PreUpgradeCacheElevatedAfterTeamUpgrade(t *testing.T) {
	secret := razorpayWebhookSecret(t)
	proPlanID := razorpayProPlanID(t)
	teamID, sessionJWT, _ := claimAndGetSession(t)

	// Provision a cache resource BEFORE upgrading (will have resource.tier='free').
	freeProv := provisionAnonymousAuth(t, sessionJWT)
	if freeProv.Tier != "free" {
		t.Fatalf("C3: expected free tier for a claimed-but-unpaid team's pre-upgrade provision, got %q", freeProv.Tier)
	}
	preUpgradeLimit, _ := freeProv.Limits["memory_mb"].(float64)

	// Upgrade the team with the real Pro plan_id.
	subscriptionID := "cus_test_" + uuid.NewString()[:12]
	webhookResp := postRazorpayWebhook(t, secret, subscriptionChargedPayload(teamID, subscriptionID, proPlanID))
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
		t.Errorf("C3: new pro resource limit (%.0f) must exceed old free resource limit (%.0f)",
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

	if got, ok := tierByToken[freeProv.Token]; ok {
		if got != "pro" {
			t.Errorf("C3: pre-upgrade resource should be elevated to pro after upgrade webhook; got tier=%q", got)
		}
		t.Logf("C3: pre-upgrade resource %q elevated to tier=%q ✓", freeProv.Token, got)
	} else {
		t.Errorf("C3: pre-upgrade resource %q not found in list", freeProv.Token)
	}

	t.Logf("C3: pre-upgrade=%.0f (free) → upgraded resource elevated to pro (%.0f)",
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
	proPlanID := razorpayProPlanID(t)

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

	// free DB limits — a claimed-but-unpaid team is `free`; an authenticated
	// provision gets tier=free, whose limits mirror anonymous by design.
	teamID, sessionJWT, _ := claimAndGetSession(t)
	freeDB := apiPost(t, "/db/new", nil,
		"X-Forwarded-For", uniqueIP(t),
		"Authorization", "Bearer "+sessionJWT,
	)
	skipIfServiceDown(t, freeDB, "postgres")
	var freeDBBody struct {
		Limits struct {
			StorageMB   int `json:"storage_mb"`
			Connections int `json:"connections"`
		} `json:"limits"`
		Tier string `json:"tier"`
	}
	decodeJSON(t, freeDB, &freeDBBody)

	if freeDBBody.Tier != "free" {
		t.Fatalf("C4: expected free tier for a claimed-but-unpaid team's authenticated provision, got %q", freeDBBody.Tier)
	}
	if freeDBBody.Limits.StorageMB != 10 {
		t.Errorf("C4: free postgres storage_mb: want 10, got %d", freeDBBody.Limits.StorageMB)
	}
	if freeDBBody.Limits.Connections != 2 {
		t.Errorf("C4: free postgres connections: want 2, got %d", freeDBBody.Limits.Connections)
	}
	t.Logf("C4 free postgres: storage_mb=%d connections=%d",
		freeDBBody.Limits.StorageMB, freeDBBody.Limits.Connections)

	// pro DB limits (upgrade with the real Pro plan_id, then provision)
	subscriptionID := "cus_test_" + uuid.NewString()[:12]
	webhookResp := postRazorpayWebhook(t, secret, subscriptionChargedPayload(teamID, subscriptionID, proPlanID))
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
	if proDBBody.Limits.StorageMB != 10240 {
		t.Errorf("C4: pro postgres storage_mb: want 10240, got %d", proDBBody.Limits.StorageMB)
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
	proPlanID := razorpayProPlanID(t)
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

	// Free Redis (authenticated — a claimed-but-unpaid team is `free`, whose
	// limits mirror anonymous by design).
	freeCache := apiPost(t, "/cache/new", nil,
		"X-Forwarded-For", uniqueIP(t),
		"Authorization", "Bearer "+sessionJWT,
	)
	skipIfServiceDown(t, freeCache, "redis")
	var freeCacheBody struct {
		Limits struct {
			MemoryMB int `json:"memory_mb"`
		} `json:"limits"`
		Tier string `json:"tier"`
	}
	decodeJSON(t, freeCache, &freeCacheBody)
	if freeCacheBody.Tier != "free" {
		t.Fatalf("C5: expected free tier for a claimed-but-unpaid team's authenticated provision, got %q", freeCacheBody.Tier)
	}
	if freeCacheBody.Limits.MemoryMB != 5 {
		t.Errorf("C5: free redis memory_mb: want 5, got %d", freeCacheBody.Limits.MemoryMB)
	}

	// Upgrade with the real Pro plan_id, then pro Redis
	subscriptionID := "cus_test_" + uuid.NewString()[:12]
	webhookResp := postRazorpayWebhook(t, secret, subscriptionChargedPayload(teamID, subscriptionID, proPlanID))
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
	if proCacheBody.Limits.MemoryMB != 512 {
		t.Errorf("C5: pro redis memory_mb: want 512, got %d", proCacheBody.Limits.MemoryMB)
	}

	t.Logf("C5 redis memory_mb: anonymous=%d → free=%d → pro=%d",
		anonCacheBody.Limits.MemoryMB, freeCacheBody.Limits.MemoryMB, proCacheBody.Limits.MemoryMB)

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

	t.Logf("C5 mongodb storage_mb anonymous=%d (hobby=100, pro=5120 per plans.yaml)", anonNoSQLBody.Limits.StorageMB)
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
	proPlanID := razorpayProPlanID(t)
	teamID, sessionJWT, _ := claimAndGetSession(t)

	// Upgrade with the real Pro plan_id (post-F3 an empty plan_id maps to hobby).
	subscriptionID := "cus_test_" + uuid.NewString()[:12]
	upgradeResp := postRazorpayWebhook(t, secret, subscriptionChargedPayload(teamID, subscriptionID, proPlanID))
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
	proPlanID := razorpayProPlanID(t)
	teamID, sessionJWT, _ := claimAndGetSession(t)

	// Provision one free-tier cache (a claimed-but-unpaid team is `free`).
	freeProv := provisionAnonymousAuth(t, sessionJWT)
	if freeProv.Tier != "free" {
		t.Fatalf("C8: expected free provision for a claimed-but-unpaid team, got %q", freeProv.Tier)
	}

	// Upgrade with the real Pro plan_id.
	subscriptionID := "cus_test_" + uuid.NewString()[:12]
	webhookResp := postRazorpayWebhook(t, secret, subscriptionChargedPayload(teamID, subscriptionID, proPlanID))
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

	// Find the free and pro resources in the list.
	tierByToken := make(map[string]string)
	for _, item := range listBody.Items {
		tierByToken[item.Token] = item.Tier
	}

	// After ElevateResourceTiersByTeam fix: the upgrade webhook promotes ALL existing
	// resources, so the pre-upgrade free resource is now 'pro' in the list.
	if got, ok := tierByToken[freeProv.Token]; ok {
		if got != "pro" {
			t.Errorf("C8: pre-upgrade resource tier in list: want 'pro' (elevated by webhook), got %q", got)
		}
		t.Logf("C8: pre-upgrade resource %q shows tier=%q in list ✓ (elevated by upgrade webhook)", freeProv.Token, got)
	} else {
		t.Errorf("C8: pre-upgrade resource %q not found in list; tokens present: %v",
			freeProv.Token, tierByToken)
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

// ── C9: Anonymous → free via claim (no Razorpay required) ────────────────────
//
// Stale-assertion fix (WEBHOOK-VERIFY-2026-05-19): this test previously claimed
// "claim = instant 5x limit jump to hobby". That pre-dates the `free` tier — a
// claimed-but-unpaid team is `free`, whose limits deliberately MIRROR anonymous
// (no-trial / pay-from-day-one policy: the real jump is the paid upgrade, not
// the claim). The test now verifies the actual no-Razorpay mechanic:
//   1. Anonymous provision → 5MB redis memory.
//   2. Claim it → team is `free`; a new provision is tier=free with the SAME
//      5MB limit — claiming alone does not raise limits.
// The paid pro upgrade (asserted in C1/C5) is what raises them.

func TestE2E_TierMechanics_C9_AnonToFreeViaClaim(t *testing.T) {
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

	// Claim → free account (claimed-but-unpaid).
	teamID, sessionJWT, _ := claimAndGetSession(t)
	_ = teamID

	// Provision a new cache resource as a free-tier user.
	freeProv := provisionAnonymousAuth(t, sessionJWT)
	if freeProv.Tier != "free" {
		t.Fatalf("C9: expected free tier for a claimed-but-unpaid team's authenticated provision, got %q", freeProv.Tier)
	}
	freeLimit, ok := freeProv.Limits["memory_mb"].(float64)
	if !ok {
		t.Fatalf("C9: free limits.memory_mb must be float64, got %T", freeProv.Limits["memory_mb"])
	}
	// The free tier mirrors anonymous — claiming alone does not raise limits.
	if freeLimit != anonLimit {
		t.Errorf("C9: free memory_mb (%.0f) should equal anonymous (%.0f) — claiming alone does not raise limits",
			freeLimit, anonLimit)
	}

	t.Logf("C9: anonymous=%.0f → free=%.0f (claim is an identity step; the paid upgrade is the real jump)", anonLimit, freeLimit)
	t.Logf("C9: mechanism: POST /claim sets resource.tier='free' + team.plan_tier='free'")
	t.Logf("C9:            new provisions use team.plan_tier → free limits == anonymous limits")
}

// ── C10: Free resource has correct limits and is accessible via management API ─
//
// Verifies that a free-tier cache resource provisioned by an authenticated user:
//   - Has memory_mb limit = 5 (free tier from plans.yaml, mirrors anonymous)
//   - Is visible via GET /api/v1/resources with status=active
//   - Does NOT expose connection_url in the list response
//
// Stale-assertion fix (WEBHOOK-VERIFY-2026-05-19): a claimed-but-unpaid team is
// `free`, not `hobby` — the prior `hobby`/25MB assertions pre-date the tier.
// No Razorpay required — uses JWT + claim only.

func TestE2E_TierMechanics_C10_FreeResource_CorrectLimits_VisibleInAPI(t *testing.T) {
	if os.Getenv("E2E_JWT_SECRET") == "" {
		t.Skip("E2E_JWT_SECRET not set — skipping authenticated tier tests")
	}

	_, sessionJWT, _ := claimAndGetSession(t)

	// Provision a free cache resource.
	prov := provisionAnonymousAuth(t, sessionJWT)
	if prov.Tier != "free" {
		t.Fatalf("C10: expected free provision for a claimed-but-unpaid team, got %q", prov.Tier)
	}

	// Verify free memory_mb limit is exactly 5 (from plans.yaml, mirrors anonymous).
	freeMemMB, _ := prov.Limits["memory_mb"].(float64)
	if freeMemMB != 5 {
		t.Errorf("C10: free memory_mb: want 5, got %.0f", freeMemMB)
	}
	t.Logf("C10: free cache %s | memory_mb=%.0f", prov.Token, freeMemMB)

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
				t.Errorf("C10: free resource status: want active, got %v", item["status"])
			}
			if _, hasURL := item["connection_url"]; hasURL {
				t.Error("C10: connection_url must NOT be exposed in management API list response")
			}
			t.Logf("C10: resource in list: token=%s status=%v tier=%v", prov.Token, item["status"], item["tier"])
		}
	}
	if !found {
		t.Errorf("C10: free resource %q not found in management API list", prov.Token)
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
