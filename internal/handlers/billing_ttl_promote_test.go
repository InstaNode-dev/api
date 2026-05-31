package handlers_test

// billing_ttl_promote_test.go — integration coverage for the
// "subscription.charged auto-promotes the team's deployment TTL state"
// regression (P1, 2026-05-31). Drives the real /razorpay/webhook endpoint
// against a real Postgres test DB and asserts both observable effects of
// the new PromoteDeploymentTTLsForTeam call:
//
//   (1) teams.default_deployment_ttl_policy flips from 'auto_24h' to
//       'permanent' on a free→paid upgrade.
//   (2) Pre-upgrade auto_24h deployments are flipped to permanent +
//       expires_at = NULL inside the same webhook handler call.
//
// Bug class (CLAUDE.md rule 17): "fires on upgrade but not on existing
// data" — the user reported Pro-tier deploys still got the
// "expires in 6 hours" email after upgrade because the team's
// DefaultDeploymentTTLPolicy was never flipped and the in-flight 24h
// deploys were never promoted. These tests pin the fix at the webhook
// boundary so a future refactor that bypasses the model call still trips
// the contract.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// TestBillingWebhook_ChargedPromotesTeamDefaultAndDeploys is the
// end-to-end happy path: a free team with one in-flight auto_24h deploy
// receives subscription.charged with the pro plan_id. After the webhook
// returns 200 we assert (1) team default flipped to permanent, (2) the
// pre-upgrade deploy's ttl_policy flipped to permanent + expires_at
// cleared, (3) a team.ttl_policies_promoted audit row exists carrying
// the promote counts as metadata.
func TestBillingWebhook_ChargedPromotesTeamDefaultAndDeploys(t *testing.T) {
	if testhelpersSkipNoDB(t) {
		return
	}
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app, cfg := billingWebhookDBApp(t, db)

	ctx := context.Background()
	teamID := testhelpers.MustCreateTeamDB(t, db, "free")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	teamUUID := uuid.MustParse(teamID)

	// Confirm the team starts with the auto_24h default (the regression's
	// pre-condition — MustCreateTeamDB doesn't override the column default).
	require.Equal(t, "auto_24h", readTeamDefault(t, db, teamUUID),
		"fixture precondition: a fresh team must start at auto_24h — see migration 045")

	// Seed an in-flight auto_24h deploy. This is the deploy the user thought
	// they had "secured" by upgrading — the bug is that it kept its TTL.
	preDeploy, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID:    teamUUID,
		AppID:     "app-preupg-" + uuid.NewString()[:8],
		Tier:      "free",
		TTLPolicy: models.DeployTTLPolicyAuto24h,
	})
	require.NoError(t, err)
	require.True(t, preDeploy.ExpiresAt.Valid,
		"fixture precondition: auto_24h deploy must have expires_at set")

	// Drive subscription.charged with the pro plan_id.
	subID := "sub_promote_" + uuid.NewString()
	payload := makeChargedPayloadFull(t, teamID, subID, cfg.RazorpayPlanIDPro, 1, 0, "")

	resp, err := app.Test(signedWebhookRequest(t, payload), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"happy-path subscription.charged must return 200")

	// (1) THE LOAD-BEARING ASSERTION (P1 fix 2026-05-31). Team default flipped
	// to permanent. Pre-fix this was the silently-skipped step — Razorpay's
	// upgrade webhook called UpdatePlanTier + ElevateDeployments but NOT
	// PromoteDeploymentTTLs, so the team's NEXT POST /deploy/new still
	// inherited 'auto_24h' and re-fired the "expires in 6 hours" email.
	assert.Equal(t, "permanent", readTeamDefault(t, db, teamUUID),
		"webhook MUST flip team default_deployment_ttl_policy from auto_24h → permanent on paid-tier upgrade — regression P1 2026-05-31")

	// (2) Pre-existing auto_24h deploy ends up as permanent + expires_at NULL
	// after the full webhook lands. Note: the older
	// UpgradeTeamAllTiersWithSubscription tx ALSO sets ttl_policy='permanent'
	// on every non-terminal deploy as a side-effect of tier elevation, so by
	// the time the new PromoteDeploymentTTLsForTeam call runs the deploy may
	// already be permanent (DeploysPromoted reports 0 in the audit metadata).
	// The user-visible contract is "the deploy is permanent after upgrade" —
	// this assertion pins THAT, regardless of which path landed it.
	var postPolicy string
	var postExpires sql.NullTime
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT ttl_policy, expires_at FROM deployments WHERE id = $1`,
		preDeploy.ID,
	).Scan(&postPolicy, &postExpires))
	assert.Equal(t, models.DeployTTLPolicyPermanent, postPolicy,
		"pre-upgrade auto_24h deploy MUST be permanent after the webhook — regression P1 2026-05-31")
	assert.False(t, postExpires.Valid,
		"pre-upgrade deploy's expires_at MUST be cleared so the expiry warning emails stop firing")

	// (3) Audit row emitted under the new kind. Postgres re-serialises JSONB
	// with whitespace + reordered keys, so we parse + assert on the structural
	// values rather than the raw text. The team_default_flipped MUST be true
	// (the load-bearing change), reason MUST be 'tier_upgrade', and the
	// count_deploys_promoted is asserted to be present (its exact value
	// depends on whether the broader UpgradeTeamAllTiers tx already ran the
	// per-deploy ttl_policy='permanent' write — see (2) above).
	var (
		auditCount int
		summary    string
		metaText   string
	)
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM audit_log
		 WHERE team_id = $1::uuid AND kind = $2
	`, teamID, models.AuditKindTeamTTLPoliciesPromoted).Scan(&auditCount))
	assert.Equal(t, 1, auditCount,
		"exactly one team.ttl_policies_promoted audit row must exist after the upgrade")

	require.NoError(t, db.QueryRow(`
		SELECT summary, metadata::text FROM audit_log
		 WHERE team_id = $1::uuid AND kind = $2
		 ORDER BY created_at DESC LIMIT 1
	`, teamID, models.AuditKindTeamTTLPoliciesPromoted).Scan(&summary, &metaText))
	assert.Contains(t, summary, "tier_upgrade",
		"audit summary must name the trigger reason so operators can grep for it")
	meta := decodeTTLPromoteMeta(t, metaText)
	assert.Equal(t, true, meta["team_default_flipped"],
		"metadata must record team_default_flipped=true so operators can replay the change")
	assert.Equal(t, "tier_upgrade", meta["reason"],
		"metadata must record the reason slug")
	_, hasCount := meta["count_deploys_promoted"]
	assert.True(t, hasCount,
		"metadata must include count_deploys_promoted so operators can size the affected blast")
}

// decodeTTLPromoteMeta parses an audit_log.metadata::text payload that carries
// mixed JSON types (bool + number + string) into a typed map. The existing
// decodeAuditMetadata helper assumes map[string]string, which would silently
// drop our bool/number fields.
func decodeTTLPromoteMeta(t *testing.T, raw string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("decodeTTLPromoteMeta: %v\n  raw=%s", err, raw)
	}
	return m
}

// TestBillingWebhook_ChargedDoesNotPromoteOnSameTierRenewal is the
// observability noop case: a hobby team receiving a hobby renewal charge
// (already on the tier, default already permanent because the FIRST upgrade
// flipped it) MUST NOT emit a new team.ttl_policies_promoted audit row —
// nothing changed. Pins the promote-only-when-something-changed contract;
// otherwise every monthly renewal would re-emit a no-op audit row and
// pollute the customer's /api/v1/audit feed.
func TestBillingWebhook_ChargedDoesNotPromoteOnSameTierRenewal(t *testing.T) {
	if testhelpersSkipNoDB(t) {
		return
	}
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app, cfg := billingWebhookDBApp(t, db)

	ctx := context.Background()
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	teamUUID := uuid.MustParse(teamID)

	// Pre-promote the team to mirror "this is the SECOND charge — first one
	// already flipped everything to permanent".
	require.NoError(t, models.UpdateTeamDefaultDeploymentTTLPolicy(ctx, db, teamUUID, "permanent"))

	subID := "sub_renew_" + uuid.NewString()
	payload := makeChargedPayloadFull(t, teamID, subID, cfg.RazorpayPlanIDHobby, 2, 0, "")

	resp, err := app.Test(signedWebhookRequest(t, payload), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Default unchanged.
	assert.Equal(t, "permanent", readTeamDefault(t, db, teamUUID),
		"a renewal must NOT change a team default that's already permanent")

	// No promoted-audit row — nothing changed → noop branch.
	var auditCount int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM audit_log
		 WHERE team_id = $1::uuid AND kind = $2
	`, teamID, models.AuditKindTeamTTLPoliciesPromoted).Scan(&auditCount))
	assert.Equal(t, 0, auditCount,
		"a noop promote (nothing changed) MUST NOT emit a team.ttl_policies_promoted audit row — emit only on real state change")
}

// readTeamDefault is a one-line helper so the assertions above stay readable.
func readTeamDefault(t *testing.T, db *sql.DB, teamID uuid.UUID) string {
	t.Helper()
	var policy string
	err := db.QueryRow(
		`SELECT COALESCE(default_deployment_ttl_policy, 'auto_24h') FROM teams WHERE id = $1`,
		teamID,
	).Scan(&policy)
	if err != nil {
		t.Fatalf("readTeamDefault: %v", err)
	}
	return policy
}
