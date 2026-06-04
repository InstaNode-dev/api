package handlers_test

// billing_block_helpers_test.go — shared helpers for the W3 billing-block
// integration suite (billing_block_*_test.go). These are W3-local helpers
// (prefixed billingBlock*) so they do not collide with the existing cov2*/
// billing* helpers this suite also reuses. NOTHING here redefines an existing
// helper — seedVerifiedTeamUser, cov2CheckoutApp, changePlanAppReal,
// changePlanReq, postCheckoutReq, signRazorpayPayload,
// makeSubscriptionChargedPayloadWithPlan, makeSubscriptionCancelledPayload and
// cov2WebhookAppReal all already exist in the package and are used as-is.

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// billingBlockJWTSecret is the ≥32-byte HMAC secret the W3 suite stamps onto
// every test cfg. Identical value to testhelpers.TestJWTSecret; named locally
// so the intent ("any valid secret, never a real one") is explicit at call
// sites.
const billingBlockJWTSecret = testhelpers.TestJWTSecret

// billingBlockSkipNoDB skips a W3 test when no test Postgres is configured.
// The billing block is a real-backend integration surface — these tests
// assert on actual rows in teams/resources/audit_log, so a missing DB is a
// loud skip, never a false green.
func billingBlockSkipNoDB(t *testing.T) bool {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("W3 billing-block integration: TEST_DATABASE_URL not set")
		return true
	}
	return false
}

// billingBlockDB opens a fresh migrated test DB and returns it with its
// cleanup. Thin wrapper over testhelpers.SetupTestDB so every W3 test reads
// the same way.
func billingBlockDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	return testhelpers.SetupTestDB(t)
}

// mustSeedTeam creates a team row at the given plan tier and registers a
// cleanup. Returns the team id as a string (the shape changePlanAppReal +
// the webhook payload builders consume).
func mustSeedTeam(t *testing.T, db *sql.DB, tier string) string {
	t.Helper()
	id := testhelpers.MustCreateTeamDB(t, db, tier)
	t.Cleanup(func() {
		db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, id)
	})
	return id
}

// billingBlockSeedResource inserts an active resource owned by teamID at the
// given tier and returns its id. Used by the webhook-transition tests to
// prove that an upgrade ELEVATES existing resources and a downgrade LEAVES
// them. expires_at is left NULL (a claimed, permanent resource) so the
// reaper-race guard in the elevation UPDATE never excludes it.
func billingBlockSeedResource(t *testing.T, db *sql.DB, teamID uuid.UUID, resourceType, tier string) uuid.UUID {
	t.Helper()
	res, err := models.CreateResource(context.Background(), db, models.CreateResourceParams{
		TeamID:       &teamID,
		ResourceType: resourceType,
		Name:         "w3-" + resourceType + "-" + uuid.NewString()[:8],
		Tier:         tier,
		Env:          "production",
	})
	require.NoError(t, err, "seed resource (%s/%s)", resourceType, tier)
	// CreateResource inserts a 'pending' row; the tier-elevation UPDATE only
	// touches active/paused/suspended rows. Flip to 'active' so the resource
	// is in the state a real claimed resource would be in when an upgrade
	// webhook fires.
	require.NoError(t, models.MarkResourceActive(context.Background(), db, res.ID),
		"activate seeded resource (%s/%s)", resourceType, tier)
	t.Cleanup(func() {
		db.Exec(`DELETE FROM resources WHERE id = $1`, res.ID)
	})
	return res.ID
}

// billingBlockResourceTier reads back the current tier of a resource row so a
// test can assert whether a webhook elevated or left it.
func billingBlockResourceTier(t *testing.T, db *sql.DB, id uuid.UUID) string {
	t.Helper()
	var tier string
	require.NoError(t,
		db.QueryRow(`SELECT tier FROM resources WHERE id = $1`, id).Scan(&tier),
		"read resource tier")
	return tier
}

// billingBlockTeamTier reads back the current plan_tier of a team row.
func billingBlockTeamTier(t *testing.T, db *sql.DB, teamID string) string {
	t.Helper()
	var tier string
	require.NoError(t,
		db.QueryRow(`SELECT plan_tier FROM teams WHERE id = $1::uuid`, teamID).Scan(&tier),
		"read team plan_tier")
	return tier
}
