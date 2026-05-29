// onboarding_jwt_plan_boundary_test.go
//
// Locks the trust boundary between the onboarding JWT's advisory
// `SuggestedPlan` field and the team's actual `plan_tier`.
//
// Context (API FINDING-2, 2026-05-29):
//   - `crypto.OnboardingClaims.SuggestedPlan` is set during anonymous
//     provisioning (`provision_helper.go:572`) but has ZERO call sites
//     in the production claim path.
//   - `onboarding.go` derives tier purely from `models.CreateTeam`'s
//     hardcoded SQL literal `plan_tier='free'`.
//   - The only path to a paid tier is the Razorpay
//     `subscription.charged` webhook calling `ElevateResourceTiersByTeam`.
//
// This test re-signs an onboarding JWT with `SuggestedPlan="team"` while
// reusing the JTI that the server registered in `onboarding_events`,
// posts it to `/claim`, and asserts the resulting team lands on
// `plan_tier="free"`. If a future engineer wires `claims.SuggestedPlan`
// into the claim handler (i.e. starts trusting a JWT-supplied tier),
// this test goes RED.
package handlers_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/crypto"
	"instant.dev/internal/testhelpers"
)

func TestClaimDoesNotTrustJWTPlanField(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	fp := testhelpers.UniqueFingerprint(t)
	res := testhelpers.MustProvisionCacheFull(t, app, fp)
	require.NotEmpty(t, res.JWT, "provision response must include an onboarding JWT")
	defer db.Exec(`DELETE FROM resources WHERE token = $1`, res.Token)

	// Decode the server-issued JWT to lift its JTI + base claims so the
	// re-signed token still matches a row in onboarding_events.
	parsed, err := crypto.VerifyOnboardingJWT([]byte(testhelpers.TestJWTSecret), res.JWT)
	require.NoError(t, err)
	require.Equal(t, "hobby", parsed.SuggestedPlan,
		"sanity: today's provisioner mints suggested_plan='hobby' (provision_helper.go:572)")
	require.NotEmpty(t, parsed.ID, "JWT must carry a JTI registered in onboarding_events")

	// Re-sign with SuggestedPlan="team" — a hostile token claiming the
	// highest-AOV tier. JTI is preserved so the row in onboarding_events
	// resolves cleanly; the only mutation is the JSON suggested_plan field.
	hostile := crypto.OnboardingClaims{
		Fingerprint:   parsed.Fingerprint,
		Country:       parsed.Country,
		CloudVendor:   parsed.CloudVendor,
		OrgName:       parsed.OrgName,
		Tokens:        parsed.Tokens,
		ResourceTypes: parsed.ResourceTypes,
		SuggestedPlan: "team",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        parsed.ID,
			IssuedAt:  parsed.IssuedAt,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}
	hostileToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, hostile).
		SignedString([]byte(testhelpers.TestJWTSecret))
	require.NoError(t, err)

	// Re-verify defence in depth: the re-signed token DOES decode to
	// suggested_plan="team", proving the test is exercising the
	// "JWT claims a higher tier" surface — not a no-op.
	reparsed, err := crypto.VerifyOnboardingJWT([]byte(testhelpers.TestJWTSecret), hostileToken)
	require.NoError(t, err)
	require.Equal(t, "team", reparsed.SuggestedPlan)

	// POST /claim with the hostile token.
	email := testhelpers.UniqueEmail(t)
	body := map[string]any{
		"jwt":       hostileToken,
		"email":     email,
		"team_name": "jwt-plan-boundary-" + uuid.NewString()[:8],
	}
	claimResp := testhelpers.PostJSON(t, app, "/claim", body)
	defer claimResp.Body.Close()
	require.Equal(t, http.StatusCreated, claimResp.StatusCode,
		"claim must succeed — the JWT is still server-signed; the boundary lives in the post-verify tier-resolution step")

	// Team's plan_tier must be the hardcoded SQL literal 'free',
	// NOT the JWT's advisory 'team'.
	var tier string
	err = db.QueryRow(`
		SELECT plan_tier FROM teams WHERE id = (
			SELECT team_id FROM resources WHERE token = $1
		)`, res.Token).Scan(&tier)
	require.NoError(t, err)
	assert.Equal(t, "free", tier,
		"claim must derive plan_tier from the hardcoded SQL literal in models.CreateTeam, not from the JWT")

	// Resource tier must also be the hardcoded 'free' update, not 'team'.
	var resourceTier string
	err = db.QueryRow(`SELECT tier FROM resources WHERE token = $1`, res.Token).Scan(&resourceTier)
	require.NoError(t, err)
	assert.Equal(t, "free", resourceTier,
		"resource tier must flip to the hardcoded 'free' literal on claim, not the JWT-supplied tier")

	// Cleanup the team that was created.
	db.Exec(`DELETE FROM teams WHERE id = (SELECT team_id FROM resources WHERE token = $1)`, res.Token)
}
