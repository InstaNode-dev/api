package handlers_test

// claim_fingerprint_isolation_test.go — regression tests for the
// claim-by-fingerprint ownership transfer (P0, confirmed live in production
// 2026-08-13).
//
// The bug, in two layers:
//
//	Layer 1 — provision_helper.issueOnboardingJWT built the signed JWT's `tok`
//	array by sweeping models.GetAllActiveResourcesByFingerprint(fp). A
//	fingerprint is SHA256(/24 subnet + ASN), so every caller behind one
//	NAT/CGNAT range shares a bucket. The JWT handed to caller A therefore
//	ENUMERATED caller B's live resource tokens. The signature was no defence:
//	the contents were assembled from the network.
//
//	Layer 2 — onboarding.Claim, after binding everything the JWT listed, swept
//	the fingerprint AGAIN and attached any unclaimed match. So even a JWT that
//	listed nothing of B's would still hand B's resources to A.
//
// Confirmed in prod: a test team ended up owning three Postgres databases it
// never created, one created before its first API call existed.
//
// The fix: ownership derives only from a capability the caller HOLDS — the
// signed onboarding token it was handed at provision time — never from its
// network address. Multi-service bundling is preserved by chaining a prior
// signed token on X-Instant-Upgrade-Token (see upgrade_token_chain_test.go).
//
// EVERY test in this file is written against the PUBLIC surface only (no
// post-fix symbols), so it compiles — and fails — against the pre-fix tree.
// That is deliberate: it is the proof-of-vulnerability suite.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/crypto"
	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// natCaller is one of two independent agents that happen to share a public
// egress IP — the everyday NAT / CGNAT / office-wifi / CI-runner case that
// makes the fingerprint a shared bucket rather than an identity.
type natCaller struct {
	Token string
	JWT   string
}

// provisionBehindNAT POSTs /cache/new with the shared X-Forwarded-For and
// returns the caller's own token plus the onboarding JWT it was handed.
// Optional headers let a test chain a prior upgrade token.
//
// `label` makes the request body unique per caller. That is NOT cosmetic: the
// idempotency middleware's body-fingerprint fallback is scoped by the same
// network fingerprint (internal/middleware/idempotency.go — scope =
// GetFingerprint(c) for anonymous callers), so two byte-identical anonymous
// POSTs from one /24 inside 120s replay ONE response — i.e. one caller
// receives the other's credentials. That is a separate finding, reported but
// deliberately not fixed here; these tests route around it so they exercise
// the claim path rather than the replay cache.
func provisionBehindNAT(t *testing.T, app *fiber.App, sharedIP, label string, headers map[string]string) natCaller {
	t.Helper()
	reqBody := fmt.Sprintf(`{"name":%q}`, label+"-"+uuid.NewString()[:8])
	req := httptest.NewRequest(http.MethodPost, "/cache/new", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", sharedIP)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusCreated, resp.StatusCode,
		"provisioning behind the shared NAT must succeed — the wedge is non-negotiable")

	var body struct {
		Token      string `json:"token"`
		UpgradeJWT string `json:"upgrade_jwt"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.NotEmpty(t, body.Token)
	require.NotEmpty(t, body.UpgradeJWT, "anonymous provision must hand back an upgrade_jwt")
	return natCaller{Token: body.Token, JWT: body.UpgradeJWT}
}

// jwtTokens returns the `tok` array carried by a signed onboarding JWT.
func jwtTokens(t *testing.T, signed string) []string {
	t.Helper()
	claims, err := crypto.VerifyOnboardingJWT([]byte(testhelpers.TestJWTSecret), signed)
	require.NoError(t, err, "server-issued onboarding JWT must verify")
	return claims.Tokens
}

// claimAs runs POST /claim with a fresh email and returns the HTTP status.
func claimAs(t *testing.T, app *fiber.App, onboardingJWT string) int {
	t.Helper()
	resp := testhelpers.PostJSON(t, app, "/claim", map[string]any{
		"token":     onboardingJWT,
		"email":     testhelpers.UniqueEmail(t),
		"team_name": "team-" + uuid.NewString()[:8],
	})
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

// ownerTeamID returns resources.team_id for a token, or "" when still unowned.
func ownerTeamID(t *testing.T, db *sql.DB, token string) string {
	t.Helper()
	var teamID sql.NullString
	err := db.QueryRow(`SELECT team_id::text FROM resources WHERE token = $1`, token).Scan(&teamID)
	require.NoError(t, err, "resource row must exist for token %s", token)
	if !teamID.Valid {
		return ""
	}
	return teamID.String
}

// dropResources removes the rows a test created, plus any team that ended up
// owning them, so a shared test DB does not accumulate state.
func dropResources(db *sql.DB, tokens ...string) {
	for _, tok := range tokens {
		_, _ = db.Exec(`DELETE FROM teams WHERE id = (SELECT team_id FROM resources WHERE token = $1)`, tok)
		_, _ = db.Exec(`DELETE FROM resources WHERE token = $1`, tok)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// THE regression test. Two DIFFERENT callers, one fingerprint.
// ─────────────────────────────────────────────────────────────────────────────

// TestClaim_TwoCallersOneFingerprint_ClaimBindsOnlyOwnResources is the direct
// regression test for the live P0. Two unrelated agents provision from the same
// /24 inside one TTL window; the first to claim must NOT inherit the other's
// live database credential.
//
// It asserts BOTH layers, because fixing only one leaves the hole open:
//
//	Layer 1 — the signed JWT handed to caller B must not even ENUMERATE caller
//	          A's token. (Pre-fix: B's `tok` array contains A's token.)
//	Layer 2 — claiming with caller A's JWT must leave caller B's resource
//	          unowned. (Pre-fix: the claim-time sweep attaches it to A's team.)
func TestClaim_TwoCallersOneFingerprint_ClaimBindsOnlyOwnResources(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	// One public egress IP, two strangers behind it.
	sharedIP := testhelpers.FingerprintToIP(testhelpers.UniqueFingerprint(t))

	alice := provisionBehindNAT(t, app, sharedIP, "alice", nil)
	bob := provisionBehindNAT(t, app, sharedIP, "bob", nil)
	defer dropResources(db, alice.Token, bob.Token)

	require.NotEqual(t, alice.Token, bob.Token,
		"sanity: two provisions behind one NAT must yield two distinct resources")

	// ── Layer 1: the signed JWT must not enumerate the other caller ──────────
	assert.Equal(t, []string{bob.Token}, jwtTokens(t, bob.JWT),
		"LAYER 1 REGRESSION: Bob's onboarding JWT must list only Bob's own token. "+
			"Building `tok` from GetAllActiveResourcesByFingerprint leaks Alice's "+
			"resource token to Bob inside a signed credential.")
	assert.Equal(t, []string{alice.Token}, jwtTokens(t, alice.JWT),
		"LAYER 1: Alice's onboarding JWT must list only Alice's own token")

	// ── Layer 2: claiming must bind only what the JWT lists ──────────────────
	require.Equal(t, http.StatusCreated, claimAs(t, app, alice.JWT),
		"Alice's claim must succeed")

	aliceOwner := ownerTeamID(t, db, alice.Token)
	assert.NotEmpty(t, aliceOwner, "Alice's own resource must be bound to her new team")

	assert.Empty(t, ownerTeamID(t, db, bob.Token),
		"LAYER 2 REGRESSION: Bob's resource must still be UNOWNED after Alice claims. "+
			"The claim-time fingerprint sweep handed a stranger's live credential to "+
			"whoever claimed first — this is the exact prod incident.")

	// And Bob can still claim his own — the fix must not strand him.
	require.Equal(t, http.StatusCreated, claimAs(t, app, bob.JWT),
		"Bob must still be able to claim his own resource afterwards")
	bobOwner := ownerTeamID(t, db, bob.Token)
	assert.NotEmpty(t, bobOwner, "Bob's resource must bind to Bob's team")
	assert.NotEqual(t, aliceOwner, bobOwner,
		"Alice and Bob must end up in different teams — a shared /24 is not a shared account")
}

// ─────────────────────────────────────────────────────────────────────────────
// /claim/preview must not over-promise.
// ─────────────────────────────────────────────────────────────────────────────

// TestClaimPreview_MatchesWhatClaimBinds pins the preview-equals-claim
// invariant. The preview is what an agent shows the user before they commit;
// a preview that lists a stranger's resource is its own bug, and it is the
// surface that made the claim-by-fingerprint hole look intentional.
//
// The assertion is a set comparison computed from the DB after the claim, so
// it fails if EITHER side drifts — not just if the preview is wrong.
func TestClaimPreview_MatchesWhatClaimBinds(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	sharedIP := testhelpers.FingerprintToIP(testhelpers.UniqueFingerprint(t))
	alice := provisionBehindNAT(t, app, sharedIP, "alice", nil)
	bob := provisionBehindNAT(t, app, sharedIP, "bob", nil)
	defer dropResources(db, alice.Token, bob.Token)

	// What the preview promises Alice.
	resp := testhelpers.GetReq(t, app, "/claim/preview?t="+alice.JWT)
	var preview struct {
		OK         bool `json:"ok"`
		TokenValid bool `json:"token_valid"`
		Items      []struct {
			Token string `json:"token"`
		} `json:"items"`
	}
	testhelpers.DecodeJSON(t, resp, &preview)
	require.True(t, preview.OK)
	require.True(t, preview.TokenValid)

	promised := make([]string, 0, len(preview.Items))
	for _, it := range preview.Items {
		promised = append(promised, it.Token)
	}
	sort.Strings(promised)

	assert.Equal(t, []string{alice.Token}, promised,
		"the preview must promise Alice exactly her own resource — never Bob's, "+
			"which merely shares her /24")

	// What the claim actually binds.
	require.Equal(t, http.StatusCreated, claimAs(t, app, alice.JWT))

	var bound []string
	for _, tok := range []string{alice.Token, bob.Token} {
		if ownerTeamID(t, db, tok) != "" {
			bound = append(bound, tok)
		}
	}
	sort.Strings(bound)

	assert.Equal(t, promised, bound,
		"PREVIEW-EQUALS-CLAIM: /claim/preview must list exactly the set /claim binds")
}

// ─────────────────────────────────────────────────────────────────────────────
// A JWT naming a token someone else already owns.
// ─────────────────────────────────────────────────────────────────────────────

// TestClaim_SkipsTokenAlreadyClaimedByAnotherTeam covers the residual case the
// fix must still handle safely: a token appears in a verified JWT, but by the
// time it is redeemed the resource belongs to a different team.
//
// This is not hypothetical. Onboarding JWTs live 7 days, and every JWT minted
// BEFORE this fix shipped carries fingerprint-swept strangers' tokens. Those
// tokens must be skipped, never re-pointed at the redeeming team.
//
// The hostile token is built by re-signing Alice's real JWT with Bob's token
// appended, preserving the JTI so it still resolves against onboarding_events
// — i.e. exactly the shape of a legacy pre-fix JWT.
func TestClaim_SkipsTokenAlreadyClaimedByAnotherTeam(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	sharedIP := testhelpers.FingerprintToIP(testhelpers.UniqueFingerprint(t))
	alice := provisionBehindNAT(t, app, sharedIP, "alice", nil)
	bob := provisionBehindNAT(t, app, sharedIP, "bob", nil)
	defer dropResources(db, alice.Token, bob.Token)

	// Bob claims first — his resource now belongs to Bob's team.
	require.Equal(t, http.StatusCreated, claimAs(t, app, bob.JWT))
	bobOwner := ownerTeamID(t, db, bob.Token)
	require.NotEmpty(t, bobOwner)

	// Alice presents a (legitimately signed) token that also names Bob's
	// resource — the legacy pre-fix JWT shape.
	base, err := crypto.VerifyOnboardingJWT([]byte(testhelpers.TestJWTSecret), alice.JWT)
	require.NoError(t, err)
	legacy := crypto.OnboardingClaims{
		Fingerprint:   base.Fingerprint,
		Country:       base.Country,
		CloudVendor:   base.CloudVendor,
		OrgName:       base.OrgName,
		Tokens:        []string{alice.Token, bob.Token},
		ResourceTypes: base.ResourceTypes,
		SuggestedPlan: base.SuggestedPlan,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        base.ID, // preserved so onboarding_events resolves
			IssuedAt:  base.IssuedAt,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}
	legacyToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, legacy).
		SignedString([]byte(testhelpers.TestJWTSecret))
	require.NoError(t, err)

	// The preview must already refuse to promise Bob's resource.
	resp := testhelpers.GetReq(t, app, "/claim/preview?t="+legacyToken)
	var preview struct {
		Items []struct {
			Token string `json:"token"`
		} `json:"items"`
	}
	testhelpers.DecodeJSON(t, resp, &preview)
	for _, it := range preview.Items {
		assert.NotEqual(t, bob.Token, it.Token,
			"preview must not promise a resource another team already owns")
	}

	require.Equal(t, http.StatusCreated, claimAs(t, app, legacyToken),
		"an unowned token alongside an already-owned one must still claim cleanly")

	assert.Equal(t, bobOwner, ownerTeamID(t, db, bob.Token),
		"SKIPPED, NOT STOLEN: an already-claimed token named in a JWT must stay "+
			"with its existing owner")
	assert.NotEmpty(t, ownerTeamID(t, db, alice.Token),
		"Alice's own resource must still bind")
}

// TestClaim_IgnoresUnparseableAndUnknownTokensInJWT covers the two remaining
// skip arms of the claim transfer loop (and their preview twins): a `tok`
// entry that is not a UUID, and a well-formed UUID with no resource row.
// Neither may abort the claim or leak into the bound set.
func TestClaim_IgnoresUnparseableAndUnknownTokensInJWT(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	sharedIP := testhelpers.FingerprintToIP(testhelpers.UniqueFingerprint(t))
	alice := provisionBehindNAT(t, app, sharedIP, "alice", nil)
	defer dropResources(db, alice.Token)

	base, err := crypto.VerifyOnboardingJWT([]byte(testhelpers.TestJWTSecret), alice.JWT)
	require.NoError(t, err)

	ghost := uuid.NewString() // well-formed, no row
	noisy := crypto.OnboardingClaims{
		Fingerprint: base.Fingerprint,
		// "not-a-uuid" exercises the parse-failure skip; ghost exercises the
		// lookup-failure skip; the duplicate exercises the dedup skip.
		Tokens: []string{"not-a-uuid", ghost, alice.Token, alice.Token},
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        base.ID,
			IssuedAt:  base.IssuedAt,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}
	noisyToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, noisy).
		SignedString([]byte(testhelpers.TestJWTSecret))
	require.NoError(t, err)

	resp := testhelpers.GetReq(t, app, "/claim/preview?t="+noisyToken)
	var preview struct {
		Items []struct {
			Token string `json:"token"`
		} `json:"items"`
	}
	testhelpers.DecodeJSON(t, resp, &preview)
	require.Len(t, preview.Items, 1, "only the one real, unowned resource may be previewed")
	assert.Equal(t, alice.Token, preview.Items[0].Token)

	require.Equal(t, http.StatusCreated, claimAs(t, app, noisyToken))
	assert.NotEmpty(t, ownerTeamID(t, db, alice.Token))

	var ghostRows int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM resources WHERE token = $1`, ghost).Scan(&ghostRows))
	assert.Zero(t, ghostRows, "a claim must never conjure a row for an unknown token")
}

// TestGetAllActiveResourcesByFingerprint_HasNoOwnershipCallSites is the
// coverage test rule 17 asks for: it fails if a NEW ownership-granting call
// site of the fingerprint sweep appears later.
//
// The query itself is legitimate and stays — the recycle gate uses it to decide
// "is this fingerprint mid-session", which is quota logic, not ownership. What
// must never come back is a call from the claim/JWT-issuance path. This test
// pins the behavioural contract that such a call would break: a resource that
// exists ONLY in the fingerprint bucket (never named in any JWT) is invisible
// to both /claim/preview and /claim.
func TestGetAllActiveResourcesByFingerprint_HasNoOwnershipCallSites(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	sharedIP := testhelpers.FingerprintToIP(testhelpers.UniqueFingerprint(t))
	alice := provisionBehindNAT(t, app, sharedIP, "alice", nil)
	defer dropResources(db, alice.Token)

	// A stranger's row seeded straight into Alice's fingerprint bucket — the
	// "provisioned after the JWT was issued" case the removed sweep existed to
	// serve, and the exact shape the prod incident took.
	var fingerprint string
	require.NoError(t, db.QueryRow(
		`SELECT fingerprint FROM resources WHERE token = $1`, alice.Token).Scan(&fingerprint))

	strangerExpiry := time.Now().UTC().Add(24 * time.Hour)
	stranger, err := models.CreateResource(t.Context(), db, models.CreateResourceParams{
		ResourceType: "redis",
		Name:         fmt.Sprintf("stranger-%s", uuid.NewString()[:8]),
		Tier:         "anonymous",
		Fingerprint:  fingerprint,
		ExpiresAt:    &strangerExpiry,
	})
	require.NoError(t, err)
	defer dropResources(db, stranger.Token.String())
	// CreateResource lands rows in 'pending'; the sweep only sees 'active'.
	require.NoError(t, models.MarkResourceActive(t.Context(), db, stranger.ID))

	// Sanity: the sweep really would find it.
	swept, err := models.GetAllActiveResourcesByFingerprint(t.Context(), db, fingerprint)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(swept), 2,
		"sanity: both rows share the fingerprint bucket, so a sweep would return both")

	resp := testhelpers.GetReq(t, app, "/claim/preview?t="+alice.JWT)
	var preview struct {
		Items []struct {
			Token string `json:"token"`
		} `json:"items"`
	}
	testhelpers.DecodeJSON(t, resp, &preview)
	require.Len(t, preview.Items, 1,
		"preview must be built from the JWT alone — a fingerprint sweep would return 2")
	assert.Equal(t, alice.Token, preview.Items[0].Token)

	require.Equal(t, http.StatusCreated, claimAs(t, app, alice.JWT))
	assert.Empty(t, ownerTeamID(t, db, stranger.Token.String()),
		"a resource reachable only via the fingerprint must never be claimed")
}
