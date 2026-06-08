package handlers_test

// claim_funnel_integration_test.go — integration coverage for the
// anonymous→registered claim funnel, targeting the behaviours the
// existing onboarding suites assert at most partially:
//
//   1. token-vs-jwt precedence — when BOTH the canonical `token` and the
//      deprecated `jwt` alias are present, `token` MUST win
//      (ClaimRequest.claimToken, onboarding.go:218). The existing
//      TestClaim_JWTLegacyAlias_AcceptedFallback only proves the
//      `jwt`-only fallback; nothing pins the precedence when both fields
//      carry conflicting values.
//
//   2. account-takeover guard side-effects — the existing
//      TestClaim_AccountTakeoverGuard / TestResidualClaim_AccountExists_409
//      assert the 409 + JWT-not-consumed invariant, but NOT that the
//      refusal leaves the anonymous resources unattached (team_id still
//      NULL) and mints NO session token. Those are the security-load-
//      bearing assertions of P0-1 (no resource graft, no session for an
//      unproven email) — a regression that re-attached the resources or
//      leaked a session would slip past the existing tests.
//
//   3. happy-path session token validity — the existing happy-path tests
//      assert session_token is non-empty but never decode it. This test
//      verifies the minted session JWT decodes under the server secret
//      and carries the just-created team_id (tid) + user_id (uid), proving
//      the funnel hands the caller a usable, correctly-scoped session.
//
// All helpers (onboardingResidualApp, mintOnboardingJWT, decodeErrCode,
// testhelpers.*) are defined in the existing handlers_test files and
// reused here — this file adds no new harness.
//
// These are integration tests requiring a real Postgres (TEST_DATABASE_URL).

import (
	"context"
	"net/http"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// claimAccountExistsErrCode is the wire `error` code POST /claim returns
// when the supplied email already belongs to a registered account
// (onboarding.go errCodeAccountExists). Named here so the assertions read
// against a constant, not a scattered string literal.
const claimAccountExistsErrCode = "account_exists"

// claimSessionTokenField is the response field carrying the minted session
// JWT on a successful claim (onboarding.go Claim resp map).
const claimSessionTokenField = "session_token"

// claimTeamIDField / claimUserIDField are the success-response identity
// fields echoed back to the caller.
const (
	claimTeamIDField = "team_id"
	claimUserIDField = "user_id"
)

// sessionClaimTeamID / sessionClaimUserID are the JSON keys on the minted
// session JWT (handlers.sessionClaims: `tid` / `uid`). Kept as named
// constants so the decode assertions don't hardcode the wire field names
// inline.
const (
	sessionClaimTeamID = "tid"
	sessionClaimUserID = "uid"
)

// TestClaimFunnel_TokenWinsOverJWTAlias asserts the claimToken precedence:
// when a request carries BOTH `token` (a valid provisioned onboarding JWT)
// and `jwt` (garbage), the claim succeeds — proving the handler read the
// canonical `token` field and ignored the deprecated `jwt` alias. If the
// precedence ever flipped (jwt winning), the garbage alias would drive an
// invalid_token 400 and this test would go RED.
func TestClaimFunnel_TokenWinsOverJWTAlias(t *testing.T) {
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

	// Both fields present: canonical `token` is the real JWT, deprecated
	// `jwt` is garbage. token must win → 201.
	body := map[string]any{
		"token":     res.JWT,
		"jwt":       "garbage-alias-that-must-be-ignored",
		"email":     testhelpers.UniqueEmail(t),
		"team_name": "token-wins-" + uuid.NewString()[:8],
	}
	resp := testhelpers.PostJSON(t, app, "/claim", body)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode,
		"token must win over jwt when both present — a 400 means the garbage jwt alias was read instead")
	defer db.Exec(`DELETE FROM teams WHERE id = (SELECT team_id FROM resources WHERE token = $1)`, res.Token)

	// The resource must have been claimed by the token path.
	var teamIDNull bool
	require.NoError(t, db.QueryRow(
		`SELECT team_id IS NULL FROM resources WHERE token = $1`, res.Token,
	).Scan(&teamIDNull))
	assert.False(t, teamIDNull,
		"resource must be attached — proves the canonical token drove the claim")
}

// TestClaimFunnel_AccountTakeover_NoResourceAttach_NoSession extends the
// P0-1 takeover guard coverage with the two side-effect invariants the
// existing tests omit:
//
//   - the anonymous resource the JWT pointed at must STAY unattached
//     (team_id IS NULL) — the refused claim must not graft it onto the
//     victim's (or any) team;
//   - the 409 response must carry NO session_token — a refused claim must
//     never leak a session for an email the caller didn't prove they own.
func TestClaimFunnel_AccountTakeover_NoResourceAttach_NoSession(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()
	ctx := context.Background()

	// Provision a real anonymous resource so the JWT references something
	// claimable — this is what the guard must refuse to graft.
	fp := testhelpers.UniqueFingerprint(t)
	res := testhelpers.MustProvisionCacheFull(t, app, fp)
	require.NotEmpty(t, res.JWT, "provision response must include an onboarding JWT")
	defer db.Exec(`DELETE FROM resources WHERE token = $1`, res.Token)

	// Seed a pre-existing registered account for the email the attacker
	// will claim with.
	victimEmail := testhelpers.UniqueEmail(t)
	victimTeam := testhelpers.MustCreateTeamDB(t, db, "hobby")
	_, err := models.CreateUser(ctx, db, uuid.MustParse(victimTeam), victimEmail, "", "", "owner")
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, victimTeam)

	// Claim the provisioned resource's JWT but with the victim's email.
	resp := testhelpers.PostJSON(t, app, "/claim", map[string]any{
		"token": res.JWT,
		"email": victimEmail,
	})
	defer resp.Body.Close()

	require.Equal(t, http.StatusConflict, resp.StatusCode,
		"claiming with an email that already has an account must be refused (P0-1)")
	assert.Equal(t, claimAccountExistsErrCode, decodeErrCode(t, resp),
		"refusal must use the account_exists error code")

	var got map[string]any
	testhelpers.DecodeJSON(t, resp, &got)
	_, hasSession := got[claimSessionTokenField]
	assert.False(t, hasSession,
		"a refused claim must NOT mint a session_token for an unproven email (P0-1)")

	// The anonymous resource must remain unattached — the guard must not
	// have grafted it onto the victim's team (or any team).
	var teamIDNull bool
	require.NoError(t, db.QueryRow(
		`SELECT team_id IS NULL FROM resources WHERE token = $1`, res.Token,
	).Scan(&teamIDNull))
	assert.True(t, teamIDNull,
		"a refused claim must leave the anonymous resource unattached (team_id IS NULL)")

	// Belt-and-braces: the victim's team must own no resources it didn't
	// already have (the provisioned resource must not have been grafted in).
	var grafted int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM resources WHERE team_id = $1::uuid`, victimTeam,
	).Scan(&grafted))
	assert.Equal(t, 0, grafted,
		"refused claim must not graft the anonymous resource onto the victim's team")
}

// TestClaimFunnel_HappyPath_SessionTokenDecodesToCreatedTeam asserts the
// minted session JWT is real and correctly scoped: it decodes under the
// server secret AND carries the team_id (tid) + user_id (uid) the claim
// response echoes. This proves the funnel hands the caller a usable,
// correctly-scoped session — not just a non-empty string.
func TestClaimFunnel_HappyPath_SessionTokenDecodesToCreatedTeam(t *testing.T) {
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

	resp := testhelpers.PostJSON(t, app, "/claim", map[string]any{
		"token":     res.JWT,
		"email":     testhelpers.UniqueEmail(t),
		"team_name": "session-decode-" + uuid.NewString()[:8],
	})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var got map[string]any
	testhelpers.DecodeJSON(t, resp, &got)
	defer db.Exec(`DELETE FROM teams WHERE id = (SELECT team_id FROM resources WHERE token = $1)`, res.Token)

	respTeamID, _ := got[claimTeamIDField].(string)
	respUserID, _ := got[claimUserIDField].(string)
	require.NotEmpty(t, respTeamID, "claim response must carry team_id")
	require.NotEmpty(t, respUserID, "claim response must carry user_id")

	sessionToken, _ := got[claimSessionTokenField].(string)
	require.NotEmpty(t, sessionToken, "happy-path claim must mint a session_token")

	// The session JWT must decode under the server (test) secret —
	// sessionClaims is unexported, so parse into MapClaims and read the
	// `tid` / `uid` wire fields directly.
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(sessionToken, claims, func(*jwt.Token) (interface{}, error) {
		return []byte(testhelpers.TestJWTSecret), nil
	})
	require.NoError(t, err, "minted session token must verify under the server secret")
	require.True(t, parsed.Valid, "minted session token must be valid")

	assert.Equal(t, respTeamID, claims[sessionClaimTeamID],
		"session token tid must equal the just-created team_id")
	assert.Equal(t, respUserID, claims[sessionClaimUserID],
		"session token uid must equal the just-created user_id")
}
