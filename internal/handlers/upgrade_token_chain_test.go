package handlers_test

// upgrade_token_chain_test.go — the capability that REPLACED the network
// fingerprint as the basis for multi-service claim bundling.
//
// Before the 2026-08-13 fix, one agent session's services ended up in one
// claimable bundle because the onboarding JWT was assembled from
// GetAllActiveResourcesByFingerprint — which also swept in every stranger
// behind the same NAT (see claim_fingerprint_isolation_test.go).
//
// The bundle survives; the mechanism changed. An agent re-presents the
// `upgrade_jwt` it was handed on the previous provision via the
// X-Instant-Upgrade-Token request header. The server VERIFIES the signature
// and carries that token list forward. Holding the prior signed token proves
// the caller received it; a stranger on the same /24 cannot produce one.
//
// The header was chosen over a body field because:
//   - it applies uniformly to all seven /{service}/new endpoints plus the
//     multipart /deploy path, with no per-endpoint JSON schema change;
//   - it never collides with the caller's own `name`/`env`/`dedicated` body;
//   - old clients that don't send it are unaffected — absent means "this
//     request's token only", which is the safe default.
//
// Degradation contract, asserted below: an absent, malformed, expired,
// wrong-key, or otherwise unverifiable prior token NEVER fails the provision.
// It degrades to a single-token JWT and is logged + counted.

import (
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/crypto"
	"instant.dev/internal/handlers"
	"instant.dev/internal/testhelpers"
)

// chainHeader builds the request-header map that chains a prior upgrade token.
func chainHeader(prior string) map[string]string {
	return map[string]string{handlers.HeaderPriorUpgradeToken: prior}
}

// TestUpgradeTokenChain_ValidPriorTokenBindsAllResources is the "one caller
// chaining a valid prior JWT → all their resources bind" case. It is the
// functional replacement for the deleted fingerprint sweep, and it must work
// even while a stranger is provisioning from the very same /24.
func TestUpgradeTokenChain_ValidPriorTokenBindsAllResources(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	sharedIP := testhelpers.FingerprintToIP(testhelpers.UniqueFingerprint(t))

	first := provisionBehindNAT(t, app, sharedIP, "alice-1", nil)
	// A stranger on the same /24, provisioning in the middle of Alice's
	// session. Nothing about Alice's chain may pick this up.
	stranger := provisionBehindNAT(t, app, sharedIP, "stranger", nil)
	second := provisionBehindNAT(t, app, sharedIP, "alice-2", chainHeader(first.JWT))
	third := provisionBehindNAT(t, app, sharedIP, "alice-3", chainHeader(second.JWT))
	defer dropResources(db, first.Token, second.Token, third.Token, stranger.Token)

	chained := jwtTokens(t, third.JWT)
	assert.ElementsMatch(t, []string{third.Token, second.Token, first.Token}, chained,
		"a two-hop chain must accumulate exactly the caller's own three tokens")
	assert.NotContains(t, chained, stranger.Token,
		"chaining must never absorb a same-/24 stranger's token")

	// The whole bundle claims in one call.
	require.Equal(t, http.StatusCreated, claimAs(t, app, third.JWT))

	owner := ownerTeamID(t, db, third.Token)
	require.NotEmpty(t, owner)
	assert.Equal(t, owner, ownerTeamID(t, db, first.Token),
		"the first resource in the chain must bind to the same team")
	assert.Equal(t, owner, ownerTeamID(t, db, second.Token),
		"the middle resource in the chain must bind to the same team")
	assert.Empty(t, ownerTeamID(t, db, stranger.Token),
		"the stranger's resource must remain unowned")
}

// TestUpgradeTokenChain_ClaimPreviewShowsTheWholeChain keeps the preview
// honest in the other direction: now that the chain is what bundles services,
// the preview must promise the whole chain — no more, no less.
func TestUpgradeTokenChain_ClaimPreviewShowsTheWholeChain(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	sharedIP := testhelpers.FingerprintToIP(testhelpers.UniqueFingerprint(t))
	first := provisionBehindNAT(t, app, sharedIP, "alice-1", nil)
	stranger := provisionBehindNAT(t, app, sharedIP, "stranger", nil)
	second := provisionBehindNAT(t, app, sharedIP, "alice-2", chainHeader(first.JWT))
	defer dropResources(db, first.Token, second.Token, stranger.Token)

	resp := testhelpers.GetReq(t, app, "/claim/preview?t="+second.JWT)
	var preview struct {
		Items []struct {
			Token string `json:"token"`
		} `json:"items"`
	}
	testhelpers.DecodeJSON(t, resp, &preview)

	promised := make([]string, 0, len(preview.Items))
	for _, it := range preview.Items {
		promised = append(promised, it.Token)
	}
	assert.ElementsMatch(t, []string{first.Token, second.Token}, promised,
		"the preview must promise the whole chain and nothing outside it")

	require.Equal(t, http.StatusCreated, claimAs(t, app, second.JWT))
	assert.NotEmpty(t, ownerTeamID(t, db, first.Token))
	assert.NotEmpty(t, ownerTeamID(t, db, second.Token))
	assert.Empty(t, ownerTeamID(t, db, stranger.Token))
}

// TestUpgradeTokenChain_BadPriorTokenDegradesButNeverFails is the degradation
// contract. Every unusable prior token must leave the provision succeeding
// with a single-token JWT — never a 4xx, never a 5xx, and never a silent
// fallback to the fingerprint.
func TestUpgradeTokenChain_BadPriorTokenDegradesButNeverFails(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	// Each subtest gets its OWN shared /24 so it stays under the 5/day
	// per-fingerprint provisioning cap, while the degraded caller still sits
	// in the SAME fingerprint bucket as its victim — which is what makes
	// "must not fall back to the fingerprint" a real assertion rather than a
	// vacuous one.
	cases := []struct {
		name string
		// prior returns the hostile header value. victim is a genuine,
		// already-provisioned caller in the same fingerprint bucket.
		prior func(t *testing.T, victim natCaller) string
	}{
		{
			// Flip one character of the payload segment: the signature no
			// longer covers the bytes presented.
			name: "tampered_payload",
			prior: func(_ *testing.T, victim natCaller) string {
				b := []byte(victim.JWT)
				for i, ch := range b {
					if ch == '.' {
						if b[i+1] == 'e' {
							b[i+1] = 'f'
						} else {
							b[i+1] = 'e'
						}
						break
					}
				}
				return string(b)
			},
		},
		{
			name: "expired",
			prior: func(t *testing.T, victim natCaller) string {
				return mintPriorToken(t, victim, testhelpers.TestJWTSecret, time.Now().Add(-time.Second))
			},
		},
		{
			name: "wrong_signature",
			prior: func(t *testing.T, victim natCaller) string {
				return mintPriorToken(t, victim, "an_entirely_different_secret_at_least_32b!",
					time.Now().Add(time.Hour))
			},
		},
		{
			name:  "not_a_jwt",
			prior: func(*testing.T, natCaller) string { return "definitely-not-a-jwt" },
		},
		{
			// TrimSpace makes this indistinguishable from "no header at all":
			// the safe default, reached without a verification attempt.
			name:  "whitespace_only",
			prior: func(*testing.T, natCaller) string { return "   " },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sharedIP := testhelpers.FingerprintToIP(testhelpers.UniqueFingerprint(t))
			victim := provisionBehindNAT(t, app, sharedIP, "victim", nil)
			defer dropResources(db, victim.Token)

			// provisionBehindNAT already require()s HTTP 201 — an unusable
			// prior token must not turn a provision into an error.
			got := provisionBehindNAT(t, app, sharedIP, "degraded", chainHeader(tc.prior(t, victim)))
			defer dropResources(db, got.Token)

			tokens := jwtTokens(t, got.JWT)
			assert.Equal(t, []string{got.Token}, tokens,
				"an unusable prior token must degrade to THIS request's token only")
			assert.NotContains(t, tokens, victim.Token,
				"degradation must not fall back to the fingerprint — that is the bug being fixed")
		})
	}
}

// mintPriorToken signs a prior-upgrade-token candidate naming the victim's
// resource, with a caller-chosen key and expiry, so each hostile variant
// differs from a working token in exactly one way.
func mintPriorToken(t *testing.T, victim natCaller, secret string, exp time.Time) string {
	t.Helper()
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, crypto.OnboardingClaims{
		Tokens: []string{victim.Token},
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "prior-" + victim.Token,
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}).SignedString([]byte(secret))
	require.NoError(t, err)
	return signed
}

// TestUpgradeTokenChain_PriorTokenDoesNotLaunderAnotherCallersToken closes the
// obvious attack on the new mechanism: a stranger who somehow forges or
// re-signs a token naming a victim's resource must gain nothing, because the
// signature check is the whole gate — and even a correctly signed token
// naming a resource owned by someone else is skipped at claim time.
func TestUpgradeTokenChain_PriorTokenDoesNotLaunderAnotherCallersToken(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	sharedIP := testhelpers.FingerprintToIP(testhelpers.UniqueFingerprint(t))
	victim := provisionBehindNAT(t, app, sharedIP, "victim", nil)
	defer dropResources(db, victim.Token)

	// The attacker signs a prior token naming the victim's resource with a
	// key it does not have. The chain must reject it outright.
	forged, err := jwt.NewWithClaims(jwt.SigningMethodHS256, crypto.OnboardingClaims{
		Tokens: []string{victim.Token},
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "forged",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}).SignedString([]byte("attacker_key_that_is_not_the_platform_key"))
	require.NoError(t, err)

	attacker := provisionBehindNAT(t, app, sharedIP, "attacker", chainHeader(forged))
	defer dropResources(db, attacker.Token)

	assert.Equal(t, []string{attacker.Token}, jwtTokens(t, attacker.JWT),
		"a forged prior token must contribute nothing")

	// The victim claims first — the resource now belongs to the victim's team.
	require.Equal(t, http.StatusCreated, claimAs(t, app, victim.JWT))
	victimTeam := ownerTeamID(t, db, victim.Token)
	require.NotEmpty(t, victimTeam)

	require.Equal(t, http.StatusCreated, claimAs(t, app, attacker.JWT))
	assert.Equal(t, victimTeam, ownerTeamID(t, db, victim.Token),
		"the victim's resource must stay with the victim's team")
}
