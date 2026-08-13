package handlers

// upgrade_chain_whitebox_test.go — in-package coverage for the token-chaining
// arms of issueOnboardingJWT that are awkward to reach over HTTP: the
// maxChainedUpgradeTokens ceiling, the empty/duplicate token skips, and the
// enabled-services filter on chained resource types.
//
// The end-to-end behaviour lives in upgrade_token_chain_test.go; this file
// pins the internal invariants that keep the JWT bounded and honest.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/crypto"
	"instant.dev/internal/plans"
)

const chainTestSecret = "test_secret_must_be_at_least_32_bytes_long_xx"

// newChainHelper builds a provisionHelper with a real enabled-services list so
// the resource-type filter in issueOnboardingJWT is exercised rather than
// short-circuited. No DB is wired: issueOnboardingJWT must not touch one —
// that is the whole point of the fix.
func newChainHelper(t *testing.T, enabledServices string) (provisionHelper, func()) {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	cfg := &config.Config{JWTSecret: chainTestSecret, EnabledServices: enabledServices}
	h := newProvisionHelper(nil, rdb, cfg, plans.Default())
	return h, func() {
		_ = rdb.Close()
		mr.Close()
	}
}

// signPrior mints a prior upgrade token carrying the given lists.
func signPrior(t *testing.T, tokens, resourceTypes []string) string {
	t.Helper()
	signed, _, err := crypto.SignOnboardingJWT([]byte(chainTestSecret), crypto.OnboardingClaims{
		Tokens:        tokens,
		ResourceTypes: resourceTypes,
	})
	require.NoError(t, err)
	return signed
}

// issueWithChain runs issueOnboardingJWT inside a real Fiber request carrying
// the prior-token header, and returns the decoded claims of the JWT it minted.
func issueWithChain(t *testing.T, h provisionHelper, resourceType string, tokens []string, priorHeader string) *crypto.OnboardingClaims {
	t.Helper()
	app := fiber.New()
	var minted string
	var issueErr error
	app.Get("/probe", func(c *fiber.Ctx) error {
		minted, _, issueErr = h.issueOnboardingJWT(c, "fp_chain", "XX", "unknown", resourceType, tokens)
		return c.JSON(fiber.Map{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	if priorHeader != "" {
		req.Header.Set(HeaderPriorUpgradeToken, priorHeader)
	}
	resp, err := app.Test(req, 2000)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)

	require.NoError(t, issueErr)
	require.NotEmpty(t, minted)
	claims, err := crypto.VerifyOnboardingJWT([]byte(chainTestSecret), minted)
	require.NoError(t, err)
	return claims
}

// TestIssueOnboardingJWT_NoHeader_IsSingleToken pins the default: with no
// prior token the JWT lists exactly what this request provisioned. There is no
// DB on the helper, so a reintroduced fingerprint sweep would panic here.
func TestIssueOnboardingJWT_NoHeader_IsSingleToken(t *testing.T) {
	h, cleanup := newChainHelper(t, "redis,postgres")
	defer cleanup()

	tok := uuid.NewString()
	claims := issueWithChain(t, h, "redis", []string{tok}, "")

	assert.Equal(t, []string{tok}, claims.Tokens)
	assert.Equal(t, []string{"redis"}, claims.ResourceTypes)
	assert.Equal(t, "fp_chain", claims.Fingerprint,
		"the fingerprint is still stamped for analytics — it just confers nothing")
}

// TestIssueOnboardingJWT_ChainSkipsEmptyAndDuplicateTokens covers the two skip
// arms of the token-merge loop.
func TestIssueOnboardingJWT_ChainSkipsEmptyAndDuplicateTokens(t *testing.T) {
	h, cleanup := newChainHelper(t, "redis,postgres")
	defer cleanup()

	current := uuid.NewString()
	older := uuid.NewString()

	// Prior lists: an empty string, the current token again, and the older
	// token twice. Only `older` may be added, exactly once.
	prior := signPrior(t, []string{"", current, older, older}, nil)
	claims := issueWithChain(t, h, "redis", []string{current}, prior)

	assert.Equal(t, []string{current, older}, claims.Tokens,
		"the merge must dedup and drop empties, preserving this request's token first")
}

// TestIssueOnboardingJWT_ChainFiltersResourceTypesByEnabledServices covers the
// resource-type merge arms: empty, already-seen, and disabled-service.
func TestIssueOnboardingJWT_ChainFiltersResourceTypesByEnabledServices(t *testing.T) {
	h, cleanup := newChainHelper(t, "redis,postgres")
	defer cleanup()

	prior := signPrior(t,
		[]string{uuid.NewString()},
		// "" → skipped; "redis" → already seen (it is this request's type);
		// "mongodb" → not in EnabledServices; "postgres" → kept.
		[]string{"", "redis", "mongodb", "postgres"},
	)
	claims := issueWithChain(t, h, "redis", []string{uuid.NewString()}, prior)

	assert.Equal(t, []string{"redis", "postgres"}, claims.ResourceTypes,
		"a JWT must only advertise services that are still claimable")
}

// TestIssueOnboardingJWT_ChainTruncatesAtCap covers the maxChainedUpgradeTokens
// ceiling. The caller's own token for THIS request must survive truncation —
// it is at the head of the list.
func TestIssueOnboardingJWT_ChainTruncatesAtCap(t *testing.T) {
	h, cleanup := newChainHelper(t, "redis")
	defer cleanup()

	current := uuid.NewString()
	oversized := make([]string, 0, maxChainedUpgradeTokens*2)
	for i := 0; i < maxChainedUpgradeTokens*2; i++ {
		oversized = append(oversized, fmt.Sprintf("%s-%d", uuid.NewString(), i))
	}

	claims := issueWithChain(t, h, "redis", []string{current}, signPrior(t, oversized, nil))

	require.Len(t, claims.Tokens, maxChainedUpgradeTokens,
		"the chain must be capped so the signed token cannot grow without bound")
	assert.Equal(t, current, claims.Tokens[0],
		"this request's own token must never be the one truncated away")
}

// TestPriorUpgradeClaims_RejectsUnverifiableHeader pins the verification gate
// directly, including the whitespace-only short circuit that must not even
// attempt a verify.
func TestPriorUpgradeClaims_RejectsUnverifiableHeader(t *testing.T) {
	h, cleanup := newChainHelper(t, "redis")
	defer cleanup()

	cases := map[string]struct {
		header  string
		wantNil bool
	}{
		"absent":          {header: "", wantNil: true},
		"whitespace_only": {header: "  \t ", wantNil: true},
		"garbage":         {header: "not.a.jwt", wantNil: true},
		"foreign_key": {header: func() string {
			signed, _, err := crypto.SignOnboardingJWT([]byte("some_other_key_at_least_32_bytes_long!!"),
				crypto.OnboardingClaims{Tokens: []string{uuid.NewString()}})
			require.NoError(t, err)
			return signed
		}(), wantNil: true},
		"genuine": {header: signPrior(t, []string{uuid.NewString()}, nil), wantNil: false},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			app := fiber.New()
			var got *crypto.OnboardingClaims
			app.Get("/probe", func(c *fiber.Ctx) error {
				got = h.priorUpgradeClaims(c)
				return c.SendStatus(fiber.StatusOK)
			})
			req := httptest.NewRequest(http.MethodGet, "/probe", nil)
			if tc.header != "" {
				req.Header.Set(HeaderPriorUpgradeToken, tc.header)
			}
			resp, err := app.Test(req, 2000)
			require.NoError(t, err)
			_ = resp.Body.Close()

			if tc.wantNil {
				assert.Nil(t, got, "an unverifiable prior token must contribute nothing")
			} else {
				require.NotNil(t, got)
				assert.Len(t, got.Tokens, 1)
			}
		})
	}
}
