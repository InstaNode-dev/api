package crypto_test

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/crypto"
)

const testJWTSecret = "test-jwt-secret-that-is-at-least-32-bytes!!"

// TestSignVerify_ValidTokenVerifies ensures a freshly-signed token verifies without error.
func TestSignVerify_ValidTokenVerifies(t *testing.T) {
	claims := crypto.OnboardingClaims{
		Fingerprint: "abcdef1234",
		CloudVendor: "aws",
		Tokens:      []string{"tok_abc123"},
	}

	tokenStr, jti, err := crypto.SignOnboardingJWT([]byte(testJWTSecret), claims)
	require.NoError(t, err)
	require.NotEmpty(t, tokenStr)
	require.NotEmpty(t, jti, "SignOnboardingJWT must return a non-empty JTI")

	got, err := crypto.VerifyOnboardingJWT([]byte(testJWTSecret), tokenStr)
	require.NoError(t, err)
	assert.Equal(t, claims.Fingerprint, got.Fingerprint)
	assert.Equal(t, claims.CloudVendor, got.CloudVendor)
	assert.Equal(t, claims.Tokens, got.Tokens)
}

// TestSignVerify_ExpiredTokenReturnsErrTokenExpired validates that a manually-crafted
// expired token is rejected with the jwt.ErrTokenExpired sentinel.
func TestSignVerify_ExpiredTokenReturnsErrTokenExpired(t *testing.T) {
	past := time.Now().Add(-2 * time.Hour)
	claims := crypto.OnboardingClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(past),
			ExpiresAt: jwt.NewNumericDate(past.Add(15 * time.Minute)),
			ID:        "test-jti-expired",
		},
	}

	// Sign directly with jwt package to embed past timestamps.
	rawTok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := rawTok.SignedString([]byte(testJWTSecret))
	require.NoError(t, err)

	_, err = crypto.VerifyOnboardingJWT([]byte(testJWTSecret), tokenStr)
	require.Error(t, err)

	// The error wraps jwt.ErrTokenExpired — unwrap through ErrJWTVerify.
	var verifyErr *crypto.ErrJWTVerify
	require.ErrorAs(t, err, &verifyErr)
	assert.ErrorIs(t, verifyErr.Cause, jwt.ErrTokenExpired,
		"expired token must wrap jwt.ErrTokenExpired")
}

// TestSignVerify_WrongSecretReturnsError ensures tokens cannot be verified with a different secret.
func TestSignVerify_WrongSecretReturnsError(t *testing.T) {
	claims := crypto.OnboardingClaims{
		Fingerprint: "fp-test",
	}

	tokenStr, _, err := crypto.SignOnboardingJWT([]byte(testJWTSecret), claims)
	require.NoError(t, err)

	_, err = crypto.VerifyOnboardingJWT([]byte("completely-different-secret-32chars!!"), tokenStr)
	require.Error(t, err, "verification with wrong secret must error")

	var verifyErr *crypto.ErrJWTVerify
	assert.ErrorAs(t, err, &verifyErr)
}

// TestSignVerify_JTIIsUniquePerToken ensures every call to SignOnboardingJWT produces a distinct JTI.
func TestSignVerify_JTIIsUniquePerToken(t *testing.T) {
	const n = 50
	claims := crypto.OnboardingClaims{
		Fingerprint: "fp-jti-test",
	}

	seen := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		_, jti, err := crypto.SignOnboardingJWT([]byte(testJWTSecret), claims)
		require.NoError(t, err)
		require.NotEmpty(t, jti, "JTI must be non-empty")
		assert.False(t, seen[jti], "JTI %q was reused — must be unique per token (iteration %d)", jti, i)
		seen[jti] = true
	}
}

// TestSignVerify_ClaimsRoundtrip verifies all custom fields survive sign → verify.
func TestSignVerify_ClaimsRoundtrip(t *testing.T) {
	original := crypto.OnboardingClaims{
		Fingerprint:   "fp_deadbeef",
		Country:       "US",
		CloudVendor:   "gcp",
		OrgName:       "Acme Corp",
		Tokens:        []string{"tok_1", "tok_2", "tok_3"},
		ResourceTypes: []string{"monitor"},
		SuggestedPlan: "hobby",
	}

	tokenStr, _, err := crypto.SignOnboardingJWT([]byte(testJWTSecret), original)
	require.NoError(t, err)

	got, err := crypto.VerifyOnboardingJWT([]byte(testJWTSecret), tokenStr)
	require.NoError(t, err)

	assert.Equal(t, original.Fingerprint, got.Fingerprint)
	assert.Equal(t, original.Country, got.Country)
	assert.Equal(t, original.CloudVendor, got.CloudVendor)
	assert.Equal(t, original.OrgName, got.OrgName)
	assert.Equal(t, original.Tokens, got.Tokens)
	assert.Equal(t, original.ResourceTypes, got.ResourceTypes)
	assert.Equal(t, original.SuggestedPlan, got.SuggestedPlan)
}

// TestSignVerify_JTIEmbeddedInToken verifies the JTI returned by Sign is the same as
// what is embedded inside the verified token claims.
func TestSignVerify_JTIEmbeddedInToken(t *testing.T) {
	claims := crypto.OnboardingClaims{
		Fingerprint: "fp-embed-test",
	}

	tokenStr, jtiOut, err := crypto.SignOnboardingJWT([]byte(testJWTSecret), claims)
	require.NoError(t, err)

	got, err := crypto.VerifyOnboardingJWT([]byte(testJWTSecret), tokenStr)
	require.NoError(t, err)

	assert.Equal(t, jtiOut, got.ID,
		"JTI returned by SignOnboardingJWT must match claims.ID in verified token")
}

// TestSignVerify_FutureIssuedAtIsRejected ensures tokens with IssuedAt in the future
// are rejected — prevents pre-minting tokens.
func TestSignVerify_FutureIssuedAtIsRejected(t *testing.T) {
	future := time.Now().Add(30 * time.Minute)
	claims := crypto.OnboardingClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(future),
			ExpiresAt: jwt.NewNumericDate(future.Add(7 * 24 * time.Hour)),
			ID:        "test-future-jti",
		},
	}

	rawTok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := rawTok.SignedString([]byte(testJWTSecret))
	require.NoError(t, err)

	_, err = crypto.VerifyOnboardingJWT([]byte(testJWTSecret), tokenStr)
	require.Error(t, err,
		"token with IssuedAt in the future must be rejected")
}

// TestSignVerify_TamperedPayloadIsRejected modifies the payload and confirms verification fails.
func TestSignVerify_TamperedPayloadIsRejected(t *testing.T) {
	claims := crypto.OnboardingClaims{
		Fingerprint: "real-fp",
	}

	tokenStr, _, err := crypto.SignOnboardingJWT([]byte(testJWTSecret), claims)
	require.NoError(t, err)

	// Split into header.payload.signature and corrupt the last char of the payload.
	parts := splitToken(tokenStr)
	require.Len(t, parts, 3, "JWT must have 3 dot-separated parts")
	payload := parts[1]
	if len(payload) > 0 {
		payload = payload[:len(payload)-1] + "X"
	}
	tampered := parts[0] + "." + payload + "." + parts[2]

	_, err = crypto.VerifyOnboardingJWT([]byte(testJWTSecret), tampered)
	require.Error(t, err, "tampered token must not verify")
}

// TestSignVerify_DefaultTTLIsSeven days verifies SignOnboardingJWT sets a 7-day TTL.
func TestSignVerify_DefaultTTLIsSevenDays(t *testing.T) {
	claims := crypto.OnboardingClaims{
		Fingerprint: "fp-ttl-test",
	}

	tokenStr, _, err := crypto.SignOnboardingJWT([]byte(testJWTSecret), claims)
	require.NoError(t, err)

	got, err := crypto.VerifyOnboardingJWT([]byte(testJWTSecret), tokenStr)
	require.NoError(t, err)
	require.NotNil(t, got.ExpiresAt)

	ttl := time.Until(got.ExpiresAt.Time)
	// Allow ±5 minutes drift for test execution time.
	assert.InDelta(t, (7 * 24 * time.Hour).Seconds(), ttl.Seconds(), (5 * time.Minute).Seconds(),
		"default JWT TTL must be approximately 7 days")
}

// splitToken splits a JWT into its three dot-separated parts.
func splitToken(tok string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(tok); i++ {
		if tok[i] == '.' {
			parts = append(parts, tok[start:i])
			start = i + 1
		}
	}
	parts = append(parts, tok[start:])
	return parts
}
