package middleware_test

// optional_auth_strict_invalid_claims_test.go — patch-coverage backfill
// for the AuthErrorInvalidClaims branch added in PR #178 (BUG-API-051).
//
// auth.go: a token whose signature is valid AND `parsed.Valid` is true but
// either `UserID` or `TeamID` claim is empty falls through to:
//     reason = AuthErrorInvalidClaims
// That branch is reached only when the JWT is well-formed enough to pass
// jwt-go's parse but still missing required claims. Existing strict tests
// cover Garbage, Expired, WrongSecret, NonBearer; none constructs a valid
// signature with empty uid/tid.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// signSessionEmptyTeam returns a JWT with valid signature + valid exp but
// `tid` (team_id) blank — exercises the InvalidClaims arm.
func signSessionEmptyTeam(t *testing.T, secret, userID string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"uid": userID,
		"tid": "",
		"jti": uuid.NewString(),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	require.NoError(t, err)
	return tok
}

// signSessionEmptyUID returns a JWT with valid signature but empty uid.
func signSessionEmptyUID(t *testing.T, secret, teamID string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"uid": "",
		"tid": teamID,
		"jti": uuid.NewString(),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	require.NoError(t, err)
	return tok
}

// TestOptionalAuthStrict_EmptyTeamID_InvalidClaims — valid signature, empty
// `tid` → 401 in strict mode.
func TestOptionalAuthStrict_EmptyTeamID_InvalidClaims(t *testing.T) {
	tok := signSessionEmptyTeam(t, testhelpers.TestJWTSecret, uuid.NewString())
	app := newOptionalAuthStrictApp(testhelpers.TestJWTSecret)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"valid-sig but empty tid must 401 in strict mode (InvalidClaims branch)")
}

// TestOptionalAuthStrict_EmptyUserID_InvalidClaims — valid signature, empty
// `uid` → 401 in strict mode.
func TestOptionalAuthStrict_EmptyUserID_InvalidClaims(t *testing.T) {
	tok := signSessionEmptyUID(t, testhelpers.TestJWTSecret, uuid.NewString())
	app := newOptionalAuthStrictApp(testhelpers.TestJWTSecret)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"valid-sig but empty uid must 401 in strict mode (InvalidClaims branch)")
}

// TestOptionalAuthStrict_BothEmpty_InvalidClaims — both empty → still 401.
func TestOptionalAuthStrict_BothEmpty_InvalidClaims(t *testing.T) {
	claims := jwt.MapClaims{
		"uid": "",
		"tid": "",
		"jti": uuid.NewString(),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testhelpers.TestJWTSecret))
	require.NoError(t, err)

	app := newOptionalAuthStrictApp(testhelpers.TestJWTSecret)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"valid-sig with both empty claims must 401")
}
