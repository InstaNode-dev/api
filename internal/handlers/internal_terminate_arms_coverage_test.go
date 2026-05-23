package handlers_test

// internal_terminate_arms_coverage_test.go — covers the remaining
// verifyInternalTerminateJWT rejection arms (empty-token, bad-purpose,
// missing-iat) not exercised by internal_terminate_test.go (which covers
// wrong-secret / expired-iat / team-mismatch / missing-bearer).

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

func TestInternalTerminate_AuthRejectArms(t *testing.T) {
	skipUnlessTerminateDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app := newTerminateTestApp(t, db, nil)
	teamID := uuid.NewString()

	t.Run("empty_bearer_token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/internal/teams/"+teamID+"/terminate", nil)
		req.Header.Set("Authorization", "Bearer ")
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("bad_purpose", func(t *testing.T) {
		tok := mintInternalTerminateJWT(t, testInternalTerminateSecret, "not_terminate", teamID, 0)
		resp := postTerminate(t, app, teamID, tok)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("missing_iat", func(t *testing.T) {
		// Mint a token with no iat claim at all → missing-iat rejection.
		claims := jwt.MapClaims{"purpose": "internal_terminate", "team_id": teamID}
		tk := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, err := tk.SignedString([]byte(testInternalTerminateSecret))
		require.NoError(t, err)
		resp := postTerminate(t, app, teamID, signed)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("future_iat_skew", func(t *testing.T) {
		tok := mintInternalTerminateJWT(t, testInternalTerminateSecret, "internal_terminate", teamID, 10*time.Minute)
		resp := postTerminate(t, app, teamID, tok)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})
}
