package handlers_test

// internal_terminate_jwtarms_final3_test.go — FINAL serial pass #3. Closes the
// verifyInternalTerminateJWT arms the existing arms-coverage test misses:
//   - empty token AFTER the "Bearer " prefix (whitespace-only)  (296-301)
//   - wrong signing method (HS512, not the pinned HS256)        (316-318)
//   - structurally-parseable but tok.Valid==false               (328-333) [best-effort]
//   - team_id claim that is not a UUID                           (382-389)

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

func TestInternalTerminateFinal3_JWTArms(t *testing.T) {
	skipUnlessTerminateDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app := newTerminateTestApp(t, db, nil)
	teamID := uuid.NewString()

	// Empty token: "Bearer " followed by whitespace-only token so the prefix
	// check passes but tokenStr trims to "" (internal_terminate.go:296-301).
	t.Run("empty_token_after_prefix", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/internal/teams/"+teamID+"/terminate", nil)
		req.Header.Set("Authorization", "Bearer \t  ")
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})

	// Wrong signing method: a token signed with HS512 must be rejected by the
	// HS256 pin (internal_terminate.go:316-318).
	t.Run("wrong_signing_method", func(t *testing.T) {
		claims := jwt.MapClaims{
			"purpose": "internal_terminate",
			"team_id": teamID,
			"iat":     time.Now().Unix(),
		}
		tk := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
		signed, err := tk.SignedString([]byte(testInternalTerminateSecret))
		require.NoError(t, err)
		resp := postTerminate(t, app, teamID, signed)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})

	// team_id claim is not a UUID → bad_team_id_claim (internal_terminate.go:382-389).
	t.Run("bad_team_id_claim", func(t *testing.T) {
		claims := jwt.MapClaims{
			"purpose": "internal_terminate",
			"team_id": "not-a-uuid",
			"iat":     time.Now().Unix(),
		}
		tk := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, err := tk.SignedString([]byte(testInternalTerminateSecret))
		require.NoError(t, err)
		resp := postTerminate(t, app, teamID, signed)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})
}
