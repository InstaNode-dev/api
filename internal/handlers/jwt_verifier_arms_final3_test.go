package handlers_test

// jwt_verifier_arms_final3_test.go — FINAL serial pass #3. Closes the
// wrong-signing-method + token-invalid + non-UUID-claim arms of the two
// remaining internal-JWT verifiers (backup-refund, resend-magic-link) that the
// existing coverage tests don't reach. Mirrors the terminate verifier coverage.

import (
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// signHS512 mints an HS512-signed token with the given claims — used to drive
// the HS256-pin rejection arm of each verifier.
func signHS512(t *testing.T, secret string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	s, err := tok.SignedString([]byte(secret))
	require.NoError(t, err)
	return s
}

func signHS256(t *testing.T, secret string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := tok.SignedString([]byte(secret))
	require.NoError(t, err)
	return s
}

// ── backup-refund verifier arms ───────────────────────────────────────────────

func TestBackupRefundFinal3_JWTArms(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	app := backupRefundTestApp(t, db, rdb, testBackupRefundSecret)
	teamID := uuid.NewString()
	backupID := uuid.NewString()
	now := time.Now().Unix()

	t.Run("wrong_signing_method", func(t *testing.T) {
		signed := signHS512(t, testBackupRefundSecret, jwt.MapClaims{
			"purpose": "internal_backup_refund", "team_id": teamID, "iat": now,
		})
		resp := backupRefundPost(t, app, signed, teamID, `{"backup_id":"`+backupID+`"}`)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("bad_team_id_claim_not_uuid", func(t *testing.T) {
		signed := signHS256(t, testBackupRefundSecret, jwt.MapClaims{
			"purpose": "internal_backup_refund", "team_id": "not-a-uuid", "iat": now,
		})
		resp := backupRefundPost(t, app, signed, teamID, `{"backup_id":"`+backupID+`"}`)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("garbage_token_parse_fail", func(t *testing.T) {
		resp := backupRefundPost(t, app, "not.a.jwt", teamID, `{"backup_id":"`+backupID+`"}`)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})
}

// ── resend-magic-link verifier arms ───────────────────────────────────────────

func TestResendMagicLinkFinal3_JWTArms(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app := resendMLTestApp(t, db, testResendMagicLinkSecret, &fakeMagicLinkMailer{})
	linkID := uuid.NewString()
	now := time.Now().Unix()

	t.Run("wrong_signing_method", func(t *testing.T) {
		signed := signHS512(t, testResendMagicLinkSecret, jwt.MapClaims{
			"purpose": "internal_resend_magic_link", "link_id": linkID, "iat": now,
		})
		resp := resendMLPost(t, app, signed, linkID)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("garbage_token_parse_fail", func(t *testing.T) {
		resp := resendMLPost(t, app, "not.a.jwt", linkID)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})
}
