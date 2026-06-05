package handlers_test

// internal_e2e_account_errpaths_test.go — deterministic error-injection
// coverage for the e2e account surface's failure arms (503 paths + best-effort
// warn arms) that the happy-path suite can't reach.
//
// We use sqlmock to drive each handler to a specific mid-flow DB failure (or a
// best-effort warn), plus the randRead seam for the crypto-rand failure arm.
// No live Postgres needed — every branch is hit deterministically.

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
)

func uuidStr() string { return uuid.NewString() }

// redisClientToNowhere returns a redis client whose connection is already
// closed, so every command (and Pipeline.Exec) errors — used to exercise the
// rate-limit fail-open arm.
func redisClientToNowhere() *redis.Client {
	c := redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:1", // nothing listens here
		DialTimeout: time.Millisecond * 50,
		MaxRetries:  -1,
	})
	return c
}

func e2eDecodeErr(t *testing.T, resp *http.Response) string {
	t.Helper()
	var out struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out.Error
}

// teamInsertRows is the RETURNING shape of CreateTestCohortTeam (and the SELECT
// shape of GetTeamByID): id, name, plan_tier, stripe_customer_id, created_at,
// default_deployment_ttl_policy.
func teamInsertRows(id string) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "name", "plan_tier", "stripe_customer_id", "created_at", "default_deployment_ttl_policy"}).
		AddRow(id, "e2e", "free", nil, time.Now(), "auto_24h")
}

// userInsertRows is the RETURNING shape of CreateUser.
func userInsertRows(userID, teamID string) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "team_id", "email", "role", "github_id", "google_id", "email_verified", "created_at"}).
		AddRow(userID, teamID, "e2e@instanode.dev", "owner", nil, nil, false, time.Now())
}

// --- CREATE error arms -------------------------------------------------------

func TestE2EAccount_Create_TeamInsertError_503(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectQuery("INSERT INTO teams").WillReturnError(errors.New("boom"))

	app := newE2ETestApp(t, db, nil, testE2EToken)
	resp := postE2ECreate(t, app, testE2EToken, `{"tier":"free"}`)
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	require.Equal(t, "team_create_failed", e2eDecodeErr(t, resp))
}

func TestE2EAccount_Create_RandError_503(t *testing.T) {
	// NOT parallel: mutates the package-global randRead seam.
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectQuery("INSERT INTO teams").WillReturnRows(teamInsertRows(uuidStr()))

	restore := handlers.SetRandReadForTest(func([]byte) (int, error) {
		return 0, errors.New("forced rand failure")
	})
	defer restore()

	app := newE2ETestApp(t, db, nil, testE2EToken)
	resp := postE2ECreate(t, app, testE2EToken, `{"tier":"free"}`)
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	require.Equal(t, "rand_failed", e2eDecodeErr(t, resp))
}

func TestE2EAccount_Create_UserInsertError_503(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectQuery("INSERT INTO teams").WillReturnRows(teamInsertRows(uuidStr()))
	mock.ExpectQuery("INSERT INTO users").WillReturnError(errors.New("boom"))

	app := newE2ETestApp(t, db, nil, testE2EToken)
	resp := postE2ECreate(t, app, testE2EToken, `{"tier":"free"}`)
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	require.Equal(t, "user_create_failed", e2eDecodeErr(t, resp))
}

// SetEmailVerified failing is best-effort: the mint must still succeed (the
// warn arm runs but the 200 is returned). This exercises the verify-fail warn.
func TestE2EAccount_Create_VerifyFail_StillSucceeds(t *testing.T) {
	t.Parallel()
	teamID, userID := uuidStr(), uuidStr()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectQuery("INSERT INTO teams").WillReturnRows(teamInsertRows(teamID))
	mock.ExpectQuery("INSERT INTO users").WillReturnRows(userInsertRows(userID, teamID))
	mock.ExpectExec("UPDATE users SET email_verified").WillReturnError(errors.New("verify blip"))
	// free tier → no UpgradeTeamAllTiers. Then the audit insert.
	mock.ExpectExec("INSERT INTO audit_log").WillReturnResult(sqlmock.NewResult(0, 1))

	app := newE2ETestApp(t, db, nil, testE2EToken)
	resp := postE2ECreate(t, app, testE2EToken, `{"tier":"free"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "verify-flip failure is best-effort, mint still succeeds")
}

// Tier-set failure: paid tier, UpgradeTeamAllTiers (a transaction) errors.
func TestE2EAccount_Create_TierSetError_503(t *testing.T) {
	t.Parallel()
	teamID, userID := uuidStr(), uuidStr()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectQuery("INSERT INTO teams").WillReturnRows(teamInsertRows(teamID))
	mock.ExpectQuery("INSERT INTO users").WillReturnRows(userInsertRows(userID, teamID))
	mock.ExpectExec("UPDATE users SET email_verified").WillReturnResult(sqlmock.NewResult(0, 1))
	// UpgradeTeamAllTiers opens a transaction; force the BEGIN to fail so the
	// whole upgrade errors deterministically regardless of inner statements.
	mock.ExpectBegin().WillReturnError(errors.New("tx blip"))

	app := newE2ETestApp(t, db, nil, testE2EToken)
	resp := postE2ECreate(t, app, testE2EToken, `{"tier":"pro"}`)
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	require.Equal(t, "tier_set_failed", e2eDecodeErr(t, resp))
}

// JWT-sign failure: force it via the empty-secret arm. HS256 SignedString with
// an empty key still succeeds in the lib, so we instead cover the audit-warn
// arm (best-effort) here: a successful free mint with the audit insert erroring
// still returns 200, exercising lines 290-292.
func TestE2EAccount_Create_AuditFail_StillSucceeds(t *testing.T) {
	t.Parallel()
	teamID, userID := uuidStr(), uuidStr()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectQuery("INSERT INTO teams").WillReturnRows(teamInsertRows(teamID))
	mock.ExpectQuery("INSERT INTO users").WillReturnRows(userInsertRows(userID, teamID))
	mock.ExpectExec("UPDATE users SET email_verified").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO audit_log").WillReturnError(errors.New("audit blip"))

	app := newE2ETestApp(t, db, nil, testE2EToken)
	resp := postE2ECreate(t, app, testE2EToken, `{"tier":"free"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "audit-insert failure is best-effort, mint still succeeds")
}

// JWT-sign failure (defensive 503): forced via the e2eSignSessionJWT seam.
func TestE2EAccount_Create_JWTSignError_503(t *testing.T) {
	// NOT parallel: mutates the package-global e2eSignSessionJWT seam.
	teamID, userID := uuidStr(), uuidStr()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectQuery("INSERT INTO teams").WillReturnRows(teamInsertRows(teamID))
	mock.ExpectQuery("INSERT INTO users").WillReturnRows(userInsertRows(userID, teamID))
	mock.ExpectExec("UPDATE users SET email_verified").WillReturnResult(sqlmock.NewResult(0, 1))

	restore := handlers.SetE2ESignSessionJWTForTest(
		func(string, uuid.UUID, uuid.UUID, string, time.Time) (string, error) {
			return "", errors.New("forced sign failure")
		})
	defer restore()

	app := newE2ETestApp(t, db, nil, testE2EToken)
	resp := postE2ECreate(t, app, testE2EToken, `{"tier":"free"}`)
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	require.Equal(t, "token_issue_failed", e2eDecodeErr(t, resp))
}

// Rate-limit Redis error → fail-open (rule 1): a broken Redis must NOT block
// the mint. Uses a redis client whose connection is closed so Pipeline.Exec
// errors, exercising the fail-open arm.
func TestE2EAccount_RateLimit_RedisError_FailsOpen(t *testing.T) {
	t.Parallel()
	rdb := redisClientToNowhere()
	defer rdb.Close()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	teamID, userID := uuidStr(), uuidStr()
	mock.ExpectQuery("INSERT INTO teams").WillReturnRows(teamInsertRows(teamID))
	mock.ExpectQuery("INSERT INTO users").WillReturnRows(userInsertRows(userID, teamID))
	mock.ExpectExec("UPDATE users SET email_verified").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO audit_log").WillReturnResult(sqlmock.NewResult(0, 1))

	app := newE2ETestApp(t, db, rdb, testE2EToken)
	resp := postE2ECreate(t, app, testE2EToken, `{"tier":"free"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"a Redis error on the rate-limit check must fail open, not block the mint")
}

// --- REAP error arms ---------------------------------------------------------

func TestE2EAccount_Reap_LookupError_503(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectQuery("FROM teams WHERE id").WillReturnError(errors.New("boom"))

	app := newE2ETestApp(t, db, nil, testE2EToken)
	resp := deleteE2EReap(t, app, testE2EToken, uuidStr())
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	require.Equal(t, "db_failed", e2eDecodeErr(t, resp))
}

func TestE2EAccount_Reap_CohortCheckError_503(t *testing.T) {
	t.Parallel()
	teamID := uuidStr()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	// GetTeamByID succeeds...
	mock.ExpectQuery("FROM teams WHERE id").WillReturnRows(teamInsertRows(teamID))
	// ...then the is_test_cohort lookup errors.
	mock.ExpectQuery("SELECT is_test_cohort FROM teams WHERE id").WillReturnError(errors.New("boom"))

	app := newE2ETestApp(t, db, nil, testE2EToken)
	resp := deleteE2EReap(t, app, testE2EToken, teamID)
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	require.Equal(t, "db_failed", e2eDecodeErr(t, resp))
}

func TestE2EAccount_Reap_MarkResourcesError_503(t *testing.T) {
	t.Parallel()
	teamID := uuidStr()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectQuery("FROM teams WHERE id").WillReturnRows(teamInsertRows(teamID))
	mock.ExpectQuery("SELECT is_test_cohort FROM teams WHERE id").
		WillReturnRows(sqlmock.NewRows([]string{"is_test_cohort"}).AddRow(true))
	mock.ExpectExec("UPDATE resources").WillReturnError(errors.New("boom"))

	app := newE2ETestApp(t, db, nil, testE2EToken)
	resp := deleteE2EReap(t, app, testE2EToken, teamID)
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	require.Equal(t, "db_failed", e2eDecodeErr(t, resp))
}

func TestE2EAccount_Reap_DeleteError_503_AndAuditWarn(t *testing.T) {
	t.Parallel()
	teamID := uuidStr()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectQuery("FROM teams WHERE id").WillReturnRows(teamInsertRows(teamID))
	mock.ExpectQuery("SELECT is_test_cohort FROM teams WHERE id").
		WillReturnRows(sqlmock.NewRows([]string{"is_test_cohort"}).AddRow(true))
	mock.ExpectExec("UPDATE resources").WillReturnResult(sqlmock.NewResult(0, 1))
	// Audit insert fails (warn arm), then the DELETE fails (503 arm).
	mock.ExpectExec("INSERT INTO audit_log").WillReturnError(errors.New("audit blip"))
	mock.ExpectExec("DELETE FROM teams").WillReturnError(errors.New("delete blip"))

	app := newE2ETestApp(t, db, nil, testE2EToken)
	resp := deleteE2EReap(t, app, testE2EToken, teamID)
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	require.Equal(t, "db_failed", e2eDecodeErr(t, resp))
}
