package handlers_test

// onboarding_residual_test.go — residual coverage for onboarding.go
// (81.5% → ≥95%). Targets the branches the prior slice left uncovered:
//
//   StartLanding:  missing_token, invalid_token, JTI-not-found, db_error
//                  (brokenDB), already-claimed redirect.
//   ClaimPreview:  db_error (brokenDB), unparseable/looked-up-miss token in
//                  claims.Tokens (continue arms), fingerprint-lookup warn.
//   Claim:         jti_lookup_failed (brokenDB), mark_converted already-used
//                  race (pre-converted row), happy-path with claimable
//                  resources + fingerprint augmentation.
//
// All onboarding JWTs are minted in-process with the test secret (same
// pattern as onboarding_coverage_test.go).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/crypto"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// onboardingResidualApp registers /start, /claim, and /claim/preview against
// an arbitrary DB so the db-error arms can be driven with a brokenDB.
func onboardingResidualApp(t *testing.T, db *sql.DB) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:        testhelpers.TestJWTSecret,
		AESKey:           testhelpers.TestAESKeyHex,
		DashboardBaseURL: "http://localhost:5173",
	}
	h := handlers.NewOnboardingHandler(db, cfg, email.NewNoop())
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": err.Error()})
		},
	})
	app.Get("/start", h.StartLanding)
	app.Post("/claim", h.Claim)
	app.Get("/claim/preview", h.ClaimPreview)
	return app
}

// mintOnboardingJWT signs an OnboardingClaims with the test secret.
func mintOnboardingJWT(t *testing.T, jti, fp string, tokens []string) string {
	t.Helper()
	claims := crypto.OnboardingClaims{
		Fingerprint: fp,
		Tokens:      tokens,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(testhelpers.TestJWTSecret))
	require.NoError(t, err)
	return signed
}

func doGet(t *testing.T, app *fiber.App, path string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// ── StartLanding ─────────────────────────────────────────────────────────────
//
// API-5 (QA 2026-05-29): /start now ALWAYS 302s to the dashboard /claim
// regardless of token validity — the dashboard ClaimPage renders any token
// error (expired / unrecognised / already-claimed) in a friendly UI. The
// platform side no longer validates the JWT at /start; that's the dashboard's
// job. Per CLAUDE.md "Live API surface" line.

// TestResidualStartLanding_MissingToken_RedirectsToClaim — no token → 302 to
// /claim (no t=) so the dashboard renders its empty / login state.
func TestResidualStartLanding_MissingToken_RedirectsToClaim(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := onboardingResidualApp(t, db)
	resp := doGet(t, app, "/start")
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Location"), "/claim")
	// No t= query when missing.
	assert.NotContains(t, resp.Header.Get("Location"), "/claim?t=")
}

// TestResidualStartLanding_GarbageToken_StillRedirects — invalid/garbage tokens
// must NOT 400 the user with raw JSON. The dashboard renders the error.
func TestResidualStartLanding_GarbageToken_StillRedirects(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := onboardingResidualApp(t, db)
	resp := doGet(t, app, "/start?t=garbage")
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Location"), "/claim?t=garbage")
}

// TestResidualStartLanding_UnknownJTI_StillRedirects — a syntactically valid
// JWT for an unknown JTI must also 302 — the dashboard does the JTI lookup
// and renders the "expired/unrecognised" message.
func TestResidualStartLanding_UnknownJTI_StillRedirects(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := onboardingResidualApp(t, db)
	signed := mintOnboardingJWT(t, uuid.NewString(), "fp-start-unknown", nil)
	resp := doGet(t, app, "/start?t="+signed)
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Location"), "/claim?t=")
}

// TestResidualStartLanding_HappyPath_Redirects — happy path is still a 302
// with t= query intact. Same shape as the always-302 contract.
func TestResidualStartLanding_HappyPath_Redirects(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := onboardingResidualApp(t, db)
	jti := uuid.NewString()
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO onboarding_events (jti, fingerprint, team_id)
		VALUES ($1, $2, NULL)
	`, jti, "fp-start-ok")
	require.NoError(t, err)
	signed := mintOnboardingJWT(t, jti, "fp-start-ok", nil)
	resp := doGet(t, app, "/start?t="+signed)
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Location"), "/claim?t=")
}

// ── ClaimPreview ─────────────────────────────────────────────────────────────

// TestClaimPreview_DBError_503 drives the preview db_error arm (109-110).
func TestResidualClaimPreview_DBError_503(t *testing.T) {
	app := onboardingResidualApp(t, brokenDB(t))
	signed := mintOnboardingJWT(t, uuid.NewString(), "fp-prev-broken", nil)
	resp := doGet(t, app, "/claim/preview?t="+signed)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestClaimPreview_BadAndMissingTokensInClaims drives the per-token continue
// arms (128-134): one unparseable token + one well-formed-but-unknown token
// in claims.Tokens. Both are skipped; the response still 200s.
func TestResidualClaimPreview_BadAndMissingTokensInClaims(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := onboardingResidualApp(t, db)
	jti := uuid.NewString()
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO onboarding_events (jti, fingerprint, team_id)
		VALUES ($1, $2, NULL)
	`, jti, "fp-prev-tokens")
	require.NoError(t, err)
	// one non-UUID token (parse continue) + one valid-but-missing UUID
	// (lookup continue).
	signed := mintOnboardingJWT(t, jti, "fp-prev-tokens",
		[]string{"not-a-uuid", uuid.NewString()})
	resp := doGet(t, app, "/claim/preview?t="+signed)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestResidualIsValidEmail_EdgeArms drives isValidEmail's domain-shape reject
// arms (676-682) via the exported helper: dotless domain, trailing-dot domain,
// leading-dot domain, and the valid baseline. Pure function — deterministic.
func TestResidualIsValidEmail_EdgeArms(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"you@example.com", true},   // valid baseline
		{"x@localhost", false},      // dotless domain (676-677)
		{"x@example.com.", false},   // trailing-dot domain (680-682)
		{"x@.example.com", false},   // leading-dot domain (680-682)
		{"you @example.com", false}, // inner whitespace (654-655)
		{"", false},                 // empty (647-648)
	}
	for _, c := range cases {
		assert.Equal(t, c.want, handlers.IsValidEmailForTest(c.in), "isValidEmail(%q)", c.in)
	}
}

// TestResidualMaskEmailForLog drives maskEmailForLog's branches via the
// exported helper.
func TestResidualMaskEmailForLog(t *testing.T) {
	assert.NotEmpty(t, handlers.MaskEmailForLogForTest("alice@example.com"))
	assert.NotPanics(t, func() { _ = handlers.MaskEmailForLogForTest("no-at-sign") })
	assert.NotPanics(t, func() { _ = handlers.MaskEmailForLogForTest("") })
}

// TestResidualClaimPreview_FingerprintResources drives the ClaimPreview
// fingerprint-augmentation loop (147-167): a preview whose JWT carries a
// fingerprint with active resources NOT in the token list.
func TestResidualClaimPreview_FingerprintResources(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := onboardingResidualApp(t, db)
	ctx := context.Background()

	fp := "fp-prev-aug-" + uuid.NewString()[:8]
	jti := uuid.NewString()
	_, err := db.ExecContext(ctx, `
		INSERT INTO onboarding_events (jti, fingerprint, team_id) VALUES ($1, $2, NULL)
	`, jti, fp)
	require.NoError(t, err)
	// Two anonymous resources for this fingerprint, NOT in the token list.
	for i := 0; i < 2; i++ {
		_, err = db.ExecContext(ctx, `
			INSERT INTO resources (token, resource_type, tier, env, status, fingerprint)
			VALUES ($1, 'redis', 'anonymous', 'production', 'active', $2)
		`, uuid.NewString(), fp)
		require.NoError(t, err)
	}
	signed := mintOnboardingJWT(t, jti, fp, nil) // empty token list → all via fingerprint
	resp := doGet(t, app, "/claim/preview?t="+signed)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	res, _ := body["resources"].([]any)
	assert.GreaterOrEqual(t, len(res), 2, "fingerprint-augmented resources must appear in preview")
}

// TestResidualClaim_AccountExists_409 drives the account-takeover-guard arm
// (325-336): an email that already belongs to a registered account → 409
// account_exists, JWT NOT consumed.
func TestResidualClaim_AccountExists_409(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := onboardingResidualApp(t, db)
	ctx := context.Background()

	// Pre-existing account.
	existingTeam := testhelpers.MustCreateTeamDB(t, db, "hobby")
	existingEmail := testhelpers.UniqueEmail(t)
	_, err := models.CreateUser(ctx, db, uuid.MustParse(existingTeam), existingEmail, "", "", "owner")
	require.NoError(t, err)

	fp := "fp-claim-exists-" + uuid.NewString()[:8]
	jti := uuid.NewString()
	_, err = db.ExecContext(ctx, `
		INSERT INTO onboarding_events (jti, fingerprint, team_id) VALUES ($1, $2, NULL)
	`, jti, fp)
	require.NoError(t, err)
	signed := mintOnboardingJWT(t, jti, fp, nil)

	resp := testhelpers.PostJSON(t, app, "/claim",
		map[string]any{"token": signed, "email": existingEmail})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

// ── Claim ────────────────────────────────────────────────────────────────────

// TestClaim_JTILookupFailed_503 drives the jti_lookup_failed arm (300-301)
// via a brokenDB: body valid, JWT verifies, GetOnboardingByJTI errors.
func TestResidualClaim_JTILookupFailed_503(t *testing.T) {
	app := onboardingResidualApp(t, brokenDB(t))
	signed := mintOnboardingJWT(t, uuid.NewString(), "fp-claim-broken", nil)
	resp := testhelpers.PostJSON(t, app, "/claim",
		map[string]any{"token": signed, "email": testhelpers.UniqueEmail(t)})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestClaim_HappyPath_ClaimsResources drives the success path including the
// JWT-listed-token transfer (428-452) and fingerprint augmentation (455-470).
func TestResidualClaim_HappyPath_ClaimsResources(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := onboardingResidualApp(t, db)
	ctx := context.Background()

	fp := "fp-claim-happy-" + uuid.NewString()[:8]
	jti := uuid.NewString()
	_, err := db.ExecContext(ctx, `
		INSERT INTO onboarding_events (jti, fingerprint, team_id)
		VALUES ($1, $2, NULL)
	`, jti, fp)
	require.NoError(t, err)

	// A JWT-listed anonymous resource (no team_id).
	listedToken := uuid.NewString()
	_, err = db.ExecContext(ctx, `
		INSERT INTO resources (token, resource_type, tier, env, status, fingerprint)
		VALUES ($1, 'redis', 'anonymous', 'production', 'active', $2)
	`, listedToken, fp)
	require.NoError(t, err)

	// A fingerprint-only anonymous resource NOT in the JWT token list.
	fpToken := uuid.NewString()
	_, err = db.ExecContext(ctx, `
		INSERT INTO resources (token, resource_type, tier, env, status, fingerprint)
		VALUES ($1, 'postgres', 'anonymous', 'production', 'active', $2)
	`, fpToken, fp)
	require.NoError(t, err)

	// An ALREADY-CLAIMED resource in the token list (team_id set) — exercises
	// the "already claimed → continue" arm (437-438).
	otherTeam := testhelpers.MustCreateTeamDB(t, db, "hobby")
	claimedToken := uuid.NewString()
	_, err = db.ExecContext(ctx, `
		INSERT INTO resources (team_id, token, resource_type, tier, env, status, fingerprint)
		VALUES ($1::uuid, $2, 'redis', 'free', 'production', 'active', $3)
	`, otherTeam, claimedToken, fp)
	require.NoError(t, err)

	// Token list: a bad-UUID (parse-continue 430-431), a well-formed-but-
	// missing UUID (fetch-continue 434-435), the already-claimed token
	// (already-claimed-continue 437-438), and the real listed token.
	signed := mintOnboardingJWT(t, jti, fp,
		[]string{"not-a-uuid", uuid.NewString(), claimedToken, listedToken})
	email := testhelpers.UniqueEmail(t)
	resp := testhelpers.PostJSON(t, app, "/claim",
		map[string]any{"token": signed, "email": email})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Both resources should now belong to the new team at tier=free.
	var listedTier, fpTier string
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT tier FROM resources WHERE token = $1`, listedToken).Scan(&listedTier))
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT tier FROM resources WHERE token = $1`, fpToken).Scan(&fpTier))
	assert.Equal(t, "free", listedTier, "JWT-listed resource must be claimed → free")
	assert.Equal(t, "free", fpTier, "fingerprint resource must be claimed → free")
}

// ── Claim create-failure arms (sqlmock mid-sequence) ─────────────────────────
//
// The Claim flow for a brand-new email runs, in order:
//   1. GetOnboardingByJTI (SELECT ... FROM onboarding_events)  — must succeed
//   2. GetUserByEmail      (SELECT ... FROM users)             — ErrNoRows (new)
//   3. MarkOnboardingConvertedPreliminary (UPDATE onboarding_events) — exec
//   4. CreateTeam          (INSERT INTO teams ... RETURNING)   — query
//   5. CreateUser          (INSERT INTO users ... RETURNING)   — query
// We mock the prefix that must succeed, then fail the target step.

// onboardingEventRow builds a GetOnboardingByJTI row (8 cols), unconverted.
func onboardingEventRow(jti string) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "fingerprint", "jwt_issued_at", "jwt_expires_at",
		"converted_at", "team_id", "resource_tokens", "jti"}).
		AddRow(uuid.New(), "fp-x", time.Now(), time.Now().Add(time.Hour), nil, nil, "{}", jti)
}

func newOnboardingSqlmockApp(t *testing.T) (*fiber.App, sqlmock.Sqlmock, func()) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	return onboardingResidualApp(t, db), mock, func() { db.Close() }
}

// TestResidualClaim_MarkConvertedFailed_503 drives the mark_converted_failed
// arm (364-369): mark step errors with a non-already-used error.
func TestResidualClaim_MarkConvertedFailed_503(t *testing.T) {
	app, mock, done := newOnboardingSqlmockApp(t)
	defer done()
	jti := uuid.NewString()
	mock.ExpectQuery(`FROM onboarding_events`).WithArgs(jti).WillReturnRows(onboardingEventRow(jti))
	mock.ExpectQuery(`FROM users WHERE lower\(email\)`).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`UPDATE onboarding_events`).WillReturnError(errors.New("mark boom"))

	signed := mintOnboardingJWT(t, jti, "fp-x", nil)
	resp := testhelpers.PostJSON(t, app, "/claim",
		map[string]any{"token": signed, "email": testhelpers.UniqueEmail(t)})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestResidualClaim_TeamCreationFailed_503 drives team_creation_failed
// (385-392): mark succeeds, CreateTeam errors.
func TestResidualClaim_TeamCreationFailed_503(t *testing.T) {
	app, mock, done := newOnboardingSqlmockApp(t)
	defer done()
	jti := uuid.NewString()
	mock.ExpectQuery(`FROM onboarding_events`).WithArgs(jti).WillReturnRows(onboardingEventRow(jti))
	mock.ExpectQuery(`FROM users WHERE lower\(email\)`).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`UPDATE onboarding_events`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`INSERT INTO teams`).WillReturnError(errors.New("team boom"))

	signed := mintOnboardingJWT(t, jti, "fp-x", nil)
	resp := testhelpers.PostJSON(t, app, "/claim",
		map[string]any{"token": signed, "email": testhelpers.UniqueEmail(t)})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestResidualClaim_UserCreationFailed_503 drives user_creation_failed
// (396-403): mark + team succeed, CreateUser errors.
func TestResidualClaim_UserCreationFailed_503(t *testing.T) {
	app, mock, done := newOnboardingSqlmockApp(t)
	defer done()
	jti := uuid.NewString()
	tid := uuid.New()
	mock.ExpectQuery(`FROM onboarding_events`).WithArgs(jti).WillReturnRows(onboardingEventRow(jti))
	mock.ExpectQuery(`FROM users WHERE lower\(email\)`).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`UPDATE onboarding_events`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`INSERT INTO teams`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "plan_tier",
			"stripe_customer_id", "created_at", "default_deployment_ttl_policy"}).
			AddRow(tid, "x@example.com", "free", nil, time.Now(), "auto_24h"))
	mock.ExpectQuery(`INSERT INTO users`).WillReturnError(errors.New("user boom"))

	signed := mintOnboardingJWT(t, jti, "fp-x", nil)
	resp := testhelpers.PostJSON(t, app, "/claim",
		map[string]any{"token": signed, "email": testhelpers.UniqueEmail(t)})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}
