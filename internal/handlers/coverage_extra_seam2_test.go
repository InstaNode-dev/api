package handlers

// coverage_extra_seam2_test.go — white-box unit tests for pure / signature-only
// helpers whose error arms the HTTP-level suites don't reach. NO new production
// seam is introduced here: these call the unexported functions directly and
// craft inputs (HS256 tokens, plan maps) to drive the otherwise-uncovered
// branches.
//
// Covered:
//   - verifyInternalTerminateJWT      — empty-token / bad-purpose / iat-future arms
//   - verifyInternalResendMagicLinkJWT — empty-token / bad-purpose / link-mismatch / missing-iat arms
//   - verifyInternalBackupRefundJWT   — empty-token / bad-purpose / missing-iat arms
//   - annualDiscountPercent           — twelveX<=0 and saved<=0 guard arms

import (
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"

	"instant.dev/internal/plans"
)

const seam2VerifySecret = "seam2-internal-jwt-secret-32-bytes-minimum-pad"

// ctxWithBearer builds a throwaway *fiber.Ctx carrying the supplied
// Authorization header value (already including the "Bearer " prefix, or empty
// for none). Returns the ctx + a release func.
func ctxWithBearer(t *testing.T, authValue string) (*fiber.Ctx, func()) {
	t.Helper()
	app := fiber.New()
	fctx := &fasthttp.RequestCtx{}
	if authValue != "" {
		fctx.Request.Header.Set(fiber.HeaderAuthorization, authValue)
	}
	c := app.AcquireCtx(fctx)
	return c, func() { app.ReleaseCtx(c) }
}

// signHS256 mints an HS256 token over claims with the seam2 secret.
func signHS256(t *testing.T, claims jwt.Claims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := tok.SignedString([]byte(seam2VerifySecret))
	require.NoError(t, err)
	return s
}

// ── verifyInternalTerminateJWT ────────────────────────────────────────────────

func TestSeam2_VerifyInternalTerminateJWT_Arms(t *testing.T) {
	teamID := uuid.New()

	// bad signature → parse_failed arm (the closure rejects, ParseWithClaims
	// returns err).
	badSig := jwt.NewWithClaims(jwt.SigningMethodHS256, &internalTerminateClaims{
		Purpose:          internalTerminatePurpose,
		TeamID:           teamID.String(),
		RegisteredClaims: jwt.RegisteredClaims{IssuedAt: jwt.NewNumericDate(time.Now())},
	})
	wrongSecret, err := badSig.SignedString([]byte("a-different-secret-entirely-padded-32b"))
	require.NoError(t, err)
	c, rel := ctxWithBearer(t, "Bearer "+wrongSecret)
	err = verifyInternalTerminateJWT(c, seam2VerifySecret, teamID)
	require.Error(t, err, "wrong-secret signature must fail parse")
	rel()

	// valid signature but wrong purpose → bad-purpose arm.
	badPurpose := signHS256(t, &internalTerminateClaims{
		Purpose:          "not_terminate",
		TeamID:           teamID.String(),
		RegisteredClaims: jwt.RegisteredClaims{IssuedAt: jwt.NewNumericDate(time.Now())},
	})
	c, rel = ctxWithBearer(t, "Bearer "+badPurpose)
	err = verifyInternalTerminateJWT(c, seam2VerifySecret, teamID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "purpose")
	rel()
}

// ── verifyInternalResendMagicLinkJWT ──────────────────────────────────────────

func TestSeam2_VerifyInternalResendMagicLinkJWT_Arms(t *testing.T) {
	linkID := uuid.New()

	// wrong purpose → bad-purpose arm.
	badPurpose := signHS256(t, &internalResendMagicLinkClaims{
		Purpose:          "not_resend",
		LinkID:           linkID.String(),
		RegisteredClaims: jwt.RegisteredClaims{IssuedAt: jwt.NewNumericDate(time.Now())},
	})
	c, rel := ctxWithBearer(t, "Bearer "+badPurpose)
	err := verifyInternalResendMagicLinkJWT(c, seam2VerifySecret, linkID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "purpose")
	rel()

	// right purpose, no iat → missing-iat arm.
	noIat := signHS256(t, &internalResendMagicLinkClaims{
		Purpose: internalResendMagicLinkPurpose,
		LinkID:  linkID.String(),
		// no IssuedAt
	})
	c, rel = ctxWithBearer(t, "Bearer "+noIat)
	err = verifyInternalResendMagicLinkJWT(c, seam2VerifySecret, linkID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "iat")
	rel()
}

// ── verifyInternalBackupRefundJWT ─────────────────────────────────────────────

func TestSeam2_VerifyInternalBackupRefundJWT_Arms(t *testing.T) {
	teamID := uuid.New()

	// wrong purpose → bad-purpose arm (line 210-213).
	badPurpose := signHS256(t, &internalBackupRefundClaims{
		Purpose:          "not_backup_refund",
		TeamID:           teamID.String(),
		RegisteredClaims: jwt.RegisteredClaims{IssuedAt: jwt.NewNumericDate(time.Now())},
	})
	c, rel := ctxWithBearer(t, "Bearer "+badPurpose)
	err := verifyInternalBackupRefundJWT(c, seam2VerifySecret, teamID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "purpose")
	rel()

	// right purpose, missing iat → missing-iat arm (line 207).
	noIat := signHS256(t, &internalBackupRefundClaims{
		Purpose: internalBackupRefundPurpose,
		TeamID:  teamID.String(),
		// no IssuedAt
	})
	c, rel = ctxWithBearer(t, "Bearer "+noIat)
	err = verifyInternalBackupRefundJWT(c, seam2VerifySecret, teamID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "iat")
	rel()
}

// ── annualDiscountPercent guard arms ──────────────────────────────────────────

func TestSeam2_AnnualDiscountPercent_GuardArms(t *testing.T) {
	// twelveX <= 0: a negative monthly price passes the `== 0` guard but makes
	// twelveX = monthly*12 negative → the defensive `twelveX <= 0` arm (a guard
	// against malformed plan data) returns 0.
	negMonthly := map[string]*plans.Plan{
		"n":        {PriceMonthly: -100},
		"n_yearly": {PriceMonthly: 1000},
	}
	assert.Equal(t, 0, annualDiscountPercent(negMonthly, "n"),
		"negative monthly price (twelveX<=0) yields no discount")

	// saved <= 0: the yearly price is HIGHER than 12× monthly (no discount → 0).
	noSaving := map[string]*plans.Plan{
		"x":        {PriceMonthly: 100},
		"x_yearly": {PriceMonthly: 1300}, // > 12*100 → saved<=0 → return 0
	}
	assert.Equal(t, 0, annualDiscountPercent(noSaving, "x"),
		"yearly priced above 12x monthly yields no discount")

	// saved exactly 0 (yearly == 12x monthly) → saved<=0 arm.
	exactly := map[string]*plans.Plan{
		"y":        {PriceMonthly: 50},
		"y_yearly": {PriceMonthly: 600}, // == 12*50 → saved==0 → return 0
	}
	assert.Equal(t, 0, annualDiscountPercent(exactly, "y"))

	// happy path for contrast (saved>0 → positive percent) keeps the success
	// arm exercised here too.
	discounted := map[string]*plans.Plan{
		"z":        {PriceMonthly: 100},
		"z_yearly": {PriceMonthly: 1000}, // 12*100=1200, saved=200 → ~17%
	}
	assert.Positive(t, annualDiscountPercent(discounted, "z"))
}
