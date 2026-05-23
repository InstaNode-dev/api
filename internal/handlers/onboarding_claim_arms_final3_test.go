package handlers_test

// onboarding_claim_arms_final3_test.go — FINAL serial pass #3. Closes three
// reachable Claim arms the residual suite leaves open:
//   - missing_email: body with an empty/whitespace email           (onboarding.go:264)
//   - invalid_token: a valid-signature JWT whose JTI is not in
//     onboarding_events → GetOnboardingByJTI ErrOnboardingNotFound  (onboarding.go:297)
//   - already_claimed: an onboarding_event already converted →
//     MarkOnboardingConvertedPreliminary ErrOnboardingAlreadyUsed   (onboarding.go:361)

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// TestOnboardingClaimFinal3_MissingEmail_400 — POST /claim with a blank email →
// missing_email 400 (onboarding.go:264).
func TestOnboardingClaimFinal3_MissingEmail_400(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := onboardingResidualApp(t, db)
	signed := mintOnboardingJWT(t, uuid.NewString(), "fp-claim-noemail", nil)
	resp := testhelpers.PostJSON(t, app, "/claim",
		map[string]any{"token": signed, "email": "   "})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestOnboardingClaimFinal3_UnknownJTI_400 — a valid-signature JWT whose JTI is
// absent from onboarding_events → GetOnboardingByJTI ErrOnboardingNotFound →
// invalid_token 400 (onboarding.go:297).
func TestOnboardingClaimFinal3_UnknownJTI_400(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := onboardingResidualApp(t, db)
	// No onboarding_events row is inserted for this JTI.
	signed := mintOnboardingJWT(t, uuid.NewString(), "fp-claim-unknown", nil)
	resp := testhelpers.PostJSON(t, app, "/claim",
		map[string]any{"token": signed, "email": testhelpers.UniqueEmail(t)})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_token", decodeErrCode(t, resp))
}

// TestOnboardingClaimFinal3_AlreadyConverted_409 — an onboarding_event whose
// converted_at is already stamped → MarkOnboardingConvertedPreliminary returns
// ErrOnboardingAlreadyUsed → already_claimed 409 (onboarding.go:361).
func TestOnboardingClaimFinal3_AlreadyConverted_409(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := onboardingResidualApp(t, db)
	ctx := context.Background()

	fp := "fp-claim-converted-" + uuid.NewString()[:8]
	jti := uuid.NewString()
	// converted_at already set → the preliminary-mark atomic UPDATE affects 0
	// rows → ErrOnboardingAlreadyUsed.
	_, err := db.ExecContext(ctx, `
		INSERT INTO onboarding_events (jti, fingerprint, team_id, converted_at)
		VALUES ($1, $2, NULL, now())
	`, jti, fp)
	require.NoError(t, err)

	signed := mintOnboardingJWT(t, jti, fp, nil)
	resp := testhelpers.PostJSON(t, app, "/claim",
		map[string]any{"token": signed, "email": testhelpers.UniqueEmail(t)})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}
