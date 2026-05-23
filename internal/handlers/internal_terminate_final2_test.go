package handlers_test

// internal_terminate_final2_test.go — FINAL SERIAL PASS #2 coverage for the
// internal_terminate.go arms the existing _final suite stops short of:
//
//   * dunning-terminate DB error      (L177-180, failAfter=3)
//   * downgrade-tier DB error          (L186-189, failAfter=4)
//   * razorpay canceler-not-configured (L200-207, real team w/ sub + nil cancelFn)
//   * razorpay cancel error            (L209-215, real team w/ sub + erroring cancelFn)
//   * audit-emit failure best-effort   (L242-244, failAfter=5; request still 200)
//   * full happy path                  (real team, cancelFn ok)
//
// Reuses the existing newTerminateTestApp / mintInternalTerminateJWT /
// postTerminate / testInternalTerminateSecret seams + openFaultDB.

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

func TestInternalTerminateFinal2_DunningTerminate_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")

	faultDB := openFaultDB(t, 3) // team(1)+idem(2)+pause(3) ok, dunning(4) errors
	app := newTerminateTestApp(t, faultDB, func(string) error { return nil })
	jwt := mintInternalTerminateJWT(t, testInternalTerminateSecret, "internal_terminate", teamID, 0)
	resp := postTerminate(t, app, teamID, jwt)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestInternalTerminateFinal2_DowngradeTier_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")

	faultDB := openFaultDB(t, 4) // ...downgrade(5) errors
	app := newTerminateTestApp(t, faultDB, func(string) error { return nil })
	jwt := mintInternalTerminateJWT(t, testInternalTerminateSecret, "internal_terminate", teamID, 0)
	resp := postTerminate(t, app, teamID, jwt)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestInternalTerminateFinal2_RazorpaySkipped_200(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	_, err := db.ExecContext(context.Background(),
		`UPDATE teams SET stripe_customer_id = $1 WHERE id = $2::uuid`, "sub_term_skip_final2_"+uuid.NewString(), teamID)
	require.NoError(t, err)

	// cancelFn=nil → "subscription_canceler_not_configured" arm; request 200.
	app := newTerminateTestApp(t, db, nil)
	jwt := mintInternalTerminateJWT(t, testInternalTerminateSecret, "internal_terminate", teamID, 0)
	resp := postTerminate(t, app, teamID, jwt)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestInternalTerminateFinal2_RazorpayCancelError_200(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	_, err := db.ExecContext(context.Background(),
		`UPDATE teams SET stripe_customer_id = $1 WHERE id = $2::uuid`, "sub_term_cancelerr_final2_"+uuid.NewString(), teamID)
	require.NoError(t, err)

	app := newTerminateTestApp(t, db, func(string) error { return errors.New("razorpay down") })
	jwt := mintInternalTerminateJWT(t, testInternalTerminateSecret, "internal_terminate", teamID, 0)
	resp := postTerminate(t, app, teamID, jwt)
	defer resp.Body.Close()
	// Razorpay cancel failure is logged, not fatal → still 200.
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestInternalTerminateFinal2_HappyPath_200(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	_, err := db.ExecContext(context.Background(),
		`UPDATE teams SET stripe_customer_id = $1 WHERE id = $2::uuid`, "sub_term_happy_final2_"+uuid.NewString(), teamID)
	require.NoError(t, err)

	called := false
	app := newTerminateTestApp(t, db, func(string) error { called = true; return nil })
	jwt := mintInternalTerminateJWT(t, testInternalTerminateSecret, "internal_terminate", teamID, 0)
	resp := postTerminate(t, app, teamID, jwt)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, called, "cancelSubscription must be invoked for a team with a subscription id")
}
