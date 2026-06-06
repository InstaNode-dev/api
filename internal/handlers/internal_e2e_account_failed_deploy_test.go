package handlers_test

// internal_e2e_account_failed_deploy_test.go — coverage for the
// with_failed_deploy factory pre-seed (task #70,
// docs/ci/02-FAILURE-DIAGNOSIS-AND-AUTODEBUG.md §5.4 enabler).
//
// The with_failed_deploy flag lets the web wave load /app/deployments/:id and
// render the FailureAutopsyPanel against a REAL backend. Contract pinned here:
//
//   - with_failed_deploy=true  → exactly ONE failed deployment + ONE
//     failure_autopsy deployment_events row, owned by the minted cohort team,
//     carrying the factory's reason/exit_code/last_lines/hint payload; the
//     response surfaces the deployment's app_id as failed_deploy_id.
//   - with_failed_deploy omitted → ZERO deployments seeded (inert by default).
//   - non-cohort / token-unset paths unaffected (the seed runs only on a
//     successful authorized mint, which is already cohort-scoped).
//   - a seed FAILURE surfaces as a 503 seed_failed (never a half-seeded 200).
//
// Seeds are asserted from the DB directly (mirrors the with_resources seed
// test) AND the autopsy payload is compared against the handler's exported
// single-source-of-truth constants (E2EFailedDeploySeedForTest) so a future
// payload edit auto-updates the assertion rather than drifting.

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/testhelpers"
)

// TestE2EAccount_Create_WithFailedDeploy_SeedsOneFailedDeployAndAutopsy asserts
// the seed writes exactly one failed deployment + one autopsy event with the
// factory's payload, owned by the minted team, and surfaces failed_deploy_id.
func TestE2EAccount_Create_WithFailedDeploy_SeedsOneFailedDeployAndAutopsy(t *testing.T) {
	skipUnlessE2EDB(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	app := newE2ETestApp(t, db, nil, testE2EToken)

	resp := postE2ECreate(t, app, testE2EToken, `{"tier":"pro","with_failed_deploy":true}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	out := decodeE2ECreate(t, resp)

	require.NotEmpty(t, out.FailedDeployID,
		"failed_deploy_id must be surfaced so the web wave can navigate to it")

	ctx := context.Background()

	// Exactly ONE deployment, in status=failed, owned by the minted team, with
	// the factory's one-line error_message.
	wantErrMsg, wantReason, wantEvent, wantHint, wantExit, wantLines :=
		handlers.E2EFailedDeploySeedForTest()

	var (
		depCount     int
		status       string
		appID        string
		teamID       string
		errorMessage string
	)
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT count(*) FROM deployments WHERE team_id = $1`, out.TeamID).Scan(&depCount))
	require.Equal(t, 1, depCount, "exactly one deployment must be seeded")

	require.NoError(t, db.QueryRowContext(ctx, `
		SELECT app_id, status, team_id::text, error_message
		FROM deployments WHERE team_id = $1
	`, out.TeamID).Scan(&appID, &status, &teamID, &errorMessage))
	require.Equal(t, out.FailedDeployID, appID, "failed_deploy_id must echo the seeded deployment's app_id")
	require.Equal(t, "failed", status)
	require.Equal(t, out.TeamID, teamID, "seeded deployment must be owned by the minted team")
	require.Equal(t, wantErrMsg, errorMessage, "error_message must be the factory's one-liner")

	// Exactly ONE failure_autopsy deployment_events row with the factory payload.
	var (
		depID        string
		eventCount   int
		autReason    string
		autExitCode  int
		autEvent     string
		autHint      string
		autLastLines []byte
	)
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT id::text FROM deployments WHERE team_id = $1`, out.TeamID).Scan(&depID))

	require.NoError(t, db.QueryRowContext(ctx, `
		SELECT count(*) FROM deployment_events
		WHERE deployment_id = $1 AND kind = 'failure_autopsy'
	`, depID).Scan(&eventCount))
	require.Equal(t, 1, eventCount, "exactly one failure_autopsy event must be seeded")

	require.NoError(t, db.QueryRowContext(ctx, `
		SELECT reason, exit_code, event, hint, last_lines
		FROM deployment_events
		WHERE deployment_id = $1 AND kind = 'failure_autopsy'
	`, depID).Scan(&autReason, &autExitCode, &autEvent, &autHint, &autLastLines))

	require.Equal(t, wantReason, autReason)
	require.Equal(t, wantExit, autExitCode)
	require.Equal(t, wantEvent, autEvent)
	require.Equal(t, wantHint, autHint)
	// last_lines is JSONB — assert it carries the factory's (non-empty) tail.
	require.NotEmpty(t, wantLines, "factory last_lines must be non-empty by design")
	for _, line := range wantLines {
		require.Contains(t, string(autLastLines), line,
			"seeded last_lines must carry the factory's build-error tail")
	}
}

// TestE2EAccount_Create_WithoutFailedDeploy_SeedsNothing pins inert-by-default:
// omitting with_failed_deploy seeds ZERO deployments and surfaces an empty
// failed_deploy_id.
func TestE2EAccount_Create_WithoutFailedDeploy_SeedsNothing(t *testing.T) {
	skipUnlessE2EDB(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	app := newE2ETestApp(t, db, nil, testE2EToken)

	resp := postE2ECreate(t, app, testE2EToken, `{"tier":"free"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	out := decodeE2ECreate(t, resp)
	require.Empty(t, out.FailedDeployID,
		"failed_deploy_id must be empty when with_failed_deploy is omitted")

	var n int
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM deployments WHERE team_id = $1`, out.TeamID).Scan(&n))
	require.Equal(t, 0, n, "no deployment must be seeded when with_failed_deploy is omitted")
}

// TestE2EAccount_Create_WithFailedDeploy_SeedFailure_Returns503 forces the
// failed-deploy seed to fail (via the e2eSeedFailedDeploy seam) and asserts
// CreateAccount surfaces a 503 seed_failed — CI must never receive a
// half-seeded account.
func TestE2EAccount_Create_WithFailedDeploy_SeedFailure_Returns503(t *testing.T) {
	skipUnlessE2EDB(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	app := newE2ETestApp(t, db, nil, testE2EToken)

	restore := handlers.SetE2ESeedFailedDeployForTest(errors.New("deploy seed exploded"))
	defer restore()

	resp := postE2ECreate(t, app, testE2EToken, `{"tier":"pro","with_failed_deploy":true}`)
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode,
		"a failed-deploy seed failure must surface as 503, never a half-seeded 200")
	out := decodeE2ECreate(t, resp)
	require.Equal(t, "seed_failed", out.Error)
}
