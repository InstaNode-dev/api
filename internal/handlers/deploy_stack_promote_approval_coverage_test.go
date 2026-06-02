package handlers_test

// deploy_stack_promote_approval_coverage_test.go — coverage for
// consumeApprovedPromote (the manual-trigger approval escape on
// POST /stacks/:slug/promote) and the requireTeam / optionalStackTeam
// invalid-team branches.
//
// Scope: deploy.go + stack.go ONLY. Skips cleanly when TEST_DATABASE_URL
// is unset.

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// TestStackPromote_ApprovalID_Success drives consumeApprovedPromote's happy
// path: an approved, non-executed row matching team+from+to+kind lets the
// promote proceed (and the row flips to executed).
func TestStackPromote_ApprovalID_Success(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "appsucc@example.com")

	slug, _ := seedPromoteSourceStack(t, db, teamIDStr, "staging", "approve-success")
	app := newStackTestApp(t, db)

	id := mustSeedApprovedPromote(t, db, teamID, "staging", "production")
	resp := postPromote(t, app, jwt, slug, map[string]any{
		"from":        "staging",
		"to":          "production",
		"approval_id": id,
	})
	defer resp.Body.Close()
	// 200/202 = consumed + executed. The point is we got PAST the approval
	// gate (not a 4xx approval rejection).
	assert.NotContains(t, []int{http.StatusBadRequest, http.StatusConflict, http.StatusGone, http.StatusNotFound},
		resp.StatusCode, "approved row must let the promote proceed; got %d", resp.StatusCode)
}

func TestStackPromote_ApprovalID_InvalidUUID(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "appbad@example.com")
	slug, _ := seedPromoteSourceStack(t, db, teamIDStr, "staging", "approve-baduuid")
	app := newStackTestApp(t, db)

	resp := postPromote(t, app, jwt, slug, map[string]any{
		"from": "staging", "to": "production", "approval_id": "not-a-uuid",
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_approval_id", decodeErrCode(t, resp))
}

func TestStackPromote_ApprovalID_NotFound(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "appnf@example.com")
	slug, _ := seedPromoteSourceStack(t, db, teamIDStr, "staging", "approve-notfound")
	app := newStackTestApp(t, db)

	resp := postPromote(t, app, jwt, slug, map[string]any{
		"from": "staging", "to": "production", "approval_id": uuid.NewString(),
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Equal(t, "approval_not_found", decodeErrCode(t, resp))
}

func TestStackPromote_ApprovalID_NotApproved(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "apppend@example.com")
	slug, _ := seedPromoteSourceStack(t, db, teamIDStr, "staging", "approve-pending")
	app := newStackTestApp(t, db)

	// A PENDING (not approved) row.
	id := mustSeedPendingPromote(t, db, teamID, "staging", "production")
	resp := postPromote(t, app, jwt, slug, map[string]any{
		"from": "staging", "to": "production", "approval_id": id,
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	assert.Equal(t, "approval_not_approved", decodeErrCode(t, resp))
}

func TestStackPromote_ApprovalID_Mismatch(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "appmis@example.com")
	slug, _ := seedPromoteSourceStack(t, db, teamIDStr, "staging", "approve-mismatch")
	app := newStackTestApp(t, db)

	// Approved row, but for a DIFFERENT to-env (qa, not production).
	id := mustSeedApprovedPromote(t, db, teamID, "staging", "qa")
	resp := postPromote(t, app, jwt, slug, map[string]any{
		"from": "staging", "to": "production", "approval_id": id,
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "approval_mismatch", decodeErrCode(t, resp))
}

func TestStackPromote_ApprovalID_CrossTeam(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	ownerStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	otherStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	otherID := uuid.MustParse(otherStr)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), ownerStr, "appxt@example.com")
	slug, _ := seedPromoteSourceStack(t, db, ownerStr, "staging", "approve-crossteam")
	app := newStackTestApp(t, db)

	// Approved row belongs to OTHER team.
	id := mustSeedApprovedPromote(t, db, otherID, "staging", "production")
	resp := postPromote(t, app, jwt, slug, map[string]any{
		"from": "staging", "to": "production", "approval_id": id,
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Equal(t, "approval_not_found", decodeErrCode(t, resp))
}

func TestStackPromote_ApprovalID_Expired(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "appexp@example.com")
	slug, _ := seedPromoteSourceStack(t, db, teamIDStr, "staging", "approve-expired")
	app := newStackTestApp(t, db)

	id := mustSeedApprovedPromote(t, db, teamID, "staging", "production")
	// Force the row's expires_at into the past.
	_, err := db.ExecContext(context.Background(),
		`UPDATE promote_approvals SET expires_at = now() - interval '1 hour' WHERE id = $1`, id)
	require.NoError(t, err)

	resp := postPromote(t, app, jwt, slug, map[string]any{
		"from": "staging", "to": "production", "approval_id": id,
	})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusGone, resp.StatusCode)
	assert.Equal(t, "approval_expired", decodeErrCode(t, resp))
}

// TestStackPromote_DevEnv_ExecutesImmediately drives the full promote
// execution body (create child stack + copy image_refs + trigger deploy
// goroutine) in ONE call — a dev-env target bypasses the email approval gate.
// This is the largest uncovered block in stack.Promote.
func TestStackPromote_DevEnv_ExecutesImmediately(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "devpromote@example.com")
	// Source in "staging" with an image_ref so the post-017 promote path runs.
	slug, _ := seedPromoteSourceStack(t, db, teamIDStr, "staging", "dev-promote-src")
	app := newStackTestApp(t, db)

	resp := postPromote(t, app, jwt, slug, map[string]any{
		"from": "staging",
		"to":   "development", // dev-env target -> no approval gate, executes now
	})
	defer resp.Body.Close()
	// 200 (updated existing) or 202 (created child + building). Either way the
	// execution body ran.
	assert.Contains(t, []int{http.StatusOK, http.StatusAccepted}, resp.StatusCode,
		"dev-env promote must execute the body; got %d", resp.StatusCode)
}

// TestStackPromote_RepromoteDevEnv_UpdatesExisting drives the
// "target already exists" branch of the execution body — a second dev-env
// promote updates the existing child stack rather than creating a new row.
func TestStackPromote_RepromoteDevEnv_UpdatesExisting(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "repromote@example.com")
	slug, _ := seedPromoteSourceStack(t, db, teamIDStr, "staging", "repromote-src")
	app := newStackTestApp(t, db)

	body := map[string]any{"from": "staging", "to": "development"}
	resp1 := postPromote(t, app, jwt, slug, body)
	resp1.Body.Close()
	require.Contains(t, []int{http.StatusOK, http.StatusAccepted}, resp1.StatusCode)

	// Second promote -> updated_existing branch.
	resp2 := postPromote(t, app, jwt, slug, body)
	defer resp2.Body.Close()
	assert.Contains(t, []int{http.StatusOK, http.StatusAccepted}, resp2.StatusCode)
}

// TestStackPromote_ApprovalID_AlreadyExecuted covers the
// approval_already_executed branch: a second consume of the same approval row
// fails the MarkPromoteApprovalExecuted CAS.
func TestStackPromote_ApprovalID_AlreadyExecuted(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "alreadyexec@example.com")
	slug, _ := seedPromoteSourceStack(t, db, teamIDStr, "staging", "already-exec")
	app := newStackTestApp(t, db)

	id := mustSeedApprovedPromote(t, db, teamID, "staging", "production")
	body := map[string]any{"from": "staging", "to": "production", "approval_id": id}

	resp1 := postPromote(t, app, jwt, slug, body)
	resp1.Body.Close() // first consume executes the row

	// Second consume of the same (now executed) approval -> conflict. The row
	// is now status='executed', so the status-gate fires before the CAS and
	// returns approval_not_approved (the already_executed CAS branch is only
	// reachable under a concurrent double-consume race).
	resp2 := postPromote(t, app, jwt, slug, body)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusConflict, resp2.StatusCode)
	assert.Equal(t, "approval_not_approved", decodeErrCode(t, resp2))
}

// ── requireTeam / requireStackTeam / optionalStackTeam — invalid + missing team ──

func TestDeployList_InvalidTeamID_Returns400(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	// Valid signature, but the team claim is not a UUID -> requireTeam's
	// parseTeamID branch (400 invalid_team).
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), "not-a-uuid", "badteam@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	req := httpGet(t, "/api/v1/deployments", jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_team", decodeErrCode(t, resp))
}

func TestDeployList_TeamNotFound_Returns503(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	// Valid UUID but no such team row -> GetTeamByID errors -> 503.
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), uuid.NewString(), "noteam@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	req := httpGet(t, "/api/v1/deployments", jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestStackList_InvalidTeamID_Returns400(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), "not-a-uuid", "stkbadteam@example.com")
	app := newStackTestApp(t, db)
	req := httpGet(t, "/api/v1/stacks", jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_team", decodeErrCode(t, resp))
}

func TestStackGet_OptionalAuth_InvalidTeamID_Returns400(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	// optionalStackTeam invalid-team branch (a present-but-malformed token).
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), "not-a-uuid", "optbad@example.com")
	app := newStackTestApp(t, db)
	req := httpGet(t, "/stacks/whatever", jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_team", decodeErrCode(t, resp))
}

// ── deploy ConfirmDelete / CancelDelete — success paths ──────────────────────

func TestDeployConfirmDelete_ValidToken_Succeeds(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	email := "confdel-" + uuid.NewString()[:8] + "@example.com"
	userID, err := addOwnerUser(db, teamID, email)
	require.NoError(t, err)
	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{"FOO": "bar"})
	require.NoError(t, models.UpdateDeploymentProviderID(context.Background(), db, d.ID, "noop-prov", "http://x"))

	// Seed a pending deletion + plaintext token.
	_, plaintext, err := models.CreatePendingDeletion(context.Background(), db,
		d.ID, models.PendingDeletionResourceDeploy, teamID, userID, email, time.Hour)
	require.NoError(t, err)

	jwt := testhelpers.MustSignSessionJWT(t, userID.String(), teamIDStr, email)
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/deployments/"+d.AppID+"/confirm-deletion?token="+plaintext, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestDeployCancelDelete_Succeeds(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	email := "cancdel-" + uuid.NewString()[:8] + "@example.com"
	userID, err := addOwnerUser(db, teamID, email)
	require.NoError(t, err)
	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{"FOO": "bar"})
	_, _, err = models.CreatePendingDeletion(context.Background(), db,
		d.ID, models.PendingDeletionResourceDeploy, teamID, userID, email, time.Hour)
	require.NoError(t, err)

	jwt := testhelpers.MustSignSessionJWT(t, userID.String(), teamIDStr, email)
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/deployments/"+d.AppID+"/confirm-deletion", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestDeployConfirmDelete_MissingToken_Returns400(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "notok@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	// No ?token= -> resolveEmailConfirmedDeletion missing_token branch.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/deployments/anything/confirm-deletion", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestDeployDelete_PaidTier_QueuesPendingConfirmation(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	email := "paiddel-" + uuid.NewString()[:8] + "@example.com"
	userID, err := addOwnerUser(db, teamID, email)
	require.NoError(t, err)
	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{"FOO": "bar"})
	require.NoError(t, models.UpdateDeploymentProviderID(context.Background(), db, d.ID, "noop-prov", "http://x"))

	jwt := testhelpers.MustSignSessionJWT(t, userID.String(), teamIDStr, email)
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	// Paid tier + email client wired -> two-step queue (202) OR immediate (200).
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/deployments/"+d.AppID, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Contains(t, []int{http.StatusAccepted, http.StatusOK}, resp.StatusCode)
}

func TestDeployCancelDelete_CrossTeam_Returns404(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	ownerStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	ownerID := uuid.MustParse(ownerStr)
	d := seedInternalDeploy(t, db, ownerID, "healthy", map[string]string{"FOO": "bar"})

	otherStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	otherJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), otherStr, "xtcancel@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/deployments/"+d.AppID+"/confirm-deletion", nil)
	req.Header.Set("Authorization", "Bearer "+otherJWT)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	// bug bash #22: cross-tenant access returns 404 (not 403) so a non-owner
	// can't confirm the deployment exists.
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestDeployCancelDelete_UnknownID_Returns404(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "cancel404@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/deployments/nope/confirm-deletion", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestStackConfirmDelete_ValidToken_Succeeds(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	email := "stkconf-" + uuid.NewString()[:8] + "@example.com"
	userID, err := addOwnerUser(db, teamID, email)
	require.NoError(t, err)
	stackID := mustSeedSimpleStack(t, db, teamID, "healthy")
	_, plaintext, err := models.CreatePendingDeletion(context.Background(), db,
		stackID, models.PendingDeletionResourceStack, teamID, userID, email, time.Hour)
	require.NoError(t, err)

	jwt := testhelpers.MustSignSessionJWT(t, userID.String(), teamIDStr, email)
	app, _ := newCoverageStackApp(t, db)
	slug := slugForStack(t, db, stackID)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/stacks/"+slug+"/confirm-deletion?token="+plaintext, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestStackCancelDelete_Succeeds(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	email := "stkcanc-" + uuid.NewString()[:8] + "@example.com"
	userID, err := addOwnerUser(db, teamID, email)
	require.NoError(t, err)
	stackID := mustSeedSimpleStack(t, db, teamID, "healthy")
	_, _, err = models.CreatePendingDeletion(context.Background(), db,
		stackID, models.PendingDeletionResourceStack, teamID, userID, email, time.Hour)
	require.NoError(t, err)

	jwt := testhelpers.MustSignSessionJWT(t, userID.String(), teamIDStr, email)
	app, _ := newCoverageStackApp(t, db)
	slug := slugForStack(t, db, stackID)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/stacks/"+slug+"/confirm-deletion", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func mustSeedSimpleStack(t *testing.T, db *sql.DB, teamID uuid.UUID, status string) uuid.UUID {
	t.Helper()
	slug := "stk-del-" + uuid.NewString()[:10]
	var id uuid.UUID
	require.NoError(t, db.QueryRow(`
		INSERT INTO stacks (team_id, slug, namespace, status, tier, env)
		VALUES ($1, $2, $3, $4, 'pro', 'production') RETURNING id
	`, teamID, slug, "instant-stack-"+slug, status).Scan(&id))
	return id
}

func slugForStack(t *testing.T, db *sql.DB, id uuid.UUID) string {
	t.Helper()
	var slug string
	require.NoError(t, db.QueryRow(`SELECT slug FROM stacks WHERE id = $1`, id).Scan(&slug))
	return slug
}

// ── stack Family — URL enrichment + cache header ─────────────────────────────

func TestStackFamily_EnrichesExposedURL(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "fam@example.com")

	// Seed a stack with an exposed service that HAS an app_url so the
	// exposed-URL break + cache-control branch both execute.
	slug := "stk-fam-" + uuid.NewString()[:8]
	var stackID uuid.UUID
	require.NoError(t, db.QueryRow(`
		INSERT INTO stacks (team_id, slug, namespace, status, tier, env)
		VALUES ($1, $2, $3, 'healthy', 'pro', 'production') RETURNING id
	`, teamID, slug, "instant-stack-"+slug).Scan(&stackID))
	_, err := db.Exec(`
		INSERT INTO stack_services (stack_id, name, port, status, expose, app_url)
		VALUES ($1, 'web', 8080, 'healthy', true, 'https://web.example.com')
	`, stackID)
	require.NoError(t, err)

	app := newStackTestApp(t, db)
	req := httpGet(t, "/api/v1/stacks/"+slug+"/family", jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Cache-Control"), "private")
}

// ── stack UpdateEnv — 64KiB cap ──────────────────────────────────────────────

func TestStackUpdateEnv_TooLarge_Returns413(t *testing.T) {
	requireTestDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "toobig@example.com")
	slug := "stk-big-" + uuid.NewString()[:8]
	var stackID uuid.UUID
	require.NoError(t, db.QueryRow(`
		INSERT INTO stacks (team_id, slug, namespace, status, tier, env)
		VALUES ($1, $2, $3, 'healthy', 'pro', 'production') RETURNING id
	`, teamID, slug, "instant-stack-"+slug).Scan(&stackID))

	// A single value > 64KiB blows the cap inside UpdateStackEnvVars.
	big := make([]byte, 70*1024)
	for i := range big {
		big[i] = 'A'
	}
	app := newStackTestApp(t, db)
	body := `{"env":{"HUGE":"` + string(big) + `"}}`
	req := httptest.NewRequest(http.MethodPatch, "/stacks/"+slug+"/env",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
	assert.Equal(t, "env_too_large", decodeErrCode(t, resp))
}

// ── seed helpers ──────────────────────────────────────────────────────────────

func httpGet(t *testing.T, path, jwt string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.55.0.1")
	return req
}

// mustSeedPendingPromote inserts a pending promote_approvals row and returns
// its id string.
func mustSeedPendingPromote(t *testing.T, db *sql.DB, teamID uuid.UUID, from, to string) string {
	t.Helper()
	tok, err := models.GeneratePromoteApprovalToken()
	require.NoError(t, err)
	row, err := models.CreatePromoteApproval(context.Background(), db, models.CreatePromoteApprovalParams{
		Token:            tok,
		TeamID:           teamID,
		RequestedByEmail: "approver@example.com",
		PromoteKind:      models.PromoteApprovalKindStack,
		PromotePayload:   []byte(`{}`),
		FromEnv:          from,
		ToEnv:            to,
	})
	require.NoError(t, err)
	return row.ID.String()
}

// mustSeedApprovedPromote inserts a promote_approvals row and flips it to
// 'approved', returning its id string.
func mustSeedApprovedPromote(t *testing.T, db *sql.DB, teamID uuid.UUID, from, to string) string {
	t.Helper()
	id := mustSeedPendingPromote(t, db, teamID, from, to)
	ok, err := models.ApprovePromoteApproval(context.Background(), db, uuid.MustParse(id))
	require.NoError(t, err)
	require.True(t, ok, "seed approval must flip pending -> approved")
	return id
}
