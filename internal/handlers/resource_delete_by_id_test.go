package handlers_test

// resource_delete_by_id_test.go — Wave-2 A1 behavioural coverage:
//
//  1. DELETE /api/v1/resources/:id accepts BOTH address forms — the row `id`
//     (as returned by GET /api/v1/resources) and the provision `token`. The
//     id form used to 404 100% of the time, breaking the natural
//     list→delete-by-id flow.
//  2. Provision-rollback rows persist as status='failed' (a pollable terminal
//     state): visible in lists, deletable, never counted against quota.
//
// Uses the bufconn fake-provisioner fixture from
// coverage_provisioner_grpc_test.go so the deprovision RPC is observable.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// decodeInto unmarshals a response body into out (best-effort: an empty body
// leaves out zero-valued).
func decodeInto(t *testing.T, resp *http.Response, out any) {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	if len(raw) > 0 {
		require.NoError(t, json.Unmarshal(raw, out))
	}
}

// mustParseUUID parses s or fails the test.
func mustParseUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	require.NoError(t, err)
	return id
}

// doDelete issues DELETE /api/v1/resources/{ref} with the given JWT.
func doDelete(t *testing.T, fx grpcProvFixture, ref, jwt string) (*http.Response, grpcProvResp) {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/resources/"+ref, nil)
	req.Header.Set("X-Forwarded-For", "10.70.0.1")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := fx.app.Test(req, 15000)
	require.NoError(t, err)
	var parsed grpcProvResp
	decodeInto(t, resp, &parsed)
	return resp, parsed
}

// resourceStatus reads the row's current status.
func resourceStatus(t *testing.T, fx grpcProvFixture, id string) string {
	t.Helper()
	var status string
	require.NoError(t, fx.db.QueryRowContext(context.Background(),
		`SELECT status FROM resources WHERE id = $1::uuid`, id).Scan(&status))
	return status
}

// TestResourceDelete_ByRowID_Succeeds is the headline fix: the id returned by
// the list endpoint is accepted by DELETE, with the deprovision RPC still
// addressed by the resource's TOKEN (backend object names derive from it).
func TestResourceDelete_ByRowID_Succeeds(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)
	id, token := seedSourceResource(t, fx.db, teamID, "postgres", "pro", "production")

	resp, _ := doDelete(t, fx, id, jwt)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"DELETE by row id must succeed — the list endpoint keys rows by id")

	assert.Equal(t, "deleted", resourceStatus(t, fx, id))

	// The destructive deprovision must target the TOKEN, not the path id.
	require.GreaterOrEqual(t, fake.deprovisionCount(), 1, "deprovision RPC must fire")
	require.NotNil(t, fake.lastDeprovision())
	assert.Equal(t, token, fake.lastDeprovision().GetToken(),
		"deprovision must be addressed by resource.Token even when the path param is the row id")
}

// TestResourceDelete_ByToken_StillWorks pins the historical contract.
func TestResourceDelete_ByToken_StillWorks(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)
	id, token := seedSourceResource(t, fx.db, teamID, "postgres", "pro", "production")

	resp, _ := doDelete(t, fx, token, jwt)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "deleted", resourceStatus(t, fx, id))
}

// TestResourceDelete_ByRowID_OtherTeam_404 — authorization is identical for
// the id form: another team's row id resolves but must 404 (never confirm
// existence).
func TestResourceDelete_ByRowID_OtherTeam_404(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	ownerTeam := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	id, _ := seedSourceResource(t, fx.db, ownerTeam, "postgres", "pro", "production")

	attackerTeam := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, attackerTeam)

	resp, body := doDelete(t, fx, id, jwt)
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Equal(t, "not_found", body.Error)
	assert.Equal(t, "active", resourceStatus(t, fx, id), "row must be untouched")
	assert.Equal(t, 0, fake.deprovisionCount(), "no deprovision for an unauthorized delete")
}

// TestResourceDelete_UnknownUUID_404 — a UUID matching neither token nor id.
func TestResourceDelete_UnknownUUID_404(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)

	resp, body := doDelete(t, fx, "00000000-0000-4000-8000-00000000dead", jwt)
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Equal(t, "not_found", body.Error)
}

// TestProvisionRollback_PersistsFailedRow_ListedAndDeletable drives the full
// Wave-2 A1 lifecycle: a failed provision leaves a status='failed' row that
// (a) the caller can poll, (b) appears in GET /api/v1/resources, (c) does NOT
// count against the per-type quota, and (d) is deletable by row id.
func TestProvisionRollback_PersistsFailedRow_ListedAndDeletable(t *testing.T) {
	fake := &fakeProvisioner{failProvision: true}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)

	resp, body := doProvision(t, fx, "/db/new", "10.71.0.1", jwt, map[string]any{"name": "rollback-failed-row"})
	resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	require.Equal(t, "provision_failed", body.Error)

	// (a) The row persists in the terminal 'failed' state — it must NOT have
	// vanished (the pre-A1 soft-delete made a timed-out provision unpollable).
	var id, status string
	require.NoError(t, fx.db.QueryRowContext(context.Background(),
		`SELECT id::text, status FROM resources WHERE team_id = $1::uuid AND resource_type = 'postgres'
		 ORDER BY created_at DESC LIMIT 1`, teamID).Scan(&id, &status))
	require.Equal(t, models.StatusFailed, status,
		"provision rollback must persist a 'failed' row, not delete it")

	// (b) Visible in the team list (only 'deleted' rows are hidden).
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/resources", nil)
	listReq.Header.Set("Authorization", "Bearer "+jwt)
	listResp, err := fx.app.Test(listReq, 15000)
	require.NoError(t, err)
	defer listResp.Body.Close()
	require.Equal(t, http.StatusOK, listResp.StatusCode)
	var list struct {
		Items []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"items"`
	}
	decodeInto(t, listResp, &list)
	found := false
	for _, it := range list.Items {
		if it.ID == id {
			found = true
			assert.Equal(t, models.StatusFailed, it.Status)
		}
	}
	assert.True(t, found, "failed row must appear in GET /api/v1/resources")

	// (c) Quota-exempt: failed rows never count toward the per-type cap.
	n, err := models.CountActiveResourcesByTeamAndType(context.Background(), fx.db,
		mustParseUUID(t, teamID), "postgres")
	require.NoError(t, err)
	assert.Equal(t, 0, n, "a failed row must not count against the plan quota")

	// (d) Deletable by row id — terminal cleanup stays in the user's hands.
	delResp, _ := doDelete(t, fx, id, jwt)
	defer delResp.Body.Close()
	require.Equal(t, http.StatusOK, delResp.StatusCode, "failed rows must be deletable")
	assert.Equal(t, "deleted", resourceStatus(t, fx, id))
}

// TestProvisionRollback_Cache_Authenticated_FailedRow covers the
// authenticated /cache/new rollback arm (cache.go) — the one provision-fail
// arm the pre-A1 suites didn't reach — and asserts the new terminal state.
func TestProvisionRollback_Cache_Authenticated_FailedRow(t *testing.T) {
	fake := &fakeProvisioner{failProvision: true}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)

	resp, body := doProvision(t, fx, "/cache/new", "10.72.0.1", jwt, map[string]any{"name": "cache-auth-fail"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	require.Equal(t, "provision_failed", body.Error)

	var status string
	require.NoError(t, fx.db.QueryRowContext(context.Background(),
		`SELECT status FROM resources WHERE team_id = $1::uuid AND resource_type = 'redis'
		 ORDER BY created_at DESC LIMIT 1`, teamID).Scan(&status))
	assert.Equal(t, models.StatusFailed, status)
}

// TestResourceDelete_Storage_ByRowID_AuditUsesToken drives the storage
// deprovision arm with a SUCCESSFUL revoke (hermetic minio-admin fake) under
// the id-addressed form, proving the IAM-removal audit row is keyed by the
// resource TOKEN (key_<token[:8]>), not the path id.
func TestResourceDelete_Storage_ByRowID_AuditUsesToken(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, rClean := testhelpers.SetupTestRedis(t)
	defer rClean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	userID := uuid.NewString()

	h := handlers.NewResourceHandler(db, rdb, resourceResidualConfig(), plans.Default(), nil, prefixScopedProvider(t))
	app := resourceResidualApp(t, db, rdb, h, teamID, userID)

	token := seedTeamResource(t, db, teamID, "storage", "active")
	var rowID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT id::text FROM resources WHERE token = $1`, token).Scan(&rowID))

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/resources/"+rowID, nil)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "storage delete by row id must succeed")

	// The IAM audit emit is async (safego.Go) — poll briefly.
	wantFragment := "key_" + token[:8]
	deadline := time.Now().Add(3 * time.Second)
	for {
		var summary string
		err := db.QueryRowContext(context.Background(),
			`SELECT summary FROM audit_log WHERE team_id = $1::uuid AND kind = $2
			 ORDER BY created_at DESC LIMIT 1`, teamID, models.AuditKindStorageIAMUserDeleted).Scan(&summary)
		if err == nil {
			assert.Contains(t, summary, wantFragment,
				"IAM audit summary must reference the TOKEN-derived key, not the path id")
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("storage IAM audit row never appeared: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
