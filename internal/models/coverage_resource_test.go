package models

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// resourceMockCols mirrors resourceColumns (26 columns) in order.
func resourceMockCols() []string {
	return []string{
		"id", "team_id", "token", "resource_type", "name", "connection_url", "key_prefix", "tier",
		"env", "fingerprint", "cloud_vendor", "country_code", "status", "migration_status",
		"expires_at", "storage_bytes", "provider_resource_id", "created_request_id", "parent_resource_id", "paused_at",
		"last_seen_at", "degraded", "degraded_reason", "last_reconciled_at", "auth_mode", "created_at",
	}
}

// resourceMockRow returns a row matching resourceColumns. parent non-nil to
// exercise the ParentResourceID branch in scanResource.
func resourceMockRow() *sqlmock.Rows {
	parent := uuid.New()
	return sqlmock.NewRows(resourceMockCols()).AddRow(
		uuid.New(), nil, uuid.New(), "postgres", nil, nil, nil, "hobby",
		"production", nil, nil, nil, "active", nil,
		nil, int64(0), nil, nil, parent, nil,
		nil, false, nil, nil, "isolated", time.Now(),
	)
}

func TestResourceErrorString(t *testing.T) {
	require.Contains(t, (&ErrResourceNotFound{Token: "tok"}).Error(), "tok")
}

func TestCreateResource_Branches(t *testing.T) {
	ctx := context.Background()
	team := uuid.New()
	exp := time.Now().Add(time.Hour)
	parent := uuid.New()

	db, mock := newMock(t)
	mock.ExpectQuery(`INSERT INTO resources`).WillReturnRows(resourceMockRow())
	got, err := CreateResource(ctx, db, CreateResourceParams{
		TeamID: &team, ResourceType: "postgres", Tier: "hobby", Env: "production", ExpiresAt: &exp, ParentResourceID: &parent,
	})
	require.NoError(t, err)
	require.Equal(t, "postgres", got.ResourceType)

	// empty env default + nil optionals + error
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`INSERT INTO resources`).WillReturnError(errors.New("boom"))
	_, err = CreateResource(ctx, db2, CreateResourceParams{ResourceType: "redis", Tier: "anonymous"})
	require.ErrorContains(t, err, "boom")
}

func TestMarkResourceActive_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE resources SET status = 'active'`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, MarkResourceActive(ctx, db, uuid.New()))

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE resources SET status = 'active'`).WillReturnResult(sqlmock.NewResult(0, 0))
	require.ErrorIs(t, MarkResourceActive(ctx, db2, uuid.New()), ErrResourceNotPending)

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE resources SET status = 'active'`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, MarkResourceActive(ctx, db3, uuid.New()), "boom")
}

func TestCountActiveResourcesByTeamAndType_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`COUNT\(\*\) FROM resources`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	n, err := CountActiveResourcesByTeamAndType(ctx, db, uuid.New(), "postgres")
	require.NoError(t, err)
	require.Equal(t, 2, n)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`COUNT\(\*\) FROM resources`).WillReturnError(errors.New("boom"))
	_, err = CountActiveResourcesByTeamAndType(ctx, db2, uuid.New(), "postgres")
	require.ErrorContains(t, err, "boom")
}

func TestGetResourceByToken_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`FROM resources WHERE token`).WillReturnRows(resourceMockRow())
	_, err := GetResourceByToken(ctx, db, uuid.New())
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM resources WHERE token`).WillReturnError(errNoRows())
	_, err = GetResourceByToken(ctx, db2, uuid.New())
	var nf *ErrResourceNotFound
	require.ErrorAs(t, err, &nf)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM resources WHERE token`).WillReturnError(errors.New("boom"))
	_, err = GetResourceByToken(ctx, db3, uuid.New())
	require.ErrorContains(t, err, "boom")
}

func TestGetActiveResourceByFingerprintType_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`AND resource_type = \$2`).WillReturnRows(resourceMockRow())
	_, err := GetActiveResourceByFingerprintType(ctx, db, "fp", "postgres", "") // empty env default
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`AND resource_type = \$2`).WillReturnError(errNoRows())
	_, err = GetActiveResourceByFingerprintType(ctx, db2, "fp", "postgres", "prod")
	var nf *ErrResourceNotFound
	require.ErrorAs(t, err, &nf)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`AND resource_type = \$2`).WillReturnError(errors.New("boom"))
	_, err = GetActiveResourceByFingerprintType(ctx, db3, "fp", "postgres", "prod")
	require.ErrorContains(t, err, "boom")
}

func TestGetActiveResourceByFingerprint_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`AND team_id IS NULL\s+AND env = \$2`).WillReturnRows(resourceMockRow())
	_, err := GetActiveResourceByFingerprint(ctx, db, "fp", "")
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`AND env = \$2`).WillReturnError(errNoRows())
	_, err = GetActiveResourceByFingerprint(ctx, db2, "fp", "prod")
	var nf *ErrResourceNotFound
	require.ErrorAs(t, err, &nf)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`AND env = \$2`).WillReturnError(errors.New("boom"))
	_, err = GetActiveResourceByFingerprint(ctx, db3, "fp", "prod")
	require.ErrorContains(t, err, "boom")
}

func TestGetAllActiveResourcesByFingerprint_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`FROM resources`).WillReturnRows(resourceMockRow())
	out, err := GetAllActiveResourcesByFingerprint(ctx, db, "fp")
	require.NoError(t, err)
	require.Len(t, out, 1)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM resources`).WillReturnError(errors.New("qerr"))
	_, err = GetAllActiveResourcesByFingerprint(ctx, db2, "fp")
	require.ErrorContains(t, err, "qerr")

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM resources`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = GetAllActiveResourcesByFingerprint(ctx, db3, "fp")
	require.Error(t, err)
}

// TestGetAllActiveResourcesByFingerprint_FiltersExpiredRows pins API-4 /
// CLI-MCP-15R2 (QA 2026-05-29): the recycle gate suppressed itself on
// queue/storage flows because expired-but-status='active' rows (TTL reaper
// hadn't run yet) leaked through this query. The fix adds an
// `expires_at IS NULL OR expires_at > NOW()` clause so the query result is
// reaper-independent. This test asserts the SQL fragment is present so the
// guard cannot regress without failing the test.
func TestGetAllActiveResourcesByFingerprint_FiltersExpiredRows(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	// Use a strict regex that asserts the expires_at filter is part of the
	// WHERE clause. If a future refactor removes it, this test reds.
	mock.ExpectQuery(`WHERE fingerprint = \$1\s+AND team_id IS NULL\s+AND status = 'active'\s+AND \(expires_at IS NULL OR expires_at > NOW\(\)\)`).
		WillReturnRows(resourceMockRow())
	out, err := GetAllActiveResourcesByFingerprint(ctx, db, "fp")
	require.NoError(t, err)
	require.Len(t, out, 1)
}

func TestGetWebhookHMACSecret_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`SELECT hmac_secret FROM resources`).WillReturnRows(sqlmock.NewRows([]string{"hmac_secret"}).AddRow("sekret"))
	s, err := GetWebhookHMACSecret(ctx, db, uuid.New())
	require.NoError(t, err)
	require.Equal(t, "sekret", s)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`SELECT hmac_secret FROM resources`).WillReturnError(errNoRows())
	s, err = GetWebhookHMACSecret(ctx, db2, uuid.New())
	require.NoError(t, err)
	require.Empty(t, s)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`SELECT hmac_secret FROM resources`).WillReturnError(errors.New("boom"))
	_, err = GetWebhookHMACSecret(ctx, db3, uuid.New())
	require.ErrorContains(t, err, "boom")

	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`SELECT hmac_secret FROM resources`).WillReturnRows(sqlmock.NewRows([]string{"hmac_secret"}).AddRow(nil))
	s, err = GetWebhookHMACSecret(ctx, db4, uuid.New())
	require.NoError(t, err)
	require.Empty(t, s)
}

func TestSetWebhookHMACSecret_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE resources SET hmac_secret`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, SetWebhookHMACSecret(ctx, db, uuid.New(), "x"))

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE resources SET hmac_secret`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, SetWebhookHMACSecret(ctx, db2, uuid.New(), "")) // clear path

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE resources SET hmac_secret`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, SetWebhookHMACSecret(ctx, db3, uuid.New(), "x"), "boom")
}

func TestSoftDeleteResource_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE resources SET status = 'deleted'`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, SoftDeleteResource(ctx, db, uuid.New()))

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE resources SET status = 'deleted'`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, SoftDeleteResource(ctx, db2, uuid.New()), "boom")
}

func TestPauseResource_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`SET status = 'paused'`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, PauseResource(ctx, db, uuid.New()))

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`SET status = 'paused'`).WillReturnResult(sqlmock.NewResult(0, 0))
	require.ErrorIs(t, PauseResource(ctx, db2, uuid.New()), ErrResourceNotActive)

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`SET status = 'paused'`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, PauseResource(ctx, db3, uuid.New()), "boom")
}

func TestPauseAllTeamResources_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`SET status = 'paused'`).WillReturnResult(sqlmock.NewResult(0, 4))
	n, err := PauseAllTeamResources(ctx, db, uuid.New())
	require.NoError(t, err)
	require.Equal(t, int64(4), n)

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`SET status = 'paused'`).WillReturnError(errors.New("boom"))
	_, err = PauseAllTeamResources(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "boom")

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`SET status = 'paused'`).WillReturnResult(sqlmock.NewErrorResult(errors.New("raerr")))
	_, err = PauseAllTeamResources(ctx, db3, uuid.New())
	require.ErrorContains(t, err, "raerr")
}

func TestResumeResource_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`SET status = 'active', paused_at = NULL`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, ResumeResource(ctx, db, uuid.New()))

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`SET status = 'active', paused_at = NULL`).WillReturnResult(sqlmock.NewResult(0, 0))
	require.ErrorIs(t, ResumeResource(ctx, db2, uuid.New()), ErrResourceNotPaused)

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`SET status = 'active', paused_at = NULL`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, ResumeResource(ctx, db3, uuid.New()), "boom")
}

func TestListResourcesByTeam_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`WHERE team_id = \$1 AND status != 'deleted'`).WillReturnRows(resourceMockRow())
	out, err := ListResourcesByTeam(ctx, db, uuid.New())
	require.NoError(t, err)
	require.Len(t, out, 1)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`WHERE team_id = \$1 AND status != 'deleted'`).WillReturnError(errors.New("qerr"))
	_, err = ListResourcesByTeam(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "qerr")

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`WHERE team_id = \$1 AND status != 'deleted'`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = ListResourcesByTeam(ctx, db3, uuid.New())
	require.Error(t, err)
}

func TestListResourcesByTeamAndEnv_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`WHERE team_id = \$1 AND env = \$2`).WillReturnRows(resourceMockRow())
	out, err := ListResourcesByTeamAndEnv(ctx, db, uuid.New(), "") // empty -> default
	require.NoError(t, err)
	require.Len(t, out, 1)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`WHERE team_id = \$1 AND env = \$2`).WillReturnError(errors.New("qerr"))
	_, err = ListResourcesByTeamAndEnv(ctx, db2, uuid.New(), "prod")
	require.ErrorContains(t, err, "qerr")

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`WHERE team_id = \$1 AND env = \$2`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = ListResourcesByTeamAndEnv(ctx, db3, uuid.New(), "prod")
	require.Error(t, err)
}

func TestSimpleResourceUpdaters(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE resources SET connection_url`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, UpdateConnectionURL(ctx, db, uuid.New(), "enc"))
	db1b, mock1b := newMock(t)
	mock1b.ExpectExec(`UPDATE resources SET connection_url`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, UpdateConnectionURL(ctx, db1b, uuid.New(), "enc"), "boom")

	require.ErrorContains(t, SetResourceAuthMode(ctx, nil, uuid.New(), "bad"), "invalid auth_mode")
	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE resources SET auth_mode`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, SetResourceAuthMode(ctx, db2, uuid.New(), "legacy_open"))
	db2b, mock2b := newMock(t)
	mock2b.ExpectExec(`UPDATE resources SET auth_mode`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, SetResourceAuthMode(ctx, db2b, uuid.New(), "isolated"), "boom")

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE resources SET key_prefix`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, UpdateKeyPrefix(ctx, db3, uuid.New(), "p:"))
	db3b, mock3b := newMock(t)
	mock3b.ExpectExec(`UPDATE resources SET key_prefix`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, UpdateKeyPrefix(ctx, db3b, uuid.New(), "p:"), "boom")

	db4, mock4 := newMock(t)
	mock4.ExpectExec(`UPDATE resources SET provider_resource_id`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, UpdateProviderResourceID(ctx, db4, uuid.New(), "pid"))
	db4b, mock4b := newMock(t)
	mock4b.ExpectExec(`UPDATE resources SET provider_resource_id`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, UpdateProviderResourceID(ctx, db4b, uuid.New(), "")) // NULL path
	db4c, mock4c := newMock(t)
	mock4c.ExpectExec(`UPDATE resources SET provider_resource_id`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, UpdateProviderResourceID(ctx, db4c, uuid.New(), "pid"), "boom")

	db5, mock5 := newMock(t)
	mock5.ExpectExec(`UPDATE resources\s+SET tier`).WillReturnResult(sqlmock.NewResult(0, 2))
	require.NoError(t, ElevateResourceTiersByTeam(ctx, db5, uuid.New(), "pro"))
	db5b, mock5b := newMock(t)
	mock5b.ExpectExec(`UPDATE resources\s+SET tier`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, ElevateResourceTiersByTeam(ctx, db5b, uuid.New(), "pro"), "boom")
}

func TestSumStorageBytes_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`COALESCE\(SUM\(storage_bytes\), 0\)\s+FROM resources\s+WHERE team_id`).WillReturnRows(sqlmock.NewRows([]string{"sum"}).AddRow(int64(100)))
	n, err := SumStorageBytesByTeamAndType(ctx, db, uuid.New(), "postgres")
	require.NoError(t, err)
	require.Equal(t, int64(100), n)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`WHERE team_id`).WillReturnError(errors.New("boom"))
	_, err = SumStorageBytesByTeamAndType(ctx, db2, uuid.New(), "postgres")
	require.ErrorContains(t, err, "boom")

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`WHERE fingerprint`).WillReturnRows(sqlmock.NewRows([]string{"sum"}).AddRow(int64(50)))
	n, err = SumStorageBytesByFingerprintAndType(ctx, db3, "fp", "storage")
	require.NoError(t, err)
	require.Equal(t, int64(50), n)

	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`WHERE fingerprint`).WillReturnError(errors.New("boom"))
	_, err = SumStorageBytesByFingerprintAndType(ctx, db4, "fp", "storage")
	require.ErrorContains(t, err, "boom")
}

func TestExpireAnonymousResources_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE resources\s+SET status = 'deleted'`).WillReturnResult(sqlmock.NewResult(0, 5))
	n, err := ExpireAnonymousResources(ctx, db)
	require.NoError(t, err)
	require.Equal(t, int64(5), n)

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE resources\s+SET status = 'deleted'`).WillReturnError(errors.New("boom"))
	_, err = ExpireAnonymousResources(ctx, db2)
	require.ErrorContains(t, err, "boom")
}
