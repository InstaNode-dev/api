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

func TestInsertSelfReport_Branches(t *testing.T) {
	ctx := context.Background()

	require.ErrorContains(t, InsertSelfReport(ctx, nil, SelfReportParams{}), "service is required")
	require.ErrorContains(t, InsertSelfReport(ctx, nil, SelfReportParams{Service: "api"}), "commit_id is required")
	require.ErrorContains(t, InsertSelfReport(ctx, nil, SelfReportParams{Service: "api", CommitID: "c"}), "image_digest is required")

	// happy with all set + valid build time
	db, mock := newMock(t)
	mock.ExpectExec(`INSERT INTO deploys_audit`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, InsertSelfReport(ctx, db, SelfReportParams{
		Service: DeployServiceAPI, CommitID: "abc", ImageDigest: "sha256:x", Version: "1.2.3",
		BuildTime: time.Now().UTC().Format(time.RFC3339), MigrationVersion: "062_x.sql",
	}))

	// version=unknown/dev -> NULL, build_time unparseable -> NULL, empty migration
	db2, mock2 := newMock(t)
	mock2.ExpectExec(`INSERT INTO deploys_audit`).WillReturnResult(sqlmock.NewResult(0, 0))
	require.NoError(t, InsertSelfReport(ctx, db2, SelfReportParams{
		Service: DeployServiceWorker, CommitID: "abc", ImageDigest: "sha256:x", Version: "dev", BuildTime: "garbage",
	}))

	// db error
	db3, mock3 := newMock(t)
	mock3.ExpectExec(`INSERT INTO deploys_audit`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, InsertSelfReport(ctx, db3, SelfReportParams{Service: "api", CommitID: "c", ImageDigest: "d"}), "boom")
}

func deployAuditCols() []string {
	return []string{"id", "service", "commit_id", "image_digest", "version", "build_time", "applied_at", "migration_version", "noticed_by"}
}

func TestListDeploys_Branches(t *testing.T) {
	ctx := context.Background()

	// invalid service
	_, err := ListDeploys(ctx, nil, ListDeploysParams{Service: "bogus"})
	require.ErrorContains(t, err, "invalid service")

	// happy with service + since filters + over-max limit
	db, mock := newMock(t)
	mock.ExpectQuery(`FROM deploys_audit`).
		WillReturnRows(sqlmock.NewRows(deployAuditCols()).AddRow(uuid.New(), "api", "c", "d", nil, nil, time.Now(), nil, "self-report"))
	out, err := ListDeploys(ctx, db, ListDeploysParams{Service: DeployServiceAPI, Since: time.Now().Add(-time.Hour), Limit: 9999})
	require.NoError(t, err)
	require.Len(t, out, 1)

	// default limit + query error
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM deploys_audit`).WillReturnError(errors.New("qerr"))
	_, err = ListDeploys(ctx, db2, ListDeploysParams{})
	require.ErrorContains(t, err, "qerr")

	// scan error
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM deploys_audit`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = ListDeploys(ctx, db3, ListDeploysParams{})
	require.Error(t, err)

	// rows.Err()
	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`FROM deploys_audit`).WillReturnRows(
		sqlmock.NewRows(deployAuditCols()).AddRow(uuid.New(), "api", "c", "d", nil, nil, time.Now(), nil, "self-report").RowError(0, errors.New("rowerr")))
	_, err = ListDeploys(ctx, db4, ListDeploysParams{})
	require.ErrorContains(t, err, "rowerr")
}
