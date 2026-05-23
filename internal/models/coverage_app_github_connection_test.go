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

func TestGitHubConnErrorStrings(t *testing.T) {
	require.Contains(t, (&ErrGitHubConnectionNotFound{ID: "x"}).Error(), "x")
	require.Contains(t, (&ErrGitHubDeployRateLimited{Recent: 3}).Error(), "3")
}

func ghConnCols() []string {
	return []string{"id", "app_id", "team_id", "github_repo", "branch", "webhook_secret", "installation_id", "created_at", "last_deploy_at", "last_commit_sha"}
}

func TestCreateGitHubConnection_Branches(t *testing.T) {
	ctx := context.Background()
	inst := int64(42)

	db, mock := newMock(t)
	mock.ExpectQuery(`INSERT INTO app_github_connections`).
		WillReturnRows(sqlmock.NewRows(ghConnCols()).AddRow(uuid.New(), uuid.New(), uuid.New(), "o/r", "main", "ct", inst, time.Now(), nil, nil))
	got, err := CreateGitHubConnection(ctx, db, CreateGitHubConnectionParams{AppID: uuid.New(), TeamID: uuid.New(), GitHubRepo: "o/r", WebhookSecret: "ct", InstallationID: &inst})
	require.NoError(t, err)
	require.Equal(t, "main", got.Branch)

	// empty branch -> defaults to "main", nil installation
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`INSERT INTO app_github_connections`).
		WillReturnRows(sqlmock.NewRows(ghConnCols()).AddRow(uuid.New(), uuid.New(), uuid.New(), "o/r", "main", "ct", nil, time.Now(), nil, nil))
	_, err = CreateGitHubConnection(ctx, db2, CreateGitHubConnectionParams{GitHubRepo: "o/r", WebhookSecret: "ct"})
	require.NoError(t, err)

	// error
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`INSERT INTO app_github_connections`).WillReturnError(errors.New("boom"))
	_, err = CreateGitHubConnection(ctx, db3, CreateGitHubConnectionParams{GitHubRepo: "o/r"})
	require.ErrorContains(t, err, "boom")
}

func TestGetGitHubConnectionByID_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`FROM app_github_connections\s+WHERE id`).
		WillReturnRows(sqlmock.NewRows(ghConnCols()).AddRow(uuid.New(), uuid.New(), uuid.New(), "o/r", "main", "ct", nil, time.Now(), nil, nil))
	_, err := GetGitHubConnectionByID(ctx, db, uuid.New())
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM app_github_connections\s+WHERE id`).WillReturnError(errNoRows())
	_, err = GetGitHubConnectionByID(ctx, db2, uuid.New())
	var nf *ErrGitHubConnectionNotFound
	require.ErrorAs(t, err, &nf)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM app_github_connections\s+WHERE id`).WillReturnError(errors.New("boom"))
	_, err = GetGitHubConnectionByID(ctx, db3, uuid.New())
	require.ErrorContains(t, err, "boom")
}

func TestGetGitHubConnectionByAppID_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`FROM app_github_connections\s+WHERE app_id`).
		WillReturnRows(sqlmock.NewRows(ghConnCols()).AddRow(uuid.New(), uuid.New(), uuid.New(), "o/r", "main", "ct", nil, time.Now(), nil, nil))
	_, err := GetGitHubConnectionByAppID(ctx, db, uuid.New())
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM app_github_connections\s+WHERE app_id`).WillReturnError(errNoRows())
	_, err = GetGitHubConnectionByAppID(ctx, db2, uuid.New())
	var nf *ErrGitHubConnectionNotFound
	require.ErrorAs(t, err, &nf)
}

func TestDeleteGitHubConnection_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`DELETE FROM app_github_connections WHERE id`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, DeleteGitHubConnection(ctx, db, uuid.New()))
}

func TestDeleteGitHubConnectionByAppID_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectExec(`DELETE FROM app_github_connections WHERE app_id`).WillReturnResult(sqlmock.NewResult(0, 2))
	n, err := DeleteGitHubConnectionByAppID(ctx, db, uuid.New())
	require.NoError(t, err)
	require.Equal(t, int64(2), n)

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`DELETE FROM app_github_connections WHERE app_id`).WillReturnError(errors.New("boom"))
	_, err = DeleteGitHubConnectionByAppID(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "boom")
}

func TestUpdateGitHubConnectionLastDeploy(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE app_github_connections`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, UpdateGitHubConnectionLastDeploy(ctx, db, uuid.New(), "sha"))
}

func TestEnqueueGitHubDeploy_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`INSERT INTO pending_github_deploys`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err := EnqueueGitHubDeploy(ctx, db, EnqueueGitHubDeployParams{ConnectionID: uuid.New(), AppID: uuid.New(), CommitSHA: "sha", PusherLogin: "bob"})
	require.NoError(t, err)

	// empty pusher path
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`INSERT INTO pending_github_deploys`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = EnqueueGitHubDeploy(ctx, db2, EnqueueGitHubDeployParams{CommitSHA: "sha"})
	require.NoError(t, err)
}

func TestCountRecentGitHubDeploys_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM pending_github_deploys`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))
	n, err := CountRecentGitHubDeploys(ctx, db, uuid.New(), time.Now())
	require.NoError(t, err)
	require.Equal(t, 3, n)
}

func TestCountAndEnqueueGitHubDeployLocked_Branches(t *testing.T) {
	ctx := context.Background()

	// begin error
	db, mock := newMock(t)
	mock.ExpectBegin().WillReturnError(errors.New("beginerr"))
	_, err := CountAndEnqueueGitHubDeployLocked(ctx, db, EnqueueGitHubDeployParams{ConnectionID: uuid.New()}, time.Now(), 5)
	require.ErrorContains(t, err, "beginerr")

	// lock error
	db2, mock2 := newMock(t)
	mock2.ExpectBegin()
	mock2.ExpectQuery(`SELECT id FROM app_github_connections WHERE id = \$1 FOR UPDATE`).WillReturnError(errors.New("lockerr"))
	mock2.ExpectRollback()
	_, err = CountAndEnqueueGitHubDeployLocked(ctx, db2, EnqueueGitHubDeployParams{ConnectionID: uuid.New()}, time.Now(), 5)
	require.ErrorContains(t, err, "lockerr")

	// count error
	db3, mock3 := newMock(t)
	mock3.ExpectBegin()
	mock3.ExpectQuery(`FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	mock3.ExpectQuery(`SELECT COUNT\(\*\) FROM pending_github_deploys`).WillReturnError(errors.New("counterr"))
	mock3.ExpectRollback()
	_, err = CountAndEnqueueGitHubDeployLocked(ctx, db3, EnqueueGitHubDeployParams{ConnectionID: uuid.New()}, time.Now(), 5)
	require.ErrorContains(t, err, "counterr")

	// rate limited
	db4, mock4 := newMock(t)
	mock4.ExpectBegin()
	mock4.ExpectQuery(`FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	mock4.ExpectQuery(`SELECT COUNT\(\*\) FROM pending_github_deploys`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))
	mock4.ExpectRollback()
	_, err = CountAndEnqueueGitHubDeployLocked(ctx, db4, EnqueueGitHubDeployParams{ConnectionID: uuid.New()}, time.Now(), 5)
	var rl *ErrGitHubDeployRateLimited
	require.ErrorAs(t, err, &rl)

	// insert error
	db5, mock5 := newMock(t)
	mock5.ExpectBegin()
	mock5.ExpectQuery(`FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	mock5.ExpectQuery(`SELECT COUNT\(\*\) FROM pending_github_deploys`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock5.ExpectQuery(`INSERT INTO pending_github_deploys`).WillReturnError(errors.New("inserr"))
	mock5.ExpectRollback()
	_, err = CountAndEnqueueGitHubDeployLocked(ctx, db5, EnqueueGitHubDeployParams{ConnectionID: uuid.New(), PusherLogin: "x"}, time.Now(), 5)
	require.ErrorContains(t, err, "inserr")

	// commit error
	db6, mock6 := newMock(t)
	mock6.ExpectBegin()
	mock6.ExpectQuery(`FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	mock6.ExpectQuery(`SELECT COUNT\(\*\) FROM pending_github_deploys`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock6.ExpectQuery(`INSERT INTO pending_github_deploys`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	mock6.ExpectCommit().WillReturnError(errors.New("commiterr"))
	_, err = CountAndEnqueueGitHubDeployLocked(ctx, db6, EnqueueGitHubDeployParams{ConnectionID: uuid.New(), PusherLogin: "x"}, time.Now(), 5)
	require.ErrorContains(t, err, "commiterr")

	// happy
	db7, mock7 := newMock(t)
	mock7.ExpectBegin()
	mock7.ExpectQuery(`FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	mock7.ExpectQuery(`SELECT COUNT\(\*\) FROM pending_github_deploys`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	id := uuid.New()
	mock7.ExpectQuery(`INSERT INTO pending_github_deploys`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(id))
	mock7.ExpectCommit()
	got, err := CountAndEnqueueGitHubDeployLocked(ctx, db7, EnqueueGitHubDeployParams{ConnectionID: uuid.New(), PusherLogin: "x"}, time.Now(), 5)
	require.NoError(t, err)
	require.Equal(t, id, got)
}
