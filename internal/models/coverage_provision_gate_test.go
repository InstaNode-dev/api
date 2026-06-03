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

func deploymentMockCols() []string {
	return []string{
		"id", "team_id", "resource_id", "app_id", "provider_id", "status", "app_url",
		"env_vars", "port", "tier", "env", "private", "allowed_ips", "error_message", "created_at", "updated_at",
		"notify_webhook", "notify_webhook_secret", "notify_state", "notify_attempts",
		"expires_at", "ttl_policy", "reminders_sent", "last_reminder_at",
		"source", "image_ref", "registry_creds_enc",
		"git_url", "git_ref", "git_token_enc",
	}
}

func deploymentMockRow() *sqlmock.Rows {
	return sqlmock.NewRows(deploymentMockCols()).AddRow(
		uuid.New(), uuid.New(), nil, "app", nil, "building", nil,
		[]byte(`{}`), 8080, "hobby", "production", false, "", nil, time.Now(), time.Now(),
		nil, nil, "unset", 0,
		nil, "auto_24h", 0, nil,
		"tarball", "", "", // source, image_ref, registry_creds_enc (mig 064)
		"", "", "", // git_url, git_ref, git_token_enc (mig 065)
	)
}

func TestCreateDeploymentWithCap_Branches(t *testing.T) {
	ctx := context.Background()
	team := uuid.New()
	p := CreateDeploymentParams{TeamID: team, AppID: "app", Port: 8080, Tier: "hobby"}

	// begin error
	db, mock := newMock(t)
	mock.ExpectBegin().WillReturnError(errors.New("beginerr"))
	_, err := CreateDeploymentWithCap(ctx, db, 1, p)
	require.ErrorContains(t, err, "beginerr")

	// lock team not found
	db2, mock2 := newMock(t)
	mock2.ExpectBegin()
	mock2.ExpectQuery(`SELECT id FROM teams WHERE id = \$1 FOR UPDATE`).WillReturnError(errNoRows())
	mock2.ExpectRollback()
	var nf *ErrTeamNotFound
	_, err = CreateDeploymentWithCap(ctx, db2, 1, p)
	require.ErrorAs(t, err, &nf)

	// cap reached
	db3, mock3 := newMock(t)
	mock3.ExpectBegin()
	mock3.ExpectQuery(`FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(team))
	mock3.ExpectQuery(`count\(\*\) FROM deployments`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock3.ExpectRollback()
	_, err = CreateDeploymentWithCap(ctx, db3, 1, p)
	require.ErrorIs(t, err, ErrDeploymentCapReached)

	// count error
	db3b, mock3b := newMock(t)
	mock3b.ExpectBegin()
	mock3b.ExpectQuery(`FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(team))
	mock3b.ExpectQuery(`count\(\*\) FROM deployments`).WillReturnError(errors.New("cnterr"))
	mock3b.ExpectRollback()
	_, err = CreateDeploymentWithCap(ctx, db3b, 1, p)
	require.ErrorContains(t, err, "cnterr")

	// create error
	db4, mock4 := newMock(t)
	mock4.ExpectBegin()
	mock4.ExpectQuery(`FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(team))
	mock4.ExpectQuery(`count\(\*\) FROM deployments`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock4.ExpectQuery(`INSERT INTO deployments`).WillReturnError(errors.New("createrr"))
	mock4.ExpectRollback()
	_, err = CreateDeploymentWithCap(ctx, db4, 1, p)
	require.ErrorContains(t, err, "createrr")

	// commit error
	db5, mock5 := newMock(t)
	mock5.ExpectBegin()
	mock5.ExpectQuery(`FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(team))
	mock5.ExpectQuery(`count\(\*\) FROM deployments`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock5.ExpectQuery(`INSERT INTO deployments`).WillReturnRows(deploymentMockRow())
	mock5.ExpectCommit().WillReturnError(errors.New("commiterr"))
	_, err = CreateDeploymentWithCap(ctx, db5, 1, p)
	require.ErrorContains(t, err, "commiterr")

	// happy with limit < 0 (unlimited, skip cap check)
	db6, mock6 := newMock(t)
	mock6.ExpectBegin()
	mock6.ExpectQuery(`FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(team))
	mock6.ExpectQuery(`INSERT INTO deployments`).WillReturnRows(deploymentMockRow())
	mock6.ExpectCommit()
	_, err = CreateDeploymentWithCap(ctx, db6, -1, p)
	require.NoError(t, err)
}

func stackMockCols() []string {
	return []string{"id", "team_id", "name", "slug", "namespace", "status", "tier", "env", "parent_stack_id", "expires_at", "fingerprint", "created_at", "updated_at"}
}

func stackMockRow() *sqlmock.Rows {
	return sqlmock.NewRows(stackMockCols()).AddRow(uuid.New(), nil, "n", "slug", "ns", "building", "hobby", "production", nil, nil, "", time.Now(), time.Now())
}

func stackServiceMockCols() []string {
	return []string{"id", "stack_id", "name", "image_tag", "image_ref", "status", "expose", "port", "app_url", "error_msg", "created_at"}
}

func stackServiceMockRow() *sqlmock.Rows {
	return sqlmock.NewRows(stackServiceMockCols()).AddRow(uuid.New(), uuid.New(), "svc", "tag", "", "building", true, 8080, "", "", time.Now())
}

func TestCreateStackWithCap_Branches(t *testing.T) {
	ctx := context.Background()
	team := uuid.New()
	pTeam := CreateStackParams{TeamID: &team, Name: "n", Slug: "slug", Tier: "hobby"}
	svcs := []CreateStackServiceParams{{Name: "svc", Port: 8080, Expose: true}}

	// begin error
	db, mock := newMock(t)
	mock.ExpectBegin().WillReturnError(errors.New("beginerr"))
	_, err := CreateStackWithCap(ctx, db, 1, pTeam, svcs)
	require.ErrorContains(t, err, "beginerr")

	// lock not found
	db2, mock2 := newMock(t)
	mock2.ExpectBegin()
	mock2.ExpectQuery(`FOR UPDATE`).WillReturnError(errNoRows())
	mock2.ExpectRollback()
	var nf *ErrTeamNotFound
	_, err = CreateStackWithCap(ctx, db2, 1, pTeam, svcs)
	require.ErrorAs(t, err, &nf)

	// cap reached
	db3, mock3 := newMock(t)
	mock3.ExpectBegin()
	mock3.ExpectQuery(`FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(team))
	mock3.ExpectQuery(`count\(\*\) FROM stacks`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock3.ExpectRollback()
	_, err = CreateStackWithCap(ctx, db3, 1, pTeam, svcs)
	require.ErrorIs(t, err, ErrStackCapReached)

	// count error
	db3b, mock3b := newMock(t)
	mock3b.ExpectBegin()
	mock3b.ExpectQuery(`FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(team))
	mock3b.ExpectQuery(`count\(\*\) FROM stacks`).WillReturnError(errors.New("cnterr"))
	mock3b.ExpectRollback()
	_, err = CreateStackWithCap(ctx, db3b, 1, pTeam, svcs)
	require.ErrorContains(t, err, "cnterr")

	// create stack error
	db4, mock4 := newMock(t)
	mock4.ExpectBegin()
	mock4.ExpectQuery(`FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(team))
	mock4.ExpectQuery(`count\(\*\) FROM stacks`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock4.ExpectQuery(`INSERT INTO stacks`).WillReturnError(errors.New("stkerr"))
	mock4.ExpectRollback()
	_, err = CreateStackWithCap(ctx, db4, 1, pTeam, svcs)
	require.ErrorContains(t, err, "stkerr")

	// service create error
	db5, mock5 := newMock(t)
	mock5.ExpectBegin()
	mock5.ExpectQuery(`FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(team))
	mock5.ExpectQuery(`count\(\*\) FROM stacks`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock5.ExpectQuery(`INSERT INTO stacks`).WillReturnRows(stackMockRow())
	mock5.ExpectQuery(`INSERT INTO stack_services`).WillReturnError(errors.New("svcerr"))
	mock5.ExpectRollback()
	_, err = CreateStackWithCap(ctx, db5, 1, pTeam, svcs)
	require.ErrorContains(t, err, "svcerr")

	// commit error
	db6, mock6 := newMock(t)
	mock6.ExpectBegin()
	mock6.ExpectQuery(`FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(team))
	mock6.ExpectQuery(`count\(\*\) FROM stacks`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock6.ExpectQuery(`INSERT INTO stacks`).WillReturnRows(stackMockRow())
	mock6.ExpectQuery(`INSERT INTO stack_services`).WillReturnRows(stackServiceMockRow())
	mock6.ExpectCommit().WillReturnError(errors.New("commiterr"))
	_, err = CreateStackWithCap(ctx, db6, 1, pTeam, svcs)
	require.ErrorContains(t, err, "commiterr")

	// happy anonymous (TeamID nil -> skip lock/cap)
	pAnon := CreateStackParams{Name: "n", Slug: "slug", Tier: "anonymous"}
	db7, mock7 := newMock(t)
	mock7.ExpectBegin()
	mock7.ExpectQuery(`INSERT INTO stacks`).WillReturnRows(stackMockRow())
	mock7.ExpectQuery(`INSERT INTO stack_services`).WillReturnRows(stackServiceMockRow())
	mock7.ExpectCommit()
	out, err := CreateStackWithCap(ctx, db7, -1, pAnon, svcs)
	require.NoError(t, err)
	require.Len(t, out.Services, 1)
}

func TestCheckStackCapLocked_Branches(t *testing.T) {
	ctx := context.Background()
	team := uuid.New()

	// lock not found
	db, mock := newMock(t)
	mock.ExpectBegin()
	mock.ExpectQuery(`FOR UPDATE`).WillReturnError(errNoRows())
	tx, _ := db.BeginTx(ctx, nil)
	var nf *ErrTeamNotFound
	require.ErrorAs(t, CheckStackCapLocked(ctx, tx, team, 5), &nf)

	// limit < 0 -> skip
	db2, mock2 := newMock(t)
	mock2.ExpectBegin()
	mock2.ExpectQuery(`FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(team))
	tx2, _ := db2.BeginTx(ctx, nil)
	require.NoError(t, CheckStackCapLocked(ctx, tx2, team, -1))

	// count error
	db3, mock3 := newMock(t)
	mock3.ExpectBegin()
	mock3.ExpectQuery(`FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(team))
	mock3.ExpectQuery(`count\(\*\) FROM stacks`).WillReturnError(errors.New("cnterr"))
	tx3, _ := db3.BeginTx(ctx, nil)
	require.ErrorContains(t, CheckStackCapLocked(ctx, tx3, team, 5), "cnterr")

	// cap reached
	db4, mock4 := newMock(t)
	mock4.ExpectBegin()
	mock4.ExpectQuery(`FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(team))
	mock4.ExpectQuery(`count\(\*\) FROM stacks`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))
	tx4, _ := db4.BeginTx(ctx, nil)
	require.ErrorIs(t, CheckStackCapLocked(ctx, tx4, team, 5), ErrStackCapReached)

	// happy
	db5, mock5 := newMock(t)
	mock5.ExpectBegin()
	mock5.ExpectQuery(`FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(team))
	mock5.ExpectQuery(`count\(\*\) FROM stacks`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	tx5, _ := db5.BeginTx(ctx, nil)
	require.NoError(t, CheckStackCapLocked(ctx, tx5, team, 5))
}
