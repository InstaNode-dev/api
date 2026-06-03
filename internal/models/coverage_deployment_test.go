package models

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestDeploymentErrorAndHelpers(t *testing.T) {
	require.Contains(t, (&ErrDeploymentNotFound{ID: "x"}).Error(), "x")

	require.Nil(t, splitAllowedIPs(""))
	require.Nil(t, splitAllowedIPs(" , , "))
	require.Equal(t, []string{"1.2.3.4", "5.6.7.8"}, splitAllowedIPs("1.2.3.4, 5.6.7.8"))
	require.Equal(t, "1.2.3.4,5.6.7.8", JoinAllowedIPs([]string{"1.2.3.4", "5.6.7.8"}))

	require.True(t, IsDeploymentTerminal(DeployStatusExpired))
	require.True(t, IsDeploymentTerminal(DeployStatusDeleted))
	require.True(t, IsDeploymentTerminal(DeployStatusStopped))
	require.False(t, IsDeploymentTerminal(DeployStatusHealthy))
}

func TestCreateDeployment_AllTTLBranches(t *testing.T) {
	ctx := context.Background()

	// custom ttl with hours<1 default + env empty + notify webhook + marshal env
	db, mock := newMock(t)
	mock.ExpectQuery(`INSERT INTO deployments`).WillReturnRows(deploymentMockRow())
	_, err := CreateDeployment(ctx, db, CreateDeploymentParams{
		TeamID: uuid.New(), AppID: "a", TTLPolicy: DeployTTLPolicyCustom, TTLHours: 0,
		NotifyWebhook: "https://x", NotifyWebhookSecret: "s", EnvVars: map[string]string{"K": "V"},
	})
	require.NoError(t, err)

	// permanent policy
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`INSERT INTO deployments`).WillReturnRows(deploymentMockRow())
	_, err = CreateDeployment(ctx, db2, CreateDeploymentParams{TeamID: uuid.New(), AppID: "a", TTLPolicy: DeployTTLPolicyPermanent})
	require.NoError(t, err)

	// unknown policy -> fallback auto_24h
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`INSERT INTO deployments`).WillReturnRows(deploymentMockRow())
	_, err = CreateDeployment(ctx, db3, CreateDeploymentParams{TeamID: uuid.New(), AppID: "a", TTLPolicy: "weird"})
	require.NoError(t, err)

	// db error
	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`INSERT INTO deployments`).WillReturnError(errors.New("boom"))
	_, err = CreateDeployment(ctx, db4, CreateDeploymentParams{TeamID: uuid.New(), AppID: "a"})
	require.ErrorContains(t, err, "boom")
}

func TestGetDeploymentByAppID_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`FROM deployments WHERE app_id`).WillReturnRows(deploymentMockRow())
	_, err := GetDeploymentByAppID(ctx, db, "a")
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM deployments WHERE app_id`).WillReturnError(errNoRows())
	var nf *ErrDeploymentNotFound
	_, err = GetDeploymentByAppID(ctx, db2, "a")
	require.ErrorAs(t, err, &nf)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM deployments WHERE app_id`).WillReturnError(errors.New("boom"))
	_, err = GetDeploymentByAppID(ctx, db3, "a")
	require.ErrorContains(t, err, "boom")
}

func TestGetDeploymentByID_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`FROM deployments WHERE id`).WillReturnRows(deploymentMockRow())
	_, err := GetDeploymentByID(ctx, db, uuid.New())
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM deployments WHERE id`).WillReturnError(errNoRows())
	var nf *ErrDeploymentNotFound
	_, err = GetDeploymentByID(ctx, db2, uuid.New())
	require.ErrorAs(t, err, &nf)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM deployments WHERE id`).WillReturnError(errors.New("boom"))
	_, err = GetDeploymentByID(ctx, db3, uuid.New())
	require.ErrorContains(t, err, "boom")
}

func TestGetDeploymentsByTeam_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`FROM deployments\s+WHERE team_id = \$1 AND status NOT IN`).WillReturnRows(deploymentMockRow())
	out, err := GetDeploymentsByTeam(ctx, db, uuid.New())
	require.NoError(t, err)
	require.Len(t, out, 1)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM deployments\s+WHERE team_id = \$1 AND status NOT IN`).WillReturnError(errors.New("qerr"))
	_, err = GetDeploymentsByTeam(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "qerr")

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM deployments\s+WHERE team_id = \$1 AND status NOT IN`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = GetDeploymentsByTeam(ctx, db3, uuid.New())
	require.Error(t, err)

	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`FROM deployments\s+WHERE team_id = \$1 AND status NOT IN`).WillReturnRows(deploymentMockRow().RowError(0, errors.New("rowerr")))
	_, err = GetDeploymentsByTeam(ctx, db4, uuid.New())
	require.ErrorContains(t, err, "rowerr")
}

func TestGetDeploymentsByTeamAndEnv_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`WHERE team_id = \$1 AND env = \$2`).WillReturnRows(deploymentMockRow())
	out, err := GetDeploymentsByTeamAndEnv(ctx, db, uuid.New(), "") // empty -> default
	require.NoError(t, err)
	require.Len(t, out, 1)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`WHERE team_id = \$1 AND env = \$2`).WillReturnError(errors.New("qerr"))
	_, err = GetDeploymentsByTeamAndEnv(ctx, db2, uuid.New(), "prod")
	require.ErrorContains(t, err, "qerr")

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`WHERE team_id = \$1 AND env = \$2`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = GetDeploymentsByTeamAndEnv(ctx, db3, uuid.New(), "prod")
	require.Error(t, err)
}

func TestDeploymentSimpleUpdaters_Branches(t *testing.T) {
	ctx := context.Background()
	id := uuid.New()

	// UpdateDeploymentStatus (errmsg set + empty)
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE deployments\s+SET status`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, UpdateDeploymentStatus(ctx, db, id, "healthy", "err"))
	db1b, mock1b := newMock(t)
	mock1b.ExpectExec(`UPDATE deployments\s+SET status`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, UpdateDeploymentStatus(ctx, db1b, id, "failed", ""), "boom")

	// UpdateDeploymentProviderID
	db2, mock2 := newMock(t)
	mock2.ExpectExec(`SET provider_id`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, UpdateDeploymentProviderID(ctx, db2, id, "p", "http://x"))
	db2b, mock2b := newMock(t)
	mock2b.ExpectExec(`SET provider_id`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, UpdateDeploymentProviderID(ctx, db2b, id, "p", "u"), "boom")

	// UpdateDeploymentEnvVars (nil map path + happy + error)
	db3, mock3 := newMock(t)
	mock3.ExpectExec(`SET env_vars`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, UpdateDeploymentEnvVars(ctx, db3, id, nil))
	db3b, mock3b := newMock(t)
	mock3b.ExpectExec(`SET env_vars`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, UpdateDeploymentEnvVars(ctx, db3b, id, map[string]string{"a": "b"}), "boom")

	// UpdateDeploymentAccessControl
	db4, mock4 := newMock(t)
	mock4.ExpectExec(`SET private`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, UpdateDeploymentAccessControl(ctx, db4, id, true, []string{"1.2.3.4"}))
	db4b, mock4b := newMock(t)
	mock4b.ExpectExec(`SET private`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, UpdateDeploymentAccessControl(ctx, db4b, id, false, nil), "boom")

	// DeleteDeployment
	db5, mock5 := newMock(t)
	mock5.ExpectExec(`DELETE FROM deployments`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, DeleteDeployment(ctx, db5, id))
	db5b, mock5b := newMock(t)
	mock5b.ExpectExec(`DELETE FROM deployments`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, DeleteDeployment(ctx, db5b, id), "boom")

	// MakeDeploymentPermanent
	db6, mock6 := newMock(t)
	mock6.ExpectExec(`SET expires_at = NULL, ttl_policy = 'permanent'`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, MakeDeploymentPermanent(ctx, db6, id))
	db6b, mock6b := newMock(t)
	mock6b.ExpectExec(`SET expires_at = NULL, ttl_policy = 'permanent'`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, MakeDeploymentPermanent(ctx, db6b, id), "boom")

	// ElevateDeploymentTiersByTeam
	db7, mock7 := newMock(t)
	mock7.ExpectExec(`UPDATE deployments`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, ElevateDeploymentTiersByTeam(ctx, db7, uuid.New(), "pro"))
	db7b, mock7b := newMock(t)
	mock7b.ExpectExec(`UPDATE deployments`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, ElevateDeploymentTiersByTeam(ctx, db7b, uuid.New(), "pro"), "boom")

	// SetDeploymentTTL
	db8, mock8 := newMock(t)
	mock8.ExpectExec(`SET expires_at = \$1,\s+ttl_policy = 'custom'`).WillReturnResult(sqlmock.NewResult(0, 1))
	ok8, err8 := SetDeploymentTTL(ctx, db8, id, 48)
	require.NoError(t, err8)
	require.True(t, ok8, "1 row affected → applied")
	db8b, mock8b := newMock(t)
	mock8b.ExpectExec(`ttl_policy = 'custom'`).WillReturnError(errors.New("boom"))
	_, err8b := SetDeploymentTTL(ctx, db8b, id, 48)
	require.ErrorContains(t, err8b, "boom")
	// 0 rows affected (permanent/terminal guard matched nothing) → applied=false.
	db8c, mock8c := newMock(t)
	mock8c.ExpectExec(`ttl_policy = 'custom'`).WillReturnResult(sqlmock.NewResult(0, 0))
	ok8c, err8c := SetDeploymentTTL(ctx, db8c, id, 48)
	require.NoError(t, err8c)
	require.False(t, ok8c, "0 rows affected → not applied")

	// MarkDeploymentExpired
	db9, mock9 := newMock(t)
	mock9.ExpectExec(`SET status = 'expired'`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, MarkDeploymentExpired(ctx, db9, id))
	db9b, mock9b := newMock(t)
	mock9b.ExpectExec(`SET status = 'expired'`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, MarkDeploymentExpired(ctx, db9b, id), "boom")
}

func TestGetDeploymentsExpiringSoon_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`reminders_sent < 6`).WillReturnRows(deploymentMockRow())
	out, err := GetDeploymentsExpiringSoon(ctx, db, time.Hour, time.Hour)
	require.NoError(t, err)
	require.Len(t, out, 1)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`reminders_sent < 6`).WillReturnError(errors.New("qerr"))
	_, err = GetDeploymentsExpiringSoon(ctx, db2, time.Hour, time.Hour)
	require.ErrorContains(t, err, "qerr")

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`reminders_sent < 6`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = GetDeploymentsExpiringSoon(ctx, db3, time.Hour, time.Hour)
	require.Error(t, err)

	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`reminders_sent < 6`).WillReturnRows(deploymentMockRow().RowError(0, errors.New("rowerr")))
	_, err = GetDeploymentsExpiringSoon(ctx, db4, time.Hour, time.Hour)
	require.ErrorContains(t, err, "rowerr")
}

func TestAdvanceDeploymentReminder_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`SET reminders_sent = reminders_sent \+ 1`).WillReturnResult(sqlmock.NewResult(0, 1))
	ok, err := AdvanceDeploymentReminder(ctx, db, uuid.New(), 2, time.Hour)
	require.NoError(t, err)
	require.True(t, ok)

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`SET reminders_sent = reminders_sent \+ 1`).WillReturnResult(sqlmock.NewResult(0, 0))
	ok, err = AdvanceDeploymentReminder(ctx, db2, uuid.New(), 2, time.Hour)
	require.NoError(t, err)
	require.False(t, ok)

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`SET reminders_sent = reminders_sent \+ 1`).WillReturnError(errors.New("boom"))
	_, err = AdvanceDeploymentReminder(ctx, db3, uuid.New(), 2, time.Hour)
	require.ErrorContains(t, err, "boom")

	db4, mock4 := newMock(t)
	mock4.ExpectExec(`SET reminders_sent = reminders_sent \+ 1`).WillReturnResult(sqlmock.NewErrorResult(errors.New("raerr")))
	_, err = AdvanceDeploymentReminder(ctx, db4, uuid.New(), 2, time.Hour)
	require.ErrorContains(t, err, "raerr")
}

func TestGetExpiredDeployments_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`expires_at < \$1`).WillReturnRows(deploymentMockRow())
	out, err := GetExpiredDeployments(ctx, db, 0) // default limit
	require.NoError(t, err)
	require.Len(t, out, 1)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`expires_at < \$1`).WillReturnError(errors.New("qerr"))
	_, err = GetExpiredDeployments(ctx, db2, 10)
	require.ErrorContains(t, err, "qerr")

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`expires_at < \$1`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = GetExpiredDeployments(ctx, db3, 10)
	require.Error(t, err)
}

func TestGetExpiredDeploymentsAwaitingTeardown_Branches(t *testing.T) {
	ctx := context.Background()

	// happy
	db, mock := newMock(t)
	mock.ExpectBegin()
	mock.ExpectQuery(`FOR UPDATE SKIP LOCKED`).WillReturnRows(deploymentMockRow())
	tx, _ := db.BeginTx(ctx, nil)
	out, err := GetExpiredDeploymentsAwaitingTeardown(ctx, tx, 0)
	require.NoError(t, err)
	require.Len(t, out, 1)

	// query error
	db2, mock2 := newMock(t)
	mock2.ExpectBegin()
	mock2.ExpectQuery(`FOR UPDATE SKIP LOCKED`).WillReturnError(errors.New("qerr"))
	tx2, _ := db2.BeginTx(ctx, nil)
	_, err = GetExpiredDeploymentsAwaitingTeardown(ctx, tx2, 10)
	require.ErrorContains(t, err, "qerr")

	// scan error
	db3, mock3 := newMock(t)
	mock3.ExpectBegin()
	mock3.ExpectQuery(`FOR UPDATE SKIP LOCKED`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	tx3, _ := db3.BeginTx(ctx, nil)
	_, err = GetExpiredDeploymentsAwaitingTeardown(ctx, tx3, 10)
	require.Error(t, err)
}

func TestMarkDeploymentTornDown_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectBegin()
	mock.ExpectExec(`SET status = \$1, updated_at = now\(\)`).WillReturnResult(sqlmock.NewResult(0, 1))
	tx, _ := db.BeginTx(ctx, nil)
	n, err := MarkDeploymentTornDown(ctx, tx, uuid.New())
	require.NoError(t, err)
	require.Equal(t, int64(1), n)

	db2, mock2 := newMock(t)
	mock2.ExpectBegin()
	mock2.ExpectExec(`SET status = \$1, updated_at = now\(\)`).WillReturnError(errors.New("boom"))
	tx2, _ := db2.BeginTx(ctx, nil)
	_, err = MarkDeploymentTornDown(ctx, tx2, uuid.New())
	require.ErrorContains(t, err, "boom")
}

func TestCountDeploymentsByTeam_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`count\(\*\) FROM deployments\s+WHERE team_id = \$1 AND status IN`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	n, err := CountActiveDeploymentsByTeam(ctx, db, uuid.New())
	require.NoError(t, err)
	require.Equal(t, 2, n)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`count\(\*\) FROM deployments\s+WHERE team_id = \$1 AND status IN`).WillReturnError(errors.New("boom"))
	_, err = CountActiveDeploymentsByTeam(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "boom")

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`count\(\*\) FROM deployments\s+WHERE team_id = \$1 AND status NOT IN`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))
	n, err = CountVisibleDeploymentsByTeam(ctx, db3, uuid.New())
	require.NoError(t, err)
	require.Equal(t, 3, n)

	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`count\(\*\) FROM deployments\s+WHERE team_id = \$1 AND status NOT IN`).WillReturnError(errors.New("boom"))
	_, err = CountVisibleDeploymentsByTeam(ctx, db4, uuid.New())
	require.ErrorContains(t, err, "boom")
}

func TestFindActiveDeploymentByTeamEnvName_Branches(t *testing.T) {
	ctx := context.Background()
	teamID := uuid.New()

	// Happy path: a matching row is returned. Also covers the env == ""
	// default branch by passing "" and letting the model substitute EnvDefault.
	db, mock := newMock(t)
	mock.ExpectQuery(`FROM deployments\s+WHERE team_id = \$1\s+AND env = \$2\s+AND env_vars->>'_name' = \$3`).
		WithArgs(teamID, EnvDefault, "truehomie-web").
		WillReturnRows(deploymentMockRow())
	d, err := FindActiveDeploymentByTeamEnvName(ctx, db, teamID, "", "truehomie-web")
	require.NoError(t, err)
	require.NotNil(t, d)

	// sql.ErrNoRows path: returns (nil, sql.ErrNoRows) verbatim so the handler
	// can errors.Is-check and translate to a 404 with the canonical envelope.
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM deployments\s+WHERE team_id`).
		WithArgs(teamID, "production", "missing-app").
		WillReturnError(errNoRows())
	_, err = FindActiveDeploymentByTeamEnvName(ctx, db2, teamID, "production", "missing-app")
	require.ErrorIs(t, err, sql.ErrNoRows)

	// Generic DB error path: wrapped with the function name for ops triage.
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM deployments\s+WHERE team_id`).
		WillReturnError(errors.New("connection reset"))
	_, err = FindActiveDeploymentByTeamEnvName(ctx, db3, teamID, "production", "foo")
	require.ErrorContains(t, err, "FindActiveDeploymentByTeamEnvName")
	require.ErrorContains(t, err, "connection reset")
}
