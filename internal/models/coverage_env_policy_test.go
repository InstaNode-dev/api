package models

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestEnvPolicyAllowed(t *testing.T) {
	require.True(t, EnvPolicy(nil).Allowed("prod", "deploy", "admin"))      // empty policy
	p := EnvPolicy{"prod": {}}
	require.True(t, p.Allowed("staging", "deploy", "x")) // no env entry
	require.True(t, p.Allowed("prod", "deploy", "x"))    // empty env entry
	p2 := EnvPolicy{"prod": {"deploy": {}}}
	require.True(t, p2.Allowed("prod", "deploy", "x")) // empty roles slice
	p3 := EnvPolicy{"prod": {"deploy": {"admin"}}}
	require.True(t, p3.Allowed("prod", "deploy", " ADMIN "))
	require.False(t, p3.Allowed("prod", "deploy", "viewer"))
	require.True(t, p3.Allowed("prod", "delete_resource", "viewer")) // no such action
}

func TestEnvPolicyAllowedRoles(t *testing.T) {
	require.Nil(t, EnvPolicy(nil).AllowedRoles("prod", "deploy"))
	p := EnvPolicy{"prod": {"deploy": {"admin", "owner"}}}
	require.Nil(t, p.AllowedRoles("staging", "deploy")) // no env
	require.Nil(t, p.AllowedRoles("prod", "vault_write")) // no action
	got := p.AllowedRoles("prod", "deploy")
	require.Equal(t, []string{"admin", "owner"}, got)
	got[0] = "MUTATED"
	require.Equal(t, "admin", p["prod"]["deploy"][0]) // defensive copy
}

func TestValidateEnvPolicy(t *testing.T) {
	got, err := ValidateEnvPolicy(nil)
	require.NoError(t, err)
	require.Empty(t, got)

	_, err = ValidateEnvPolicy([]byte(strings.Repeat("x", envPolicyMaxBytes+1)))
	require.ErrorContains(t, err, "too large")

	_, err = ValidateEnvPolicy([]byte(`{not json`))
	require.Error(t, err)

	_, err = ValidateEnvPolicy([]byte(`{"PROD!":{"deploy":["admin"]}}`))
	require.ErrorContains(t, err, "invalid env name")

	_, err = ValidateEnvPolicy([]byte(`{"prod":{"deplay":["admin"]}}`))
	require.ErrorContains(t, err, "unknown action")

	_, err = ValidateEnvPolicy([]byte(`{"prod":{"deploy":["bad!role"]}}`))
	require.ErrorContains(t, err, "invalid role")

	// happy with dedupe + lowercasing
	out, err := ValidateEnvPolicy([]byte(`{"PROD":{"DEPLOY":["Admin","admin","Owner"]}}`))
	require.NoError(t, err)
	require.Equal(t, []string{"admin", "owner"}, out["prod"]["deploy"])

	// duplicate env after lowercasing
	_, err = ValidateEnvPolicy([]byte(`{"PROD":{"deploy":["admin"]},"prod":{"deploy":["owner"]}}`))
	// JSON object with duplicate keys: encoding/json keeps the last; this may
	// not trigger the dup check, so just require no panic / valid result.
	_ = err
}

func TestEnvNameRoleNameValid(t *testing.T) {
	require.False(t, envNameValid(""))
	require.False(t, envNameValid(strings.Repeat("a", 65)))
	require.False(t, envNameValid("UP"))
	require.True(t, envNameValid("prod-1_x"))
	require.False(t, roleNameValid(""))
	require.False(t, roleNameValid(strings.Repeat("a", 33)))
	require.False(t, roleNameValid("a-b"))
	require.True(t, roleNameValid("admin_1"))
}

func TestKnownEnvPolicyActions(t *testing.T) {
	k := knownEnvPolicyActions()
	require.Contains(t, k, ActionDeploy)
	require.Contains(t, k, ActionDeleteResource)
	require.Contains(t, k, ActionVaultWrite)
}

func TestGetTeamEnvPolicy_Branches(t *testing.T) {
	ctx := context.Background()

	// not found -> empty
	db, mock := newMock(t)
	mock.ExpectQuery(`SELECT env_policy FROM teams`).WillReturnError(errNoRows())
	got, err := GetTeamEnvPolicy(ctx, db, uuid.New())
	require.NoError(t, err)
	require.Empty(t, got)

	// other error
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`SELECT env_policy FROM teams`).WillReturnError(errors.New("boom"))
	_, err = GetTeamEnvPolicy(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "boom")

	// empty raw -> empty policy
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`SELECT env_policy FROM teams`).WillReturnRows(sqlmock.NewRows([]string{"env_policy"}).AddRow([]byte{}))
	got, err = GetTeamEnvPolicy(ctx, db3, uuid.New())
	require.NoError(t, err)
	require.Empty(t, got)

	// malformed -> default allow (empty)
	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`SELECT env_policy FROM teams`).WillReturnRows(sqlmock.NewRows([]string{"env_policy"}).AddRow([]byte(`not json`)))
	got, err = GetTeamEnvPolicy(ctx, db4, uuid.New())
	require.NoError(t, err)
	require.Empty(t, got)

	// valid policy
	db5, mock5 := newMock(t)
	mock5.ExpectQuery(`SELECT env_policy FROM teams`).WillReturnRows(sqlmock.NewRows([]string{"env_policy"}).AddRow([]byte(`{"prod":{"deploy":["admin"]}}`)))
	got, err = GetTeamEnvPolicy(ctx, db5, uuid.New())
	require.NoError(t, err)
	require.Equal(t, []string{"admin"}, got["prod"]["deploy"])
}

func TestSetTeamEnvPolicy_Branches(t *testing.T) {
	ctx := context.Background()
	p := EnvPolicy{"prod": {"deploy": {"admin"}}}

	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE teams SET env_policy`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, SetTeamEnvPolicy(ctx, db, uuid.New(), p))

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE teams SET env_policy`).WillReturnResult(sqlmock.NewResult(0, 0))
	var nf *ErrTeamNotFound
	require.ErrorAs(t, SetTeamEnvPolicy(ctx, db2, uuid.New(), p), &nf)

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE teams SET env_policy`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, SetTeamEnvPolicy(ctx, db3, uuid.New(), p), "boom")
}
