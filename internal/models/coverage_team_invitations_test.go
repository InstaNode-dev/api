package models

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestIsValidInviteRole(t *testing.T) {
	require.True(t, IsValidInviteRole(RoleAdmin))
	require.True(t, IsValidInviteRole(RoleDeveloper))
	require.True(t, IsValidInviteRole(RoleViewer))
	require.False(t, IsValidInviteRole(RoleOwner))
	require.False(t, IsValidInviteRole("nope"))
}

func rbacInvCols() []string {
	return []string{"id", "team_id", "email", "role", "token", "invited_by", "expires_at", "accepted_at", "created_at"}
}

func rbacInvRow(accepted bool, expires time.Time) *sqlmock.Rows {
	var acc interface{}
	if accepted {
		acc = time.Now()
	}
	return sqlmock.NewRows(rbacInvCols()).AddRow(uuid.New(), uuid.New(), "a@b.com", "developer", "tok", uuid.New(), expires, acc, time.Now())
}

func TestCreateRBACInvitation_Branches(t *testing.T) {
	ctx := context.Background()

	db0, _ := newMock(t)
	_, err := CreateRBACInvitation(ctx, db0, uuid.New(), "  ", "developer", uuid.New())
	require.ErrorContains(t, err, "email required")

	db0b, _ := newMock(t)
	_, err = CreateRBACInvitation(ctx, db0b, uuid.New(), "a@b.com", "owner", uuid.New())
	require.ErrorIs(t, err, ErrInvalidInviteRole)

	// generateInviteToken error
	orig := generateInviteToken
	generateInviteToken = func() (string, error) { return "", errors.New("tokerr") }
	db1, _ := newMock(t)
	_, err = CreateRBACInvitation(ctx, db1, uuid.New(), "a@b.com", "developer", uuid.New())
	require.ErrorContains(t, err, "tokerr")
	generateInviteToken = orig

	// happy
	db, mock := newMock(t)
	mock.ExpectQuery(`INSERT INTO team_invitations`).WillReturnRows(rbacInvRow(false, time.Now().Add(time.Hour)))
	_, err = CreateRBACInvitation(ctx, db, uuid.New(), "a@b.com", "developer", uuid.New())
	require.NoError(t, err)

	// duplicate
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`INSERT INTO team_invitations`).WillReturnError(&pq.Error{Code: "23505"})
	_, err = CreateRBACInvitation(ctx, db2, uuid.New(), "a@b.com", "developer", uuid.New())
	require.ErrorIs(t, err, ErrDuplicatePendingInvite)

	// other error
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`INSERT INTO team_invitations`).WillReturnError(errors.New("boom"))
	_, err = CreateRBACInvitation(ctx, db3, uuid.New(), "a@b.com", "developer", uuid.New())
	require.ErrorContains(t, err, "boom")
}

func TestListRBACInvitations_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`FROM team_invitations`).WillReturnRows(rbacInvRow(false, time.Now().Add(time.Hour)))
	out, err := ListRBACInvitations(ctx, db, uuid.New())
	require.NoError(t, err)
	require.Len(t, out, 1)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM team_invitations`).WillReturnError(errors.New("qerr"))
	_, err = ListRBACInvitations(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "qerr")

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM team_invitations`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = ListRBACInvitations(ctx, db3, uuid.New())
	require.Error(t, err)

	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`FROM team_invitations`).WillReturnRows(rbacInvRow(false, time.Now().Add(time.Hour)).RowError(0, errors.New("rowerr")))
	_, err = ListRBACInvitations(ctx, db4, uuid.New())
	require.ErrorContains(t, err, "rowerr")
}

func TestGetRBACInvitationByID_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`FROM team_invitations WHERE id`).WillReturnRows(rbacInvRow(false, time.Now().Add(time.Hour)))
	_, err := GetRBACInvitationByID(ctx, db, uuid.New())
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM team_invitations WHERE id`).WillReturnError(errNoRows())
	_, err = GetRBACInvitationByID(ctx, db2, uuid.New())
	require.ErrorIs(t, err, ErrInvitationNotFound)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM team_invitations WHERE id`).WillReturnError(errors.New("boom"))
	_, err = GetRBACInvitationByID(ctx, db3, uuid.New())
	require.ErrorContains(t, err, "boom")
}

func TestGetRBACInvitationByToken_Branches(t *testing.T) {
	ctx := context.Background()

	db0, _ := newMock(t)
	_, err := GetRBACInvitationByToken(ctx, db0, "")
	require.ErrorIs(t, err, ErrInvitationTokenInvalid)

	db, mock := newMock(t)
	mock.ExpectQuery(`FROM team_invitations WHERE token`).WillReturnRows(rbacInvRow(false, time.Now().Add(time.Hour)))
	_, err = GetRBACInvitationByToken(ctx, db, "tok")
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM team_invitations WHERE token`).WillReturnError(errNoRows())
	_, err = GetRBACInvitationByToken(ctx, db2, "tok")
	require.ErrorIs(t, err, ErrInvitationNotFound)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM team_invitations WHERE token`).WillReturnError(errors.New("boom"))
	_, err = GetRBACInvitationByToken(ctx, db3, "tok")
	require.ErrorContains(t, err, "boom")
}

func TestRevokeRBACInvitation_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE team_invitations SET status = 'revoked'`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, RevokeRBACInvitation(ctx, db, uuid.New()))

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE team_invitations SET status = 'revoked'`).WillReturnResult(sqlmock.NewResult(0, 0))
	require.ErrorIs(t, RevokeRBACInvitation(ctx, db2, uuid.New()), ErrInvitationNotFound)

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE team_invitations SET status = 'revoked'`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, RevokeRBACInvitation(ctx, db3, uuid.New()), "boom")
}

func TestRBACInvitationStatus(t *testing.T) {
	var nilInv *RBACInvitation
	require.Equal(t, "", nilInv.Status())
	require.Equal(t, "accepted", (&RBACInvitation{AcceptedAt: nullTimeValid()}).Status())
	require.Equal(t, "expired", (&RBACInvitation{ExpiresAt: time.Now().Add(-time.Hour)}).Status())
	require.Equal(t, "pending", (&RBACInvitation{ExpiresAt: time.Now().Add(time.Hour)}).Status())
}

func TestAcceptRBACInvitationByToken_Branches(t *testing.T) {
	ctx := context.Background()

	// lookup error
	db0, mock0 := newMock(t)
	mock0.ExpectQuery(`FROM team_invitations WHERE token`).WillReturnError(errors.New("lkerr"))
	_, _, err := AcceptRBACInvitationByToken(ctx, db0, "tok")
	require.ErrorContains(t, err, "lkerr")

	// already accepted
	db1, mock1 := newMock(t)
	mock1.ExpectQuery(`FROM team_invitations WHERE token`).WillReturnRows(rbacInvRow(true, time.Now().Add(time.Hour)))
	_, _, err = AcceptRBACInvitationByToken(ctx, db1, "tok")
	require.ErrorIs(t, err, ErrInvitationAlreadyAccepted)

	// expired
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM team_invitations WHERE token`).WillReturnRows(rbacInvRow(false, time.Now().Add(-time.Hour)))
	_, _, err = AcceptRBACInvitationByToken(ctx, db3, "tok")
	require.ErrorIs(t, err, ErrInvitationExpired)

	// begin error
	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`FROM team_invitations WHERE token`).WillReturnRows(rbacInvRow(false, time.Now().Add(time.Hour)))
	mock4.ExpectBegin().WillReturnError(errors.New("beginerr"))
	_, _, err = AcceptRBACInvitationByToken(ctx, db4, "tok")
	require.ErrorContains(t, err, "beginerr")

	// update guard error
	db5, mock5 := newMock(t)
	mock5.ExpectQuery(`FROM team_invitations WHERE token`).WillReturnRows(rbacInvRow(false, time.Now().Add(time.Hour)))
	mock5.ExpectBegin()
	mock5.ExpectExec(`SET accepted_at = now\(\), status = 'accepted'`).WillReturnError(errors.New("upderr"))
	mock5.ExpectRollback()
	_, _, err = AcceptRBACInvitationByToken(ctx, db5, "tok")
	require.ErrorContains(t, err, "upderr")

	// update 0 rows -> already accepted
	db6, mock6 := newMock(t)
	mock6.ExpectQuery(`FROM team_invitations WHERE token`).WillReturnRows(rbacInvRow(false, time.Now().Add(time.Hour)))
	mock6.ExpectBegin()
	mock6.ExpectExec(`SET accepted_at = now\(\), status = 'accepted'`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock6.ExpectRollback()
	_, _, err = AcceptRBACInvitationByToken(ctx, db6, "tok")
	require.ErrorIs(t, err, ErrInvitationAlreadyAccepted)

	// happy: new user created
	db7, mock7 := newMock(t)
	mock7.ExpectQuery(`FROM team_invitations WHERE token`).WillReturnRows(rbacInvRow(false, time.Now().Add(time.Hour)))
	mock7.ExpectBegin()
	mock7.ExpectExec(`SET accepted_at = now\(\), status = 'accepted'`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock7.ExpectQuery(`FROM users WHERE lower\(email\)`).WillReturnError(errNoRows())
	mock7.ExpectQuery(`INSERT INTO users`).WillReturnRows(sqlmock.NewRows(userCols()).AddRow(uuid.New(), uuid.New(), "a@b.com", "developer", nil, nil, true, time.Now()))
	mock7.ExpectCommit()
	u, _, err := AcceptRBACInvitationByToken(ctx, db7, "tok")
	require.NoError(t, err)
	require.NotNil(t, u)

	// happy: existing user moved
	db8, mock8 := newMock(t)
	mock8.ExpectQuery(`FROM team_invitations WHERE token`).WillReturnRows(rbacInvRow(false, time.Now().Add(time.Hour)))
	mock8.ExpectBegin()
	mock8.ExpectExec(`SET accepted_at = now\(\), status = 'accepted'`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock8.ExpectQuery(`FROM users WHERE lower\(email\)`).WillReturnRows(sqlmock.NewRows(userCols()).AddRow(uuid.New(), uuid.New(), "a@b.com", "member", nil, nil, true, time.Now()))
	mock8.ExpectExec(`UPDATE users SET team_id = \$1, role = \$2`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock8.ExpectCommit()
	_, _, err = AcceptRBACInvitationByToken(ctx, db8, "tok")
	require.NoError(t, err)

	// existing user move error
	db9, mock9 := newMock(t)
	mock9.ExpectQuery(`FROM team_invitations WHERE token`).WillReturnRows(rbacInvRow(false, time.Now().Add(time.Hour)))
	mock9.ExpectBegin()
	mock9.ExpectExec(`SET accepted_at = now\(\), status = 'accepted'`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock9.ExpectQuery(`FROM users WHERE lower\(email\)`).WillReturnRows(sqlmock.NewRows(userCols()).AddRow(uuid.New(), uuid.New(), "a@b.com", "member", nil, nil, true, time.Now()))
	mock9.ExpectExec(`UPDATE users SET team_id = \$1, role = \$2`).WillReturnError(errors.New("moveerr"))
	mock9.ExpectRollback()
	_, _, err = AcceptRBACInvitationByToken(ctx, db9, "tok")
	require.ErrorContains(t, err, "moveerr")

	// user lookup transient error
	db10, mock10 := newMock(t)
	mock10.ExpectQuery(`FROM team_invitations WHERE token`).WillReturnRows(rbacInvRow(false, time.Now().Add(time.Hour)))
	mock10.ExpectBegin()
	mock10.ExpectExec(`SET accepted_at = now\(\), status = 'accepted'`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock10.ExpectQuery(`FROM users WHERE lower\(email\)`).WillReturnError(errors.New("usererr"))
	mock10.ExpectRollback()
	_, _, err = AcceptRBACInvitationByToken(ctx, db10, "tok")
	require.ErrorContains(t, err, "usererr")

	// insert user error
	db11, mock11 := newMock(t)
	mock11.ExpectQuery(`FROM team_invitations WHERE token`).WillReturnRows(rbacInvRow(false, time.Now().Add(time.Hour)))
	mock11.ExpectBegin()
	mock11.ExpectExec(`SET accepted_at = now\(\), status = 'accepted'`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock11.ExpectQuery(`FROM users WHERE lower\(email\)`).WillReturnError(errNoRows())
	mock11.ExpectQuery(`INSERT INTO users`).WillReturnError(errors.New("inserr"))
	mock11.ExpectRollback()
	_, _, err = AcceptRBACInvitationByToken(ctx, db11, "tok")
	require.ErrorContains(t, err, "inserr")

	// commit error
	db12, mock12 := newMock(t)
	mock12.ExpectQuery(`FROM team_invitations WHERE token`).WillReturnRows(rbacInvRow(false, time.Now().Add(time.Hour)))
	mock12.ExpectBegin()
	mock12.ExpectExec(`SET accepted_at = now\(\), status = 'accepted'`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock12.ExpectQuery(`FROM users WHERE lower\(email\)`).WillReturnRows(sqlmock.NewRows(userCols()).AddRow(uuid.New(), uuid.New(), "a@b.com", "member", nil, nil, true, time.Now()))
	mock12.ExpectExec(`UPDATE users SET team_id = \$1, role = \$2`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock12.ExpectCommit().WillReturnError(errors.New("commiterr"))
	_, _, err = AcceptRBACInvitationByToken(ctx, db12, "tok")
	require.ErrorContains(t, err, "commiterr")
}

func TestCountTeamOwners_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM users WHERE team_id = \$1 AND role = 'owner'`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	n, err := CountTeamOwners(ctx, db, uuid.New())
	require.NoError(t, err)
	require.Equal(t, 2, n)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`SELECT COUNT\(\*\) FROM users WHERE team_id = \$1 AND role = 'owner'`).WillReturnError(errors.New("boom"))
	_, err = CountTeamOwners(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "boom")
}

func TestEnsureNotLastOwner_Branches(t *testing.T) {
	ctx := context.Background()

	// role lookup error
	db, mock := newMock(t)
	mock.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users`).WillReturnError(errors.New("roleerr"))
	require.ErrorContains(t, EnsureNotLastOwner(ctx, db, uuid.New(), uuid.New()), "roleerr")

	// not an owner -> nil
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users`).WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("developer"))
	require.NoError(t, EnsureNotLastOwner(ctx, db2, uuid.New(), uuid.New()))

	// owner, count error
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users`).WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("owner"))
	mock3.ExpectQuery(`SELECT COUNT\(\*\) FROM users WHERE team_id = \$1 AND role = 'owner'`).WillReturnError(errors.New("cnterr"))
	require.ErrorContains(t, EnsureNotLastOwner(ctx, db3, uuid.New(), uuid.New()), "cnterr")

	// owner, last one -> ErrLastOwner
	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users`).WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("owner"))
	mock4.ExpectQuery(`SELECT COUNT\(\*\) FROM users WHERE team_id = \$1 AND role = 'owner'`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	require.ErrorIs(t, EnsureNotLastOwner(ctx, db4, uuid.New(), uuid.New()), ErrLastOwner)

	// owner, not last -> nil
	db5, mock5 := newMock(t)
	mock5.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users`).WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("owner"))
	mock5.ExpectQuery(`SELECT COUNT\(\*\) FROM users WHERE team_id = \$1 AND role = 'owner'`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	require.NoError(t, EnsureNotLastOwner(ctx, db5, uuid.New(), uuid.New()))
}
