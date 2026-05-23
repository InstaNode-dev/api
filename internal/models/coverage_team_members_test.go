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

func TestNormalizeTeamEmail(t *testing.T) {
	require.Equal(t, "a@b.com", NormalizeTeamEmail("  A@B.com "))
}

func TestGetUserRole_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users`).WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("owner"))
	r, err := GetUserRole(ctx, db, uuid.New(), uuid.New())
	require.NoError(t, err)
	require.Equal(t, "owner", r)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users`).WillReturnError(errNoRows())
	r, err = GetUserRole(ctx, db2, uuid.New(), uuid.New())
	require.NoError(t, err)
	require.Empty(t, r)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users`).WillReturnError(errors.New("boom"))
	_, err = GetUserRole(ctx, db3, uuid.New(), uuid.New())
	require.ErrorContains(t, err, "boom")
}

func TestListTeamMembers_Branches(t *testing.T) {
	ctx := context.Background()
	cols := []string{"id", "email", "role", "created_at"}

	db, mock := newMock(t)
	mock.ExpectQuery(`FROM users WHERE team_id`).WillReturnRows(sqlmock.NewRows(cols).AddRow(uuid.New(), "a@b.com", "owner", time.Now()))
	out, err := ListTeamMembers(ctx, db, uuid.New())
	require.NoError(t, err)
	require.Len(t, out, 1)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM users WHERE team_id`).WillReturnError(errors.New("qerr"))
	_, err = ListTeamMembers(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "qerr")

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM users WHERE team_id`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = ListTeamMembers(ctx, db3, uuid.New())
	require.Error(t, err)

	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`FROM users WHERE team_id`).WillReturnRows(sqlmock.NewRows(cols).AddRow(uuid.New(), "a@b.com", "owner", time.Now()).RowError(0, errors.New("rowerr")))
	_, err = ListTeamMembers(ctx, db4, uuid.New())
	require.ErrorContains(t, err, "rowerr")
}

func TestCountTeamMembersAndPending_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM users WHERE team_id`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))
	n, err := CountTeamMembers(ctx, db, uuid.New())
	require.NoError(t, err)
	require.Equal(t, 3, n)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`SELECT COUNT\(\*\) FROM users WHERE team_id`).WillReturnError(errors.New("boom"))
	_, err = CountTeamMembers(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "boom")

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM team_invitations WHERE team_id = \$1 AND status = 'pending'`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	n, err = CountPendingInvitations(ctx, db3, uuid.New())
	require.NoError(t, err)
	require.Equal(t, 2, n)

	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`FROM team_invitations WHERE team_id = \$1 AND status = 'pending'`).WillReturnError(errors.New("boom"))
	_, err = CountPendingInvitations(ctx, db4, uuid.New())
	require.ErrorContains(t, err, "boom")
}

func invCols() []string {
	return []string{"id", "team_id", "email", "role", "status", "invited_by", "created_at", "expires_at"}
}

func TestInviteMember_Branches(t *testing.T) {
	ctx := context.Background()

	db0, _ := newMock(t)
	_, err := InviteMember(ctx, db0, uuid.New(), "  ", "member", uuid.New(), -1)
	require.ErrorContains(t, err, "email required")

	db0b, _ := newMock(t)
	_, err = InviteMember(ctx, db0b, uuid.New(), "a@b.com", "owner", uuid.New(), -1)
	require.ErrorIs(t, err, ErrInvalidInviteRole)

	// inviter role lookup error
	db1, mock1 := newMock(t)
	mock1.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users`).WillReturnError(errors.New("roleerr"))
	_, err = InviteMember(ctx, db1, uuid.New(), "a@b.com", "member", uuid.New(), -1)
	require.ErrorContains(t, err, "roleerr")

	// not owner
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users`).WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("member"))
	_, err = InviteMember(ctx, db2, uuid.New(), "a@b.com", "member", uuid.New(), -1)
	require.ErrorIs(t, err, ErrNotTeamOwner)

	// member limit reached (limit 0)
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users`).WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("owner"))
	mock3.ExpectQuery(`SELECT COUNT\(\*\) FROM users WHERE team_id`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock3.ExpectQuery(`FROM team_invitations WHERE team_id = \$1 AND status = 'pending'`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	_, err = InviteMember(ctx, db3, uuid.New(), "a@b.com", "member", uuid.New(), 0)
	require.ErrorIs(t, err, ErrMemberLimitReached)

	// within-limit count error
	db3b, mock3b := newMock(t)
	mock3b.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users`).WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("owner"))
	mock3b.ExpectQuery(`SELECT COUNT\(\*\) FROM users WHERE team_id`).WillReturnError(errors.New("cnterr"))
	_, err = InviteMember(ctx, db3b, uuid.New(), "a@b.com", "member", uuid.New(), 5)
	require.ErrorContains(t, err, "cnterr")

	// already a member
	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users`).WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("owner"))
	mock4.ExpectQuery(`SELECT COUNT\(\*\) FROM users WHERE team_id`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock4.ExpectQuery(`FROM team_invitations WHERE team_id = \$1 AND status = 'pending'`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock4.ExpectQuery(`SELECT COUNT\(\*\) FROM users WHERE team_id = \$1 AND lower\(email\)`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	_, err = InviteMember(ctx, db4, uuid.New(), "a@b.com", "member", uuid.New(), 10)
	require.ErrorIs(t, err, ErrAlreadyTeamMember)

	// happy (memberLimit -1 -> skips count queries)
	db5, mock5 := newMock(t)
	mock5.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users`).WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("owner"))
	mock5.ExpectQuery(`SELECT COUNT\(\*\) FROM users WHERE team_id = \$1 AND lower\(email\)`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock5.ExpectQuery(`INSERT INTO team_invitations`).WillReturnRows(sqlmock.NewRows(invCols()).AddRow(uuid.New(), uuid.New(), "a@b.com", "member", "pending", uuid.New(), time.Now(), time.Now().Add(time.Hour)))
	_, err = InviteMember(ctx, db5, uuid.New(), "a@b.com", "member", uuid.New(), -1)
	require.NoError(t, err)

	// duplicate invite (unique violation)
	db6, mock6 := newMock(t)
	mock6.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users`).WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("owner"))
	mock6.ExpectQuery(`SELECT COUNT\(\*\) FROM users WHERE team_id = \$1 AND lower\(email\)`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock6.ExpectQuery(`INSERT INTO team_invitations`).WillReturnError(&pq.Error{Code: "23505"})
	_, err = InviteMember(ctx, db6, uuid.New(), "a@b.com", "member", uuid.New(), -1)
	require.ErrorIs(t, err, ErrDuplicatePendingInvite)

	// insert other error
	db7, mock7 := newMock(t)
	mock7.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users`).WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("owner"))
	mock7.ExpectQuery(`SELECT COUNT\(\*\) FROM users WHERE team_id = \$1 AND lower\(email\)`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock7.ExpectQuery(`INSERT INTO team_invitations`).WillReturnError(errors.New("boom"))
	_, err = InviteMember(ctx, db7, uuid.New(), "a@b.com", "member", uuid.New(), -1)
	require.ErrorContains(t, err, "boom")
}

func TestListInvitations_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`FROM team_invitations`).WillReturnRows(sqlmock.NewRows(invCols()).AddRow(uuid.New(), uuid.New(), "a@b.com", "member", "pending", uuid.New(), time.Now(), time.Now()))
	out, err := ListInvitations(ctx, db, uuid.New())
	require.NoError(t, err)
	require.Len(t, out, 1)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM team_invitations`).WillReturnError(errors.New("qerr"))
	_, err = ListInvitations(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "qerr")

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM team_invitations`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = ListInvitations(ctx, db3, uuid.New())
	require.Error(t, err)

	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`FROM team_invitations`).WillReturnRows(sqlmock.NewRows(invCols()).AddRow(uuid.New(), uuid.New(), "a@b.com", "member", "pending", uuid.New(), time.Now(), time.Now()).RowError(0, errors.New("rowerr")))
	_, err = ListInvitations(ctx, db4, uuid.New())
	require.ErrorContains(t, err, "rowerr")
}

func TestGetInvitationByID_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`FROM team_invitations WHERE id`).WillReturnRows(sqlmock.NewRows(invCols()).AddRow(uuid.New(), uuid.New(), "a@b.com", "member", "pending", uuid.New(), time.Now(), time.Now()))
	_, err := GetInvitationByID(ctx, db, uuid.New())
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM team_invitations WHERE id`).WillReturnError(errNoRows())
	_, err = GetInvitationByID(ctx, db2, uuid.New())
	require.ErrorIs(t, err, ErrInvitationNotFound)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM team_invitations WHERE id`).WillReturnError(errors.New("boom"))
	_, err = GetInvitationByID(ctx, db3, uuid.New())
	require.ErrorContains(t, err, "boom")
}

func TestRevokeInvitation_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE team_invitations SET status = 'revoked'`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, RevokeInvitation(ctx, db, uuid.New()))

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE team_invitations SET status = 'revoked'`).WillReturnResult(sqlmock.NewResult(0, 0))
	require.ErrorIs(t, RevokeInvitation(ctx, db2, uuid.New()), ErrInvitationNotFound)

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE team_invitations SET status = 'revoked'`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, RevokeInvitation(ctx, db3, uuid.New()), "boom")
}

func invRowPending(email string, expires time.Time) *sqlmock.Rows {
	return sqlmock.NewRows(invCols()).AddRow(uuid.New(), uuid.New(), email, "member", "pending", uuid.New(), time.Now(), expires)
}

func TestAcceptInvitation_Branches(t *testing.T) {
	ctx := context.Background()

	// invitation lookup error
	db0, mock0 := newMock(t)
	mock0.ExpectQuery(`FROM team_invitations WHERE id`).WillReturnError(errors.New("invlookuperr"))
	_, err := AcceptInvitation(ctx, db0, uuid.New(), uuid.New(), -1)
	require.ErrorContains(t, err, "invlookuperr")

	// not pending
	db1, mock1 := newMock(t)
	mock1.ExpectQuery(`FROM team_invitations WHERE id`).WillReturnRows(sqlmock.NewRows(invCols()).AddRow(uuid.New(), uuid.New(), "a@b.com", "member", "accepted", uuid.New(), time.Now(), time.Now().Add(time.Hour)))
	_, err = AcceptInvitation(ctx, db1, uuid.New(), uuid.New(), -1)
	require.ErrorIs(t, err, ErrInvitationNotPending)

	// expired
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM team_invitations WHERE id`).WillReturnRows(invRowPending("a@b.com", time.Now().Add(-time.Hour)))
	_, err = AcceptInvitation(ctx, db2, uuid.New(), uuid.New(), -1)
	require.ErrorIs(t, err, ErrInvitationExpired)

	// user lookup error
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM team_invitations WHERE id`).WillReturnRows(invRowPending("a@b.com", time.Now().Add(time.Hour)))
	mock3.ExpectQuery(`FROM users WHERE id`).WillReturnError(errors.New("userlookuperr"))
	_, err = AcceptInvitation(ctx, db3, uuid.New(), uuid.New(), -1)
	require.ErrorContains(t, err, "userlookuperr")

	// email mismatch
	team := uuid.New()
	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`FROM team_invitations WHERE id`).WillReturnRows(sqlmock.NewRows(invCols()).AddRow(uuid.New(), team, "invitee@b.com", "member", "pending", uuid.New(), time.Now(), time.Now().Add(time.Hour)))
	mock4.ExpectQuery(`FROM users WHERE id`).WillReturnRows(sqlmock.NewRows(userCols()).AddRow(uuid.New(), team, "different@b.com", "member", nil, nil, false, time.Now()))
	_, err = AcceptInvitation(ctx, db4, uuid.New(), uuid.New(), -1)
	require.ErrorIs(t, err, ErrEmailMismatchInvite)

	// member limit reached (user not on team yet)
	uid := uuid.New()
	db5, mock5 := newMock(t)
	mock5.ExpectQuery(`FROM team_invitations WHERE id`).WillReturnRows(sqlmock.NewRows(invCols()).AddRow(uuid.New(), team, "a@b.com", "member", "pending", uuid.New(), time.Now(), time.Now().Add(time.Hour)))
	mock5.ExpectQuery(`FROM users WHERE id`).WillReturnRows(sqlmock.NewRows(userCols()).AddRow(uid, uuid.NullUUID{}, "a@b.com", "member", nil, nil, false, time.Now()))
	mock5.ExpectQuery(`SELECT COUNT\(\*\) FROM users WHERE team_id`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))
	_, err = AcceptInvitation(ctx, db5, uuid.New(), uid, 5)
	require.ErrorIs(t, err, ErrMemberLimitReached)

	// happy: member role
	db6, mock6 := newMock(t)
	mock6.ExpectQuery(`FROM team_invitations WHERE id`).WillReturnRows(sqlmock.NewRows(invCols()).AddRow(uuid.New(), team, "a@b.com", "member", "pending", uuid.New(), time.Now(), time.Now().Add(time.Hour)))
	mock6.ExpectQuery(`FROM users WHERE id`).WillReturnRows(sqlmock.NewRows(userCols()).AddRow(uid, uuid.NullUUID{}, "a@b.com", "member", nil, nil, false, time.Now()))
	mock6.ExpectQuery(`SELECT COUNT\(\*\) FROM users WHERE team_id`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock6.ExpectBegin()
	mock6.ExpectExec(`UPDATE users SET team_id = \$1, role = \$2, is_primary = false`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock6.ExpectExec(`UPDATE team_invitations SET status = 'accepted'`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock6.ExpectCommit()
	res, err := AcceptInvitation(ctx, db6, uuid.New(), uid, -1)
	require.NoError(t, err)
	require.Equal(t, "member", res.Role)

	// owner role -> demoted to member with warning (team already has owner)
	db7, mock7 := newMock(t)
	mock7.ExpectQuery(`FROM team_invitations WHERE id`).WillReturnRows(sqlmock.NewRows(invCols()).AddRow(uuid.New(), team, "a@b.com", "owner", "pending", uuid.New(), time.Now(), time.Now().Add(time.Hour)))
	mock7.ExpectQuery(`FROM users WHERE id`).WillReturnRows(sqlmock.NewRows(userCols()).AddRow(uid, uuid.NullUUID{UUID: team, Valid: true}, "a@b.com", "member", nil, nil, false, time.Now()))
	mock7.ExpectBegin()
	mock7.ExpectQuery(`SELECT COUNT\(\*\) FROM users WHERE team_id = \$1 AND role = 'owner'`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock7.ExpectExec(`UPDATE users SET team_id`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock7.ExpectExec(`UPDATE team_invitations SET status = 'accepted'`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock7.ExpectCommit()
	res, err = AcceptInvitation(ctx, db7, uuid.New(), uid, -1)
	require.NoError(t, err)
	require.Equal(t, "member", res.Role)
	require.NotEmpty(t, res.Warning)
}

func TestCreatePersonalTeamAndReassignUser_Branches(t *testing.T) {
	ctx := context.Background()

	// begin error
	db, mock := newMock(t)
	mock.ExpectBegin().WillReturnError(errors.New("beginerr"))
	_, err := CreatePersonalTeamAndReassignUser(ctx, db, uuid.New())
	require.ErrorContains(t, err, "beginerr")

	// email lookup error
	db2, mock2 := newMock(t)
	mock2.ExpectBegin()
	mock2.ExpectQuery(`SELECT email FROM users WHERE id`).WillReturnError(errors.New("emailerr"))
	mock2.ExpectRollback()
	_, err = CreatePersonalTeamAndReassignUser(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "emailerr")

	// team insert error
	db3, mock3 := newMock(t)
	mock3.ExpectBegin()
	mock3.ExpectQuery(`SELECT email FROM users WHERE id`).WillReturnRows(sqlmock.NewRows([]string{"email"}).AddRow("a@b.com"))
	mock3.ExpectQuery(`INSERT INTO teams`).WillReturnError(errors.New("teamerr"))
	mock3.ExpectRollback()
	_, err = CreatePersonalTeamAndReassignUser(ctx, db3, uuid.New())
	require.ErrorContains(t, err, "teamerr")

	// user update error
	db4, mock4 := newMock(t)
	mock4.ExpectBegin()
	mock4.ExpectQuery(`SELECT email FROM users WHERE id`).WillReturnRows(sqlmock.NewRows([]string{"email"}).AddRow("@b.com")) // empty local -> "Personal"
	mock4.ExpectQuery(`INSERT INTO teams`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	mock4.ExpectExec(`UPDATE users SET team_id = \$1, role = 'owner', is_primary = true`).WillReturnError(errors.New("usererr"))
	mock4.ExpectRollback()
	_, err = CreatePersonalTeamAndReassignUser(ctx, db4, uuid.New())
	require.ErrorContains(t, err, "usererr")

	// commit error
	db5, mock5 := newMock(t)
	mock5.ExpectBegin()
	mock5.ExpectQuery(`SELECT email FROM users WHERE id`).WillReturnRows(sqlmock.NewRows([]string{"email"}).AddRow("a@b.com"))
	mock5.ExpectQuery(`INSERT INTO teams`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	mock5.ExpectExec(`UPDATE users SET team_id`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock5.ExpectCommit().WillReturnError(errors.New("commiterr"))
	_, err = CreatePersonalTeamAndReassignUser(ctx, db5, uuid.New())
	require.ErrorContains(t, err, "commiterr")

	// happy
	newTeam := uuid.New()
	db6, mock6 := newMock(t)
	mock6.ExpectBegin()
	mock6.ExpectQuery(`SELECT email FROM users WHERE id`).WillReturnRows(sqlmock.NewRows([]string{"email"}).AddRow("a@b.com"))
	mock6.ExpectQuery(`INSERT INTO teams`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(newTeam))
	mock6.ExpectExec(`UPDATE users SET team_id`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock6.ExpectCommit()
	got, err := CreatePersonalTeamAndReassignUser(ctx, db6, uuid.New())
	require.NoError(t, err)
	require.Equal(t, newTeam, got)
}

func TestRemoveMember_Branches(t *testing.T) {
	ctx := context.Background()
	team := uuid.New()

	// not found
	db, mock := newMock(t)
	mock.ExpectQuery(`is_primary FROM users WHERE id`).WillReturnError(errNoRows())
	_, err := RemoveMember(ctx, db, team, uuid.New())
	var nf *ErrUserNotFound
	require.ErrorAs(t, err, &nf)

	// query error
	db1b, mock1b := newMock(t)
	mock1b.ExpectQuery(`is_primary FROM users WHERE id`).WillReturnError(errors.New("boom"))
	_, err = RemoveMember(ctx, db1b, team, uuid.New())
	require.ErrorContains(t, err, "boom")

	// is_primary -> refuse
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`is_primary FROM users WHERE id`).WillReturnRows(sqlmock.NewRows([]string{"role", "is_primary"}).AddRow("member", true))
	_, err = RemoveMember(ctx, db2, team, uuid.New())
	require.ErrorIs(t, err, ErrCannotRemovePrimary)

	// owner -> refuse
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`is_primary FROM users WHERE id`).WillReturnRows(sqlmock.NewRows([]string{"role", "is_primary"}).AddRow("owner", false))
	_, err = RemoveMember(ctx, db3, team, uuid.New())
	require.ErrorIs(t, err, ErrCannotRemoveOwner)

	// happy -> delegates to CreatePersonalTeamAndReassignUser
	newTeam := uuid.New()
	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`is_primary FROM users WHERE id`).WillReturnRows(sqlmock.NewRows([]string{"role", "is_primary"}).AddRow("member", false))
	mock4.ExpectBegin()
	mock4.ExpectQuery(`SELECT email FROM users WHERE id`).WillReturnRows(sqlmock.NewRows([]string{"email"}).AddRow("a@b.com"))
	mock4.ExpectQuery(`INSERT INTO teams`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(newTeam))
	mock4.ExpectExec(`UPDATE users SET team_id`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock4.ExpectCommit()
	got, err := RemoveMember(ctx, db4, team, uuid.New())
	require.NoError(t, err)
	require.Equal(t, newTeam, got)
}

func TestLeaveTeam_Branches(t *testing.T) {
	ctx := context.Background()
	team := uuid.New()

	// role lookup error
	db, mock := newMock(t)
	mock.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, LeaveTeam(ctx, db, team, uuid.New()), "boom")

	// not on team
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users`).WillReturnError(errNoRows())
	var nf *ErrUserNotFound
	require.ErrorAs(t, LeaveTeam(ctx, db2, team, uuid.New()), &nf)

	// owner cannot leave
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users`).WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("owner"))
	require.ErrorIs(t, LeaveTeam(ctx, db3, team, uuid.New()), ErrOwnerCannotLeave)

	// happy -> reassign
	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users`).WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("member"))
	mock4.ExpectBegin()
	mock4.ExpectQuery(`SELECT email FROM users WHERE id`).WillReturnRows(sqlmock.NewRows([]string{"email"}).AddRow("a@b.com"))
	mock4.ExpectQuery(`INSERT INTO teams`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	mock4.ExpectExec(`UPDATE users SET team_id`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock4.ExpectCommit()
	require.NoError(t, LeaveTeam(ctx, db4, team, uuid.New()))
}

func TestUpdateMemberRole_Branches(t *testing.T) {
	ctx := context.Background()
	team := uuid.New()

	db0, _ := newMock(t)
	_, err := UpdateMemberRole(ctx, db0, team, uuid.New(), "  ")
	require.ErrorIs(t, err, ErrInvalidMemberRole)

	db0b, _ := newMock(t)
	_, err = UpdateMemberRole(ctx, db0b, team, uuid.New(), RoleOwner)
	require.ErrorIs(t, err, ErrCannotAssignOwnerRole)

	db0c, _ := newMock(t)
	_, err = UpdateMemberRole(ctx, db0c, team, uuid.New(), "bogus")
	require.ErrorIs(t, err, ErrInvalidMemberRole)

	// happy
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE users SET role`).WillReturnResult(sqlmock.NewResult(0, 1))
	r, err := UpdateMemberRole(ctx, db, team, uuid.New(), RoleAdmin)
	require.NoError(t, err)
	require.Equal(t, RoleAdmin, r)

	// not on team
	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE users SET role`).WillReturnResult(sqlmock.NewResult(0, 0))
	_, err = UpdateMemberRole(ctx, db2, team, uuid.New(), RoleViewer)
	require.ErrorIs(t, err, ErrTargetNotOnTeam)

	// exec error
	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE users SET role`).WillReturnError(errors.New("boom"))
	_, err = UpdateMemberRole(ctx, db3, team, uuid.New(), RoleViewer)
	require.ErrorContains(t, err, "boom")
}

func TestPromoteMemberToPrimary_Branches(t *testing.T) {
	ctx := context.Background()
	team := uuid.New()

	// begin error
	db, mock := newMock(t)
	mock.ExpectBegin().WillReturnError(errors.New("beginerr"))
	require.ErrorContains(t, PromoteMemberToPrimary(ctx, db, team, uuid.New()), "beginerr")

	// target not on team
	db2, mock2 := newMock(t)
	mock2.ExpectBegin()
	mock2.ExpectQuery(`FOR UPDATE`).WillReturnError(errNoRows())
	mock2.ExpectRollback()
	require.ErrorIs(t, PromoteMemberToPrimary(ctx, db2, team, uuid.New()), ErrTargetNotOnTeam)

	// lookup error
	db2b, mock2b := newMock(t)
	mock2b.ExpectBegin()
	mock2b.ExpectQuery(`FOR UPDATE`).WillReturnError(errors.New("lkerr"))
	mock2b.ExpectRollback()
	require.ErrorContains(t, PromoteMemberToPrimary(ctx, db2b, team, uuid.New()), "lkerr")

	// already primary, role owner -> idempotent commit
	db3, mock3 := newMock(t)
	mock3.ExpectBegin()
	mock3.ExpectQuery(`FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"role", "is_primary"}).AddRow("owner", true))
	mock3.ExpectCommit()
	require.NoError(t, PromoteMemberToPrimary(ctx, db3, team, uuid.New()))

	// already primary, stale role -> fix to owner then commit
	db4, mock4 := newMock(t)
	mock4.ExpectBegin()
	mock4.ExpectQuery(`FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"role", "is_primary"}).AddRow("admin", true))
	mock4.ExpectExec(`UPDATE users SET role = 'owner'`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock4.ExpectCommit()
	require.NoError(t, PromoteMemberToPrimary(ctx, db4, team, uuid.New()))

	// already primary, stale role fix error
	db4b, mock4b := newMock(t)
	mock4b.ExpectBegin()
	mock4b.ExpectQuery(`FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"role", "is_primary"}).AddRow("admin", true))
	mock4b.ExpectExec(`UPDATE users SET role = 'owner'`).WillReturnError(errors.New("fixerr"))
	mock4b.ExpectRollback()
	require.ErrorContains(t, PromoteMemberToPrimary(ctx, db4b, team, uuid.New()), "fixerr")

	// not primary: demote error
	db5, mock5 := newMock(t)
	mock5.ExpectBegin()
	mock5.ExpectQuery(`FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"role", "is_primary"}).AddRow("member", false))
	mock5.ExpectExec(`SET is_primary = false, role = 'admin'`).WillReturnError(errors.New("demoteerr"))
	mock5.ExpectRollback()
	require.ErrorContains(t, PromoteMemberToPrimary(ctx, db5, team, uuid.New()), "demoteerr")

	// not primary: promote error
	db6, mock6 := newMock(t)
	mock6.ExpectBegin()
	mock6.ExpectQuery(`FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"role", "is_primary"}).AddRow("member", false))
	mock6.ExpectExec(`SET is_primary = false, role = 'admin'`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock6.ExpectExec(`SET is_primary = true, role = 'owner'`).WillReturnError(errors.New("promoteerr"))
	mock6.ExpectRollback()
	require.ErrorContains(t, PromoteMemberToPrimary(ctx, db6, team, uuid.New()), "promoteerr")

	// not primary: promote 0 rows -> not on team
	db7, mock7 := newMock(t)
	mock7.ExpectBegin()
	mock7.ExpectQuery(`FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"role", "is_primary"}).AddRow("member", false))
	mock7.ExpectExec(`SET is_primary = false, role = 'admin'`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock7.ExpectExec(`SET is_primary = true, role = 'owner'`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock7.ExpectRollback()
	require.ErrorIs(t, PromoteMemberToPrimary(ctx, db7, team, uuid.New()), ErrTargetNotOnTeam)

	// happy
	db8, mock8 := newMock(t)
	mock8.ExpectBegin()
	mock8.ExpectQuery(`FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"role", "is_primary"}).AddRow("member", false))
	mock8.ExpectExec(`SET is_primary = false, role = 'admin'`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock8.ExpectExec(`SET is_primary = true, role = 'owner'`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock8.ExpectCommit()
	require.NoError(t, PromoteMemberToPrimary(ctx, db8, team, uuid.New()))
}
