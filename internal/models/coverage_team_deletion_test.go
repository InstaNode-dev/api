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

func TestRequestTeamDeletion_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE teams`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, RequestTeamDeletion(ctx, db, uuid.New()))

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE teams`).WillReturnResult(sqlmock.NewResult(0, 0))
	require.ErrorIs(t, RequestTeamDeletion(ctx, db2, uuid.New()), ErrTeamNotPendingDeletion)

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE teams`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, RequestTeamDeletion(ctx, db3, uuid.New()), "boom")
}

func TestRestoreTeam_Branches(t *testing.T) {
	ctx := context.Background()

	// success
	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE teams`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, RestoreTeam(ctx, db, uuid.New()))

	// update error
	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE teams`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, RestoreTeam(ctx, db2, uuid.New()), "boom")

	// 0 rows -> disambiguate: not found
	db3, mock3 := newMock(t)
	mock3.ExpectExec(`UPDATE teams`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock3.ExpectQuery(`SELECT status, deletion_requested_at FROM teams`).WillReturnError(errNoRows())
	var nf *ErrTeamNotFound
	require.ErrorAs(t, RestoreTeam(ctx, db3, uuid.New()), &nf)

	// 0 rows -> disambiguate query error
	db4, mock4 := newMock(t)
	mock4.ExpectExec(`UPDATE teams`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock4.ExpectQuery(`SELECT status, deletion_requested_at FROM teams`).WillReturnError(errors.New("dboom"))
	require.ErrorContains(t, RestoreTeam(ctx, db4, uuid.New()), "dboom")

	// 0 rows -> status not pending
	db5, mock5 := newMock(t)
	mock5.ExpectExec(`UPDATE teams`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock5.ExpectQuery(`SELECT status, deletion_requested_at FROM teams`).
		WillReturnRows(sqlmock.NewRows([]string{"status", "deletion_requested_at"}).AddRow("active", nil))
	require.ErrorIs(t, RestoreTeam(ctx, db5, uuid.New()), ErrTeamNotPendingDeletion)

	// 0 rows -> grace expired (status pending but update missed)
	db6, mock6 := newMock(t)
	mock6.ExpectExec(`UPDATE teams`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock6.ExpectQuery(`SELECT status, deletion_requested_at FROM teams`).
		WillReturnRows(sqlmock.NewRows([]string{"status", "deletion_requested_at"}).AddRow(TeamStatusDeletionRequested, sql.NullTime{Time: time.Now().Add(-100 * 24 * time.Hour), Valid: true}))
	require.ErrorIs(t, RestoreTeam(ctx, db6, uuid.New()), ErrTeamRestoreGraceExpired)
}

func TestMarkTeamDeletionPending_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE teams`).WillReturnResult(sqlmock.NewResult(0, 1))
	ok, err := MarkTeamDeletionPending(ctx, db, uuid.New())
	require.NoError(t, err)
	require.True(t, ok)

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE teams`).WillReturnError(errors.New("boom"))
	_, err = MarkTeamDeletionPending(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "boom")
}

func TestTeamDeletionStatusDeletionAt(t *testing.T) {
	require.True(t, TeamDeletionStatus{}.DeletionAt().IsZero())
	now := time.Now()
	s := TeamDeletionStatus{DeletionRequestedAt: sql.NullTime{Time: now, Valid: true}}
	require.WithinDuration(t, now.Add(time.Duration(TeamDeletionGraceDays)*24*time.Hour), s.DeletionAt(), time.Second)
}

func TestGetTeamDeletionStatus_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectQuery(`FROM teams WHERE id`).
		WillReturnRows(sqlmock.NewRows([]string{"status", "deletion_requested_at", "tombstoned_at"}).AddRow("active", nil, nil))
	_, err := GetTeamDeletionStatus(ctx, db, uuid.New())
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM teams WHERE id`).WillReturnError(errNoRows())
	_, err = GetTeamDeletionStatus(ctx, db2, uuid.New())
	var nf *ErrTeamNotFound
	require.ErrorAs(t, err, &nf)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM teams WHERE id`).WillReturnError(errors.New("boom"))
	_, err = GetTeamDeletionStatus(ctx, db3, uuid.New())
	require.ErrorContains(t, err, "boom")
}

func TestResumeAllTeamResources_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectExec(`UPDATE resources`).WillReturnResult(sqlmock.NewResult(0, 3))
	n, err := ResumeAllTeamResources(ctx, db, uuid.New())
	require.NoError(t, err)
	require.Equal(t, int64(3), n)

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`UPDATE resources`).WillReturnError(errors.New("boom"))
	_, err = ResumeAllTeamResources(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "boom")
}

func TestTeamSlug(t *testing.T) {
	id := uuid.New()
	require.Equal(t, "MyTeam", TeamSlug(&Team{ID: id, Name: sql.NullString{String: "MyTeam", Valid: true}}))
	// empty name string -> fallback
	got := TeamSlug(&Team{ID: id, Name: sql.NullString{String: "", Valid: true}})
	require.Equal(t, "team-"+id.String()[:8], got)
	// invalid name -> fallback
	got = TeamSlug(&Team{ID: id})
	require.Equal(t, "team-"+id.String()[:8], got)
}
