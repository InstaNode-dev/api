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

func TestGeneratePromoteApprovalToken(t *testing.T) {
	tok, err := GeneratePromoteApprovalToken()
	require.NoError(t, err)
	require.NotEmpty(t, tok)
}

func promoteApprovalCols() []string {
	return []string{"id", "token", "team_id", "requested_by_email", "promote_kind", "promote_payload", "from_env", "to_env", "status", "created_at", "expires_at", "approved_at", "executed_at", "rejected_at"}
}

func promoteApprovalRow() *sqlmock.Rows {
	return sqlmock.NewRows(promoteApprovalCols()).AddRow(uuid.New(), "tok", uuid.New(), "a@b.com", "stack", []byte(`{}`), "staging", "production", "pending", time.Now(), time.Now().Add(time.Hour), nil, nil, nil)
}

func TestCreatePromoteApproval_Branches(t *testing.T) {
	ctx := context.Background()

	// happy with ttl 0 -> default
	db, mock := newMock(t)
	mock.ExpectQuery(`INSERT INTO promote_approvals`).WillReturnRows(promoteApprovalRow())
	_, err := CreatePromoteApproval(ctx, db, CreatePromoteApprovalParams{Token: "tok", TeamID: uuid.New(), PromoteKind: PromoteApprovalKindStack})
	require.NoError(t, err)

	// with explicit ttl + error
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`INSERT INTO promote_approvals`).WillReturnError(errors.New("boom"))
	_, err = CreatePromoteApproval(ctx, db2, CreatePromoteApprovalParams{Token: "tok", TTL: time.Hour})
	require.ErrorContains(t, err, "boom")
}

func TestGetPromoteApprovalByToken_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`WHERE token`).WillReturnRows(promoteApprovalRow())
	_, err := GetPromoteApprovalByToken(ctx, db, "tok")
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`WHERE token`).WillReturnError(errNoRows())
	require.ErrorIs(t, func() error { _, e := GetPromoteApprovalByToken(ctx, db2, "tok"); return e }(), ErrPromoteApprovalNotFound)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`WHERE token`).WillReturnError(errors.New("boom"))
	_, err = GetPromoteApprovalByToken(ctx, db3, "tok")
	require.ErrorContains(t, err, "boom")
}

func TestGetPromoteApprovalByID_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectQuery(`FROM promote_approvals\s+WHERE id`).WillReturnRows(promoteApprovalRow())
	_, err := GetPromoteApprovalByID(ctx, db, uuid.New())
	require.NoError(t, err)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM promote_approvals\s+WHERE id`).WillReturnError(errNoRows())
	_, err = GetPromoteApprovalByID(ctx, db2, uuid.New())
	require.ErrorIs(t, err, ErrPromoteApprovalNotFound)

	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM promote_approvals\s+WHERE id`).WillReturnError(errors.New("boom"))
	_, err = GetPromoteApprovalByID(ctx, db3, uuid.New())
	require.ErrorContains(t, err, "boom")
}

func TestApprovePromoteApproval_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`SET status = 'approved'`).WillReturnResult(sqlmock.NewResult(0, 1))
	ok, err := ApprovePromoteApproval(ctx, db, uuid.New())
	require.NoError(t, err)
	require.True(t, ok)

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`SET status = 'approved'`).WillReturnResult(sqlmock.NewResult(0, 0))
	ok, err = ApprovePromoteApproval(ctx, db2, uuid.New())
	require.NoError(t, err)
	require.False(t, ok)

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`SET status = 'approved'`).WillReturnError(errors.New("boom"))
	_, err = ApprovePromoteApproval(ctx, db3, uuid.New())
	require.ErrorContains(t, err, "boom")

	db4, mock4 := newMock(t)
	mock4.ExpectExec(`SET status = 'approved'`).WillReturnResult(sqlmock.NewErrorResult(errors.New("raerr")))
	_, err = ApprovePromoteApproval(ctx, db4, uuid.New())
	require.ErrorContains(t, err, "raerr")
}

func TestMarkPromoteApprovalExpired_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`SET status = 'expired'`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, MarkPromoteApprovalExpired(ctx, db, uuid.New()))

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`SET status = 'expired'`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, MarkPromoteApprovalExpired(ctx, db2, uuid.New()), "boom")
}

func TestRejectPromoteApproval_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`SET status = 'rejected'`).WillReturnResult(sqlmock.NewResult(0, 1))
	ok, err := RejectPromoteApproval(ctx, db, uuid.New())
	require.NoError(t, err)
	require.True(t, ok)

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`SET status = 'rejected'`).WillReturnError(errors.New("boom"))
	_, err = RejectPromoteApproval(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "boom")

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`SET status = 'rejected'`).WillReturnResult(sqlmock.NewErrorResult(errors.New("raerr")))
	_, err = RejectPromoteApproval(ctx, db3, uuid.New())
	require.ErrorContains(t, err, "raerr")
}

func TestMarkPromoteApprovalExecuted_Branches(t *testing.T) {
	ctx := context.Background()
	db, mock := newMock(t)
	mock.ExpectExec(`SET status = 'executed'`).WillReturnResult(sqlmock.NewResult(0, 1))
	ok, err := MarkPromoteApprovalExecuted(ctx, db, uuid.New())
	require.NoError(t, err)
	require.True(t, ok)

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`SET status = 'executed'`).WillReturnError(errors.New("boom"))
	_, err = MarkPromoteApprovalExecuted(ctx, db2, uuid.New())
	require.ErrorContains(t, err, "boom")

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`SET status = 'executed'`).WillReturnResult(sqlmock.NewErrorResult(errors.New("raerr")))
	_, err = MarkPromoteApprovalExecuted(ctx, db3, uuid.New())
	require.ErrorContains(t, err, "raerr")
}

func TestListPromoteApprovals_Branches(t *testing.T) {
	ctx := context.Background()

	// no status filter + default limit
	db, mock := newMock(t)
	mock.ExpectQuery(`FROM promote_approvals\s+ORDER BY`).WillReturnRows(promoteApprovalRow())
	out, err := ListPromoteApprovals(ctx, db, ListPromoteApprovalsParams{})
	require.NoError(t, err)
	require.Len(t, out, 1)

	// status filter + over-max limit
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`WHERE status = \$1`).WillReturnRows(sqlmock.NewRows(promoteApprovalCols()))
	_, err = ListPromoteApprovals(ctx, db2, ListPromoteApprovalsParams{Status: "pending", Limit: 9999})
	require.NoError(t, err)

	// query error
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM promote_approvals`).WillReturnError(errors.New("qerr"))
	_, err = ListPromoteApprovals(ctx, db3, ListPromoteApprovalsParams{})
	require.ErrorContains(t, err, "qerr")

	// scan error
	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`FROM promote_approvals`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = ListPromoteApprovals(ctx, db4, ListPromoteApprovalsParams{})
	require.Error(t, err)

	// rows.Err()
	db5, mock5 := newMock(t)
	mock5.ExpectQuery(`FROM promote_approvals`).WillReturnRows(promoteApprovalRow().RowError(0, errors.New("rowerr")))
	_, err = ListPromoteApprovals(ctx, db5, ListPromoteApprovalsParams{})
	require.ErrorContains(t, err, "rowerr")
}
