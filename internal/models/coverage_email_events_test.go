package models

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestInsertEmailEvent_Branches(t *testing.T) {
	ctx := context.Background()
	raw := json.RawMessage(`{"message_id":"m1"}`)

	_, err := InsertEmailEvent(ctx, nil, "", "bounce", "a@b.com", "", raw)
	require.ErrorContains(t, err, "required")
	db0, _ := newMock(t)
	_, err = InsertEmailEvent(ctx, db0, "brevo", "bounce", "a@b.com", "", nil)
	require.ErrorContains(t, err, "raw payload required")

	// happy with reason
	db, mock := newMock(t)
	id := uuid.New()
	mock.ExpectQuery(`INSERT INTO email_events`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(id))
	got, err := InsertEmailEvent(ctx, db, "brevo", "bounce", "a@b.com", "hard", raw)
	require.NoError(t, err)
	require.Equal(t, id, got)

	// conflict path -> Nil, nil (empty reason)
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`INSERT INTO email_events`).WillReturnError(errNoRows())
	got, err = InsertEmailEvent(ctx, db2, "brevo", "bounce", "a@b.com", "", raw)
	require.NoError(t, err)
	require.Equal(t, uuid.Nil, got)

	// db error
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`INSERT INTO email_events`).WillReturnError(errors.New("boom"))
	_, err = InsertEmailEvent(ctx, db3, "brevo", "bounce", "a@b.com", "", raw)
	require.ErrorContains(t, err, "boom")
}

func TestHasSuppressionFor_Branches(t *testing.T) {
	ctx := context.Background()

	ok, err := HasSuppressionFor(ctx, nil, "")
	require.NoError(t, err)
	require.False(t, ok)

	// unsubscribe match (path 1)
	db, mock := newMock(t)
	mock.ExpectQuery(`event_type = \$2\s+LIMIT 1`).WillReturnRows(sqlmock.NewRows([]string{"?column?"}).AddRow(1))
	ok, err = HasSuppressionFor(ctx, db, "a@b.com")
	require.NoError(t, err)
	require.True(t, ok)

	// path 1 db error
	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`event_type = \$2\s+LIMIT 1`).WillReturnError(errors.New("u-boom"))
	_, err = HasSuppressionFor(ctx, db2, "a@b.com")
	require.ErrorContains(t, err, "u-boom")

	// path 1 no rows, path 2 match
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`event_type = \$2\s+LIMIT 1`).WillReturnError(errNoRows())
	mock3.ExpectQuery(`event_type = ANY`).WillReturnRows(sqlmock.NewRows([]string{"?column?"}).AddRow(1))
	ok, err = HasSuppressionFor(ctx, db3, "a@b.com")
	require.NoError(t, err)
	require.True(t, ok)

	// path 1 no rows, path 2 no rows
	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`event_type = \$2\s+LIMIT 1`).WillReturnError(errNoRows())
	mock4.ExpectQuery(`event_type = ANY`).WillReturnError(errNoRows())
	ok, err = HasSuppressionFor(ctx, db4, "a@b.com")
	require.NoError(t, err)
	require.False(t, ok)

	// path 2 db error
	db5, mock5 := newMock(t)
	mock5.ExpectQuery(`event_type = \$2\s+LIMIT 1`).WillReturnError(errNoRows())
	mock5.ExpectQuery(`event_type = ANY`).WillReturnError(errors.New("d-boom"))
	_, err = HasSuppressionFor(ctx, db5, "a@b.com")
	require.ErrorContains(t, err, "d-boom")
}

func TestClaimEmailSend_Branches(t *testing.T) {
	ctx := context.Background()

	ok, err := ClaimEmailSend(ctx, nil, "k", EmailSendKindReceipt)
	require.NoError(t, err)
	require.True(t, ok)

	db0, _ := newMock(t)
	ok, err = ClaimEmailSend(ctx, db0, "  ", EmailSendKindReceipt)
	require.NoError(t, err)
	require.True(t, ok)

	db, mock := newMock(t)
	mock.ExpectExec(`INSERT INTO email_send_dedup`).WillReturnResult(sqlmock.NewResult(0, 1))
	ok, err = ClaimEmailSend(ctx, db, "k", EmailSendKindDunning)
	require.NoError(t, err)
	require.True(t, ok)

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`INSERT INTO email_send_dedup`).WillReturnResult(sqlmock.NewResult(0, 0))
	ok, err = ClaimEmailSend(ctx, db2, "k", EmailSendKindDunning)
	require.NoError(t, err)
	require.False(t, ok)

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`INSERT INTO email_send_dedup`).WillReturnError(errors.New("boom"))
	_, err = ClaimEmailSend(ctx, db3, "k", EmailSendKindDunning)
	require.ErrorContains(t, err, "boom")
}

func TestRecentAuditEventExists_Branches(t *testing.T) {
	ctx := context.Background()

	ok, err := RecentAuditEventExists(ctx, nil, uuid.New(), "kind", 0)
	require.NoError(t, err)
	require.False(t, ok)

	db, mock := newMock(t)
	mock.ExpectQuery(`SELECT EXISTS`).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	ok, err = RecentAuditEventExists(ctx, db, uuid.New(), "kind", 60)
	require.NoError(t, err)
	require.True(t, ok)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`SELECT EXISTS`).WillReturnError(errors.New("boom"))
	_, err = RecentAuditEventExists(ctx, db2, uuid.New(), "kind", 60)
	require.ErrorContains(t, err, "boom")
}

func TestSuppressionChecker(t *testing.T) {
	ctx := context.Background()
	require.NotNil(t, NewSuppressionChecker(nil))

	var nilChecker *SuppressionChecker
	ok, err := nilChecker.IsSuppressed(ctx, "a@b.com")
	require.NoError(t, err)
	require.False(t, ok)

	ok, err = NewSuppressionChecker(nil).IsSuppressed(ctx, "a@b.com")
	require.NoError(t, err)
	require.False(t, ok)

	db, mock := newMock(t)
	mock.ExpectQuery(`event_type = \$2\s+LIMIT 1`).WillReturnRows(sqlmock.NewRows([]string{"?column?"}).AddRow(1))
	ok, err = NewSuppressionChecker(db).IsSuppressed(ctx, "a@b.com")
	require.NoError(t, err)
	require.True(t, ok)
}

func TestEmailDedupLedger(t *testing.T) {
	ctx := context.Background()
	require.NotNil(t, NewEmailDedupLedger(nil))

	var nilLedger *EmailDedupLedger
	ok, err := nilLedger.Sent(ctx, "k")
	require.NoError(t, err)
	require.False(t, ok)
	require.NoError(t, nilLedger.MarkSent(ctx, "k", "kind"))

	// nil db wrapper
	ok, err = NewEmailDedupLedger(nil).Sent(ctx, "k")
	require.NoError(t, err)
	require.False(t, ok)
	require.NoError(t, NewEmailDedupLedger(nil).MarkSent(ctx, "k", "kind"))

	db, mock := newMock(t)
	l := NewEmailDedupLedger(db)
	// empty key short circuits
	ok, err = l.Sent(ctx, "  ")
	require.NoError(t, err)
	require.False(t, ok)
	require.NoError(t, l.MarkSent(ctx, "  ", "kind"))

	mock.ExpectQuery(`SELECT EXISTS \(SELECT 1 FROM email_send_dedup`).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	ok, err = l.Sent(ctx, "k")
	require.NoError(t, err)
	require.True(t, ok)

	db2, mock2 := newMock(t)
	l2 := NewEmailDedupLedger(db2)
	mock2.ExpectQuery(`SELECT EXISTS \(SELECT 1 FROM email_send_dedup`).WillReturnError(errors.New("sboom"))
	_, err = l2.Sent(ctx, "k")
	require.ErrorContains(t, err, "sboom")

	db3, mock3 := newMock(t)
	l3 := NewEmailDedupLedger(db3)
	mock3.ExpectExec(`INSERT INTO email_send_dedup`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, l3.MarkSent(ctx, "k", "kind"))

	db4, mock4 := newMock(t)
	l4 := NewEmailDedupLedger(db4)
	mock4.ExpectExec(`INSERT INTO email_send_dedup`).WillReturnError(errors.New("mboom"))
	require.ErrorContains(t, l4.MarkSent(ctx, "k", "kind"), "mboom")
}
