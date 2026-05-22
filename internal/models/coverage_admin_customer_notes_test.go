package models

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestCreateAdminCustomerNote_Branches(t *testing.T) {
	ctx := context.Background()

	// empty body
	db, _ := newMock(t)
	_, err := CreateAdminCustomerNote(ctx, db, CreateAdminCustomerNoteParams{Body: "   "})
	require.ErrorIs(t, err, ErrAdminCustomerNoteEmpty)

	// too long
	db2, _ := newMock(t)
	_, err = CreateAdminCustomerNote(ctx, db2, CreateAdminCustomerNoteParams{Body: strings.Repeat("x", AdminCustomerNoteMaxBody+1)})
	require.ErrorIs(t, err, ErrAdminCustomerNoteTooLong)

	// happy
	db3, mock := newMock(t)
	mock.ExpectQuery(`INSERT INTO admin_customer_notes`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).AddRow(uuid.New(), time.Now()))
	got, err := CreateAdminCustomerNote(ctx, db3, CreateAdminCustomerNoteParams{TeamID: uuid.New(), Body: "hi", AuthorEmail: "a@b.com"})
	require.NoError(t, err)
	require.Equal(t, "hi", got.Body)

	// db error
	db4, mock := newMock(t)
	mock.ExpectQuery(`INSERT INTO admin_customer_notes`).WillReturnError(errors.New("boom"))
	_, err = CreateAdminCustomerNote(ctx, db4, CreateAdminCustomerNoteParams{Body: "x"})
	require.ErrorContains(t, err, "boom")
}

func TestListAdminCustomerNotes_Branches(t *testing.T) {
	ctx := context.Background()
	cols := []string{"id", "team_id", "body", "author_email", "created_at"}

	// clamps + happy
	db, mock := newMock(t)
	mock.ExpectQuery(`FROM admin_customer_notes`).
		WillReturnRows(sqlmock.NewRows(cols).AddRow(uuid.New(), uuid.New(), "b", "a@b.com", time.Now()))
	out, err := ListAdminCustomerNotes(ctx, db, uuid.New(), 0) // default limit
	require.NoError(t, err)
	require.Len(t, out, 1)

	db2, mock2 := newMock(t)
	mock2.ExpectQuery(`FROM admin_customer_notes`).WillReturnRows(sqlmock.NewRows(cols))
	_, err = ListAdminCustomerNotes(ctx, db2, uuid.New(), 99999) // over max
	require.NoError(t, err)

	// query error
	db3, mock3 := newMock(t)
	mock3.ExpectQuery(`FROM admin_customer_notes`).WillReturnError(errors.New("qerr"))
	_, err = ListAdminCustomerNotes(ctx, db3, uuid.New(), 10)
	require.ErrorContains(t, err, "qerr")

	// scan error
	db4, mock4 := newMock(t)
	mock4.ExpectQuery(`FROM admin_customer_notes`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	_, err = ListAdminCustomerNotes(ctx, db4, uuid.New(), 10)
	require.Error(t, err)

	// rows.Err()
	db5, mock5 := newMock(t)
	mock5.ExpectQuery(`FROM admin_customer_notes`).WillReturnRows(
		sqlmock.NewRows(cols).AddRow(uuid.New(), uuid.New(), "b", "a@b.com", time.Now()).RowError(0, errors.New("rowerr")))
	_, err = ListAdminCustomerNotes(ctx, db5, uuid.New(), 10)
	require.ErrorContains(t, err, "rowerr")
}

func TestDeleteAdminCustomerNote_Branches(t *testing.T) {
	ctx := context.Background()

	db, mock := newMock(t)
	mock.ExpectExec(`DELETE FROM admin_customer_notes`).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, DeleteAdminCustomerNote(ctx, db, uuid.New()))

	db2, mock2 := newMock(t)
	mock2.ExpectExec(`DELETE FROM admin_customer_notes`).WillReturnResult(sqlmock.NewResult(0, 0))
	require.ErrorIs(t, DeleteAdminCustomerNote(ctx, db2, uuid.New()), ErrAdminCustomerNoteNotFound)

	db3, mock3 := newMock(t)
	mock3.ExpectExec(`DELETE FROM admin_customer_notes`).WillReturnError(errors.New("boom"))
	require.ErrorContains(t, DeleteAdminCustomerNote(ctx, db3, uuid.New()), "boom")

	db4, mock4 := newMock(t)
	mock4.ExpectExec(`DELETE FROM admin_customer_notes`).WillReturnResult(sqlmock.NewErrorResult(errors.New("raerr")))
	require.ErrorContains(t, DeleteAdminCustomerNote(ctx, db4, uuid.New()), "raerr")
}
