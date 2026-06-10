package models

// team_members_invite_dup_error_test.go — covers the fail-closed branch added to
// InviteMember's "already a member" dup-check. Pre-fix the Scan error was
// swallowed (`_ = ...Scan(&existing)`), so a DB hiccup left existing=0 and the
// guard silently passed, inviting someone already on the team. The fix returns
// the error; this test pins it (memberLimit=-1 skips the limit COUNT queries, so
// the role lookup is followed directly by the email-dup COUNT).

import (
	"context"
	"errors"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

func TestInviteMember_EmailDupCheckError_FailsClosed(t *testing.T) {
	ctx := context.Background()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	// owner role → passes the owner gate.
	mock.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users`).
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("owner"))
	// memberLimit -1 skips withinMemberLimit's COUNT queries; the email-dup
	// COUNT is the next query — make it error.
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM users WHERE team_id = \$1 AND lower\(email\)`).
		WillReturnError(errors.New("dup-check db down"))

	_, err = InviteMember(ctx, db, uuid.New(), "a@b.com", "member", uuid.New(), -1)
	if err == nil {
		t.Fatal("InviteMember must FAIL CLOSED when the dup-check query errors (pre-fix it was swallowed and the invite proceeded blind)")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}
