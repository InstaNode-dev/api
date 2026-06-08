package handlers

// onboarding_attach_resource_test.go — unit tests for attachClaimedResourceToTeam,
// the shared claim-time resource-attach helper. Pre-fix both call sites used
// `_, _ = h.db.ExecContext(...)`, swallowing the error and silently orphaning a
// resource after a successful claim. These tests pin that the error is now
// surfaced (and the happy / already-attached paths are unaffected). Uses sqlmock
// so the error path is covered without a live Postgres (no docker needed).

import (
	"context"
	"errors"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

func TestAttachClaimedResourceToTeam(t *testing.T) {
	teamID, resID := uuid.New(), uuid.New()

	t.Run("success", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock.New: %v", err)
		}
		defer func() { _ = db.Close() }()
		mock.ExpectExec(`UPDATE resources SET team_id`).
			WillReturnResult(sqlmock.NewResult(0, 1))
		if err := attachClaimedResourceToTeam(context.Background(), db, teamID, resID, "req-1"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("error is surfaced, not swallowed", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock.New: %v", err)
		}
		defer func() { _ = db.Close() }()
		mock.ExpectExec(`UPDATE resources SET team_id`).
			WillReturnError(errors.New("deadlock"))
		if err := attachClaimedResourceToTeam(context.Background(), db, teamID, resID, "req-1"); err == nil {
			t.Fatal("expected the attach error to be RETURNED (pre-fix it was silently swallowed, orphaning the resource)")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("already attached is a no-op (0 rows, no error)", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock.New: %v", err)
		}
		defer func() { _ = db.Close() }()
		// WHERE team_id IS NULL guard → 0 rows when already attached; not an error.
		mock.ExpectExec(`UPDATE resources SET team_id`).
			WillReturnResult(sqlmock.NewResult(0, 0))
		if err := attachClaimedResourceToTeam(context.Background(), db, teamID, resID, "req-1"); err != nil {
			t.Fatalf("0-rows (already attached) must not error: %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}
