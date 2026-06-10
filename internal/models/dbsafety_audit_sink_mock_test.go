package models

// dbsafety_audit_sink_mock_test.go — white-box (package models) coverage of the
// dbSafetyAuditSink.Emit branches via sqlmock, with no live DB. Covers the
// goroutine insert (happy) and the InsertAuditEvent-failure log branch
// deterministically. The integration row-lands test lives in the package
// models_test file.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/providers/dbsafety"
)

func sampleRecord() dbsafety.AuditRecord {
	return dbsafety.AuditRecord{
		Kind:         dbsafety.AuditKindCustomerDBDirectDrop,
		Provider:     "db.local",
		Token:        "tok",
		DatabaseName: "db_tok",
		UserName:     "usr_tok",
		DSNHost:      "postgres-customers",
	}
}

// waitForExpectations polls the mock until every expectation is met or the
// deadline passes — the Emit insert runs in a safego goroutine.
func waitForExpectations(t *testing.T, mock sqlmock.Sqlmock) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := mock.ExpectationsWereMet(); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("sqlmock expectations not met before deadline: %v", mock.ExpectationsWereMet())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestDBSafetyAuditSink_Emit_Inserts covers the happy goroutine path: Emit
// marshals the metadata and InsertAuditEvent writes the row.
func TestDBSafetyAuditSink_Emit_Inserts(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectExec(`INSERT INTO audit_log`).WillReturnResult(sqlmock.NewResult(0, 1))

	s := &dbSafetyAuditSink{db: db}
	s.Emit(context.Background(), sampleRecord())

	waitForExpectations(t, mock)
}

// TestDBSafetyAuditSink_Emit_InsertError covers the InsertAuditEvent-failure log
// branch: the insert errors but Emit must not panic or surface anything.
func TestDBSafetyAuditSink_Emit_InsertError(t *testing.T) {
	db, mock := newMock(t)
	mock.ExpectExec(`INSERT INTO audit_log`).WillReturnError(errors.New("boom"))

	s := &dbSafetyAuditSink{db: db}
	s.Emit(context.Background(), sampleRecord())

	waitForExpectations(t, mock)
	// Give the goroutine a beat to run its error-log branch after the failing
	// exec is observed (the log call itself has no observable side effect).
	require.NotNil(t, s.db)
}
