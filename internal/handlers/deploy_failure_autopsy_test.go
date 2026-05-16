package handlers

// deploy_failure_autopsy_test.go — unit tests for the failure-autopsy
// serialisation path in deploymentToMapWithDB.
//
// Tests:
//   TestDeploymentToMap_NoFailureWhenHealthy      — healthy deployment → no "failure" key
//   TestDeploymentToMap_NoFailureWhenNoAutopsy    — failed but no autopsy row → no "failure" key
//   TestDeploymentToMap_FailureFieldPresent       — failed + autopsy row → "failure" present
//   TestDeploymentToMap_FailureFieldShape         — "failure" has all required contract fields
//   TestDeploymentToMap_ExitCodeNullable          — exit_code is nil when not set
//   TestDeploymentToMap_ExitCodeNonNull           — exit_code is int when set
//   TestDeploymentToMap_OmittedWhenStatusNotFailed — stopped/building/deploying have no "failure"

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"instant.dev/internal/models"
)

// buildTestDeployment returns a minimal Deployment in the given status.
func buildTestDeployment(status string) *models.Deployment {
	return &models.Deployment{
		ID:        uuid.New(),
		TeamID:    uuid.New(),
		AppID:     "testapp",
		Status:    status,
		Tier:      "pro",
		Env:       "production",
		Port:      8080,
		TTLPolicy: models.DeployTTLPolicyPermanent,
		EnvVars:   map[string]string{"_name": "My App"},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
}

// TestDeploymentToMap_NoFailureWhenHealthy checks that a healthy deployment
// does not hit the DB at all and returns no "failure" key.
func TestDeploymentToMap_NoFailureWhenHealthy(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	// No queries should be issued for a non-failed deployment.
	d := buildTestDeployment("healthy")
	m := deploymentToMapWithDB(d, db)

	if _, ok := m["failure"]; ok {
		t.Error("expected no 'failure' key for healthy deployment, but it was present")
	}

	// Ensure sqlmock has no unmet expectations (no DB calls happened).
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unexpected DB calls: %v", err)
	}
}

// TestDeploymentToMap_NoFailureWhenNoAutopsy checks that a failed deployment
// without an autopsy row in the DB does not include the "failure" key.
func TestDeploymentToMap_NoFailureWhenNoAutopsy(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	d := buildTestDeployment("failed")

	// DB returns no rows for the autopsy query.
	mock.ExpectQuery(`SELECT reason, exit_code, event, last_lines, hint, created_at`).
		WithArgs(d.ID, models.DeploymentEventKindFailureAutopsy).
		WillReturnRows(sqlmock.NewRows([]string{"reason", "exit_code", "event", "last_lines", "hint", "created_at"}))

	m := deploymentToMapWithDB(d, db)

	if _, ok := m["failure"]; ok {
		t.Error("expected no 'failure' key when no autopsy row exists, but it was present")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestDeploymentToMap_FailureFieldPresent checks that a failed deployment with
// an autopsy row includes the "failure" key.
func TestDeploymentToMap_FailureFieldPresent(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	d := buildTestDeployment("failed")
	occurredAt := time.Now().UTC().Add(-5 * time.Minute)
	lastLinesJSON, _ := json.Marshal([]string{"line1", "line2"})

	mock.ExpectQuery(`SELECT reason, exit_code, event, last_lines, hint, created_at`).
		WithArgs(d.ID, models.DeploymentEventKindFailureAutopsy).
		WillReturnRows(
			sqlmock.NewRows([]string{"reason", "exit_code", "event", "last_lines", "hint", "created_at"}).
				AddRow(
					models.FailureReasonCrashLoopBackOff,
					sql.NullInt32{Int32: 1, Valid: true},
					"CrashLoopBackOff: container restarted 5 times",
					lastLinesJSON,
					models.HintForReason(models.FailureReasonCrashLoopBackOff),
					occurredAt,
				),
		)

	m := deploymentToMapWithDB(d, db)

	if _, ok := m["failure"]; !ok {
		t.Fatal("expected 'failure' key to be present for failed deployment with autopsy")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestDeploymentToMap_FailureFieldShape checks that the "failure" object
// contains all contract fields (reason, exit_code, event, last_lines, hint,
// occurred_at). Verifies the exact contract expected by the dashboard.
func TestDeploymentToMap_FailureFieldShape(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	d := buildTestDeployment("failed")
	occurredAt := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	lastLinesJSON, _ := json.Marshal([]string{"error: cannot find module 'express'"})

	mock.ExpectQuery(`SELECT reason, exit_code, event, last_lines, hint, created_at`).
		WithArgs(d.ID, models.DeploymentEventKindFailureAutopsy).
		WillReturnRows(
			sqlmock.NewRows([]string{"reason", "exit_code", "event", "last_lines", "hint", "created_at"}).
				AddRow(
					models.FailureReasonBuildFailed,
					sql.NullInt32{Int32: 2, Valid: true},
					"kaniko job failed: step COPY failed",
					lastLinesJSON,
					models.HintForReason(models.FailureReasonBuildFailed),
					occurredAt,
				),
		)

	m := deploymentToMapWithDB(d, db)
	f, ok := m["failure"]
	if !ok {
		t.Fatal("expected 'failure' key")
	}

	// Re-encode to map[string]interface{} for field assertions.
	raw, _ := json.Marshal(f)
	var failure map[string]interface{}
	if err := json.Unmarshal(raw, &failure); err != nil {
		t.Fatalf("json.Unmarshal failure field: %v", err)
	}

	requiredFields := []string{"reason", "exit_code", "event", "last_lines", "hint", "occurred_at"}
	for _, field := range requiredFields {
		if _, present := failure[field]; !present {
			t.Errorf("failure object missing required field %q", field)
		}
	}

	if failure["reason"] != models.FailureReasonBuildFailed {
		t.Errorf("failure.reason = %v, want %q", failure["reason"], models.FailureReasonBuildFailed)
	}
	if failure["exit_code"].(float64) != 2 {
		t.Errorf("failure.exit_code = %v, want 2", failure["exit_code"])
	}
	if failure["occurred_at"] != "2026-05-16T12:00:00Z" {
		t.Errorf("failure.occurred_at = %v, want RFC3339 %q", failure["occurred_at"], "2026-05-16T12:00:00Z")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestDeploymentToMap_ExitCodeNullable checks that exit_code is null in the
// failure object when the autopsy row has no exit code.
func TestDeploymentToMap_ExitCodeNullable(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	d := buildTestDeployment("failed")
	occurredAt := time.Now().UTC()
	lastLinesJSON, _ := json.Marshal([]string{})

	mock.ExpectQuery(`SELECT reason, exit_code, event, last_lines, hint, created_at`).
		WithArgs(d.ID, models.DeploymentEventKindFailureAutopsy).
		WillReturnRows(
			sqlmock.NewRows([]string{"reason", "exit_code", "event", "last_lines", "hint", "created_at"}).
				AddRow(
					models.FailureReasonEvicted,
					sql.NullInt32{Valid: false}, // no exit code for evictions
					"Evicted: disk pressure",
					lastLinesJSON,
					models.HintForReason(models.FailureReasonEvicted),
					occurredAt,
				),
		)

	m := deploymentToMapWithDB(d, db)
	f := m["failure"]
	if f == nil {
		t.Fatal("expected 'failure' key")
	}

	raw, _ := json.Marshal(f)
	var failure map[string]interface{}
	_ = json.Unmarshal(raw, &failure)

	if exitCode, present := failure["exit_code"]; !present {
		t.Error("failure.exit_code key should be present even when null")
	} else if exitCode != nil {
		t.Errorf("failure.exit_code = %v, want nil for evicted pod", exitCode)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestDeploymentToMap_OmittedForNonFailedStatuses checks that statuses other
// than "failed" never include the "failure" key (no DB query issued).
func TestDeploymentToMap_OmittedForNonFailedStatuses(t *testing.T) {
	statuses := []string{"building", "deploying", "healthy", "stopped", "expired"}

	for _, status := range statuses {
		t.Run(status, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer db.Close()

			d := buildTestDeployment(status)
			m := deploymentToMapWithDB(d, db)

			if _, ok := m["failure"]; ok {
				t.Errorf("status=%q should not have a 'failure' key, but it was present", status)
			}

			// No DB queries should have fired.
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unexpected DB calls for status=%q: %v", status, err)
			}
		})
	}
}

// TestDeploymentToMap_NilDB checks that passing a nil db never panics and
// omits the "failure" key (the handler uses deploymentToMap, not the DB-aware
// version, in some paths).
func TestDeploymentToMap_NilDB(t *testing.T) {
	d := buildTestDeployment("failed")
	// deploymentToMap calls deploymentToMapWithDB(d, nil)
	m := deploymentToMap(d)
	if _, ok := m["failure"]; ok {
		t.Error("deploymentToMap (nil db path) should not include 'failure' key")
	}
}

// ── helpers ────────────────────────────────────────────────────────────────────

// GetLatestDeploymentAutopsy is exercised above via sqlmock. The test below
// verifies the SQL wires the correct constant in the WHERE clause.
func TestGetLatestDeploymentAutopsy_UsesKindConstant(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	id := uuid.New()

	// The query must pass DeploymentEventKindFailureAutopsy as the second arg.
	mock.ExpectQuery(`SELECT reason, exit_code, event, last_lines, hint, created_at`).
		WithArgs(id, models.DeploymentEventKindFailureAutopsy).
		WillReturnRows(sqlmock.NewRows([]string{"reason", "exit_code", "event", "last_lines", "hint", "created_at"}))

	row, err := models.GetLatestDeploymentAutopsy(context.Background(), db, id)
	if err != nil {
		t.Fatalf("GetLatestDeploymentAutopsy: %v", err)
	}
	if row != nil {
		t.Error("expected nil row for no-rows result")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}
