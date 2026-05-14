package models_test

// audit_log_test.go — DB-backed tests covering the nullable team_id
// path introduced by migration 028. Skips when TEST_DATABASE_URL is
// unset so the suite runs cleanly without Postgres.
//
// Migration 028 dropped NOT NULL on audit_log.team_id. This test
// asserts:
//   1. A row with TeamID = uuid.Nil inserts and reads back with
//      team_id = NULL in Postgres.
//   2. A row with a real TeamID still inserts and reads back with
//      the matching team_id.
//   3. The team-scoped ListAuditEventsByTeam read does NOT see the
//      NULL-team row (Postgres equality semantics — admin-only rows).

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

func requireDBAudit(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
}

// seedTeam inserts a teams row and returns the id. Used by tests that
// need a real team for the non-nullable comparison case.
func seedTeam(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := db.QueryRow(`INSERT INTO teams (name) VALUES ('audit-test-team') RETURNING id`).Scan(&id)
	require.NoError(t, err)
	return id
}

func TestAuditLog_InsertWithNilTeamID_ReadsBackAsNull(t *testing.T) {
	requireDBAudit(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	// Insert with TeamID = uuid.Nil — simulates a pre-team event
	// (e.g. a failed session-token refresh during signup).
	err := models.InsertAuditEvent(context.Background(), db, models.AuditEvent{
		TeamID:  uuid.Nil,
		Actor:   "system",
		Kind:    "auth.login",
		Summary: "session-token refresh failed",
	})
	require.NoError(t, err, "InsertAuditEvent with uuid.Nil TeamID should succeed")

	// Read back directly — confirm team_id is actually NULL in the DB,
	// not the zero-UUID value masquerading as a real id.
	var teamID sql.NullString
	var actor, kind, summary string
	err = db.QueryRow(`
		SELECT team_id, actor, kind, summary
		  FROM audit_log
		 WHERE kind = 'auth.login' AND summary = 'session-token refresh failed'
		 ORDER BY created_at DESC LIMIT 1
	`).Scan(&teamID, &actor, &kind, &summary)
	require.NoError(t, err)
	assert.False(t, teamID.Valid, "expected team_id to be NULL, got %q", teamID.String)
	assert.Equal(t, "system", actor)
	assert.Equal(t, "auth.login", kind)
	assert.Equal(t, "session-token refresh failed", summary)
}

func TestAuditLog_InsertWithRealTeamID_StillWorks(t *testing.T) {
	requireDBAudit(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	teamID := seedTeam(t, db)
	err := models.InsertAuditEvent(context.Background(), db, models.AuditEvent{
		TeamID:  teamID,
		Actor:   "user",
		Kind:    "provision",
		Summary: "team event",
	})
	require.NoError(t, err)

	// Read back via the team-scoped accessor. Confirms the column
	// was populated correctly.
	events, err := models.ListAuditEventsByTeam(context.Background(), db, teamID, 10, "")
	require.NoError(t, err)
	require.NotEmpty(t, events)
	assert.Equal(t, teamID, events[0].TeamID)
	assert.Equal(t, "provision", events[0].Kind)
}

func TestAuditLog_NullTeamRows_NotVisibleInTeamScopedRead(t *testing.T) {
	requireDBAudit(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	teamID := seedTeam(t, db)

	// One NULL-team event + one real-team event.
	require.NoError(t, models.InsertAuditEvent(context.Background(), db, models.AuditEvent{
		TeamID: uuid.Nil, Actor: "system", Kind: "anon.audit", Summary: "ghost",
	}))
	require.NoError(t, models.InsertAuditEvent(context.Background(), db, models.AuditEvent{
		TeamID: teamID, Actor: "user", Kind: "provision", Summary: "real",
	}))

	// Team-scoped read should see ONLY the real-team event.
	events, err := models.ListAuditEventsByTeam(context.Background(), db, teamID, 10, "")
	require.NoError(t, err)
	for _, e := range events {
		assert.NotEqual(t, "anon.audit", e.Kind,
			"team-scoped read should NOT return NULL-team events (admin-only)")
	}
}
