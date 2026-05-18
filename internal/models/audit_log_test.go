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
	"log/slog"
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

// captureHandler is a slog.Handler that records every Record it sees so a
// test can assert on the structured attributes of an emitted log line.
type captureHandler struct {
	records []slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.records = append(h.records, r)
	return nil
}
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

// attrMap flattens a slog.Record's attributes into a string-keyed map for
// easy assertion.
func attrMap(r slog.Record) map[string]slog.Value {
	m := make(map[string]slog.Value)
	r.Attrs(func(a slog.Attr) bool {
		m[a.Key] = a.Value
		return true
	})
	return m
}

// TestAuditLog_InsertEmitsSlogLineForNR is the P1-W3-01 regression: after a
// successful INSERT, InsertAuditEvent MUST emit an `audit.event` slog line so
// the audit event reaches New Relic Log. The kind MUST be logged under the
// key `audit_kind` (NOT `kind` — that collides with River's job kind). ~10 NR
// alerts query `audit_kind`; renaming the field silently breaks all of them.
func TestAuditLog_InsertEmitsSlogLineForNR(t *testing.T) {
	requireDBAudit(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	cap := &captureHandler{}
	prev := slog.Default()
	slog.SetDefault(slog.New(cap))
	defer slog.SetDefault(prev)

	teamID := seedTeam(t, db)
	resID := uuid.New()
	err := models.InsertAuditEvent(context.Background(), db, models.AuditEvent{
		TeamID:       teamID,
		Actor:        "agent",
		Kind:         "deploy.failed",
		ResourceType: "deployment",
		ResourceID:   uuid.NullUUID{UUID: resID, Valid: true},
		Summary:      "deploy failed",
	})
	require.NoError(t, err)

	// Find the audit.event line among captured records.
	var found *slog.Record
	for i := range cap.records {
		if cap.records[i].Message == "audit.event" {
			found = &cap.records[i]
			break
		}
	}
	require.NotNil(t, found, "InsertAuditEvent must emit an 'audit.event' slog line")

	m := attrMap(*found)
	// CRITICAL contract: the kind is logged under `audit_kind`, never `kind`.
	require.Contains(t, m, "audit_kind",
		"audit event kind MUST be logged under the key 'audit_kind' (NR alerts query this)")
	assert.NotContains(t, m, "kind",
		"the key 'kind' must NOT be used — it collides with River's job kind in NR Log")
	assert.Equal(t, "deploy.failed", m["audit_kind"].String())
	assert.Equal(t, "agent", m["actor"].String())
	assert.Equal(t, teamID.String(), m["team_id"].String())
	assert.Equal(t, "deployment", m["resource_type"].String())
	assert.Equal(t, resID.String(), m["resource_id"].String())
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
