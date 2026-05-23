package handlers_test

// audit_final2_test.go — FINAL SERIAL PASS #2 coverage for the audit.go
// serialization + parse arms the DB-error suite (audit_final_test.go) misses:
//
//   * parseAuditQuery bad-team-id → unauthorized   (audit.go L148-152)
//   * List happy path with metadata + resource_id + actor-email lookup
//     (auditEventToMap metadata-unmarshal L396-398, email placeholders/lookup L440-457)
//   * ListCSV happy path with a metadata-bearing row (CSV serialization L349-355)
//
// Seeds audit_log rows via models.InsertAuditEvent on a real DB and drives the
// live List / ListCSV handlers through the existing auditFaultApp seam.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

func auditF2NeedDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
}

// A JWT carrying a non-UUID team_id reaches the handler (RequireAuth doesn't
// validate UUID shape) → parseAuditQuery's uuid.Parse fails → unauthorized.
func TestAuditFinal2_BadTeamID_Unauthorized(t *testing.T) {
	auditF2NeedDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := auditFaultApp(t, seedDB)
	badJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), "not-a-uuid", "audf2@example.com")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer "+badJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAuditFinal2_List_Happy_WithMetadata(t *testing.T) {
	auditF2NeedDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRow(
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`, teamID, email).Scan(&userID))
	jwt := testhelpers.MustSignSessionJWT(t, userID, teamID, email)

	// Insert a row with metadata + resource_id so auditEventToMap runs the
	// metadata-unmarshal + the actor-email lookup placeholder builder.
	meta, _ := json.Marshal(map[string]any{"k": "v", "n": 1})
	require.NoError(t, models.InsertAuditEvent(context.Background(), db, models.AuditEvent{
		TeamID:       uuid.MustParse(teamID),
		UserID:       uuid.NullUUID{UUID: uuid.MustParse(userID), Valid: true},
		Actor:        userID,
		Kind:         "resource.created",
		ResourceType: "postgres",
		ResourceID:   uuid.NullUUID{UUID: uuid.New(), Valid: true},
		Summary:      "created a postgres resource",
		Metadata:     meta,
	}))

	app := auditFaultApp(t, db)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestAuditFinal2_ListCSV_Happy_WithMetadata(t *testing.T) {
	auditF2NeedDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRow(
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`, teamID, email).Scan(&userID))
	jwt := testhelpers.MustSignSessionJWT(t, userID, teamID, email)

	meta, _ := json.Marshal(map[string]any{"csv": "row"})
	require.NoError(t, models.InsertAuditEvent(context.Background(), db, models.AuditEvent{
		TeamID:       uuid.MustParse(teamID),
		UserID:       uuid.NullUUID{UUID: uuid.MustParse(userID), Valid: true},
		Actor:        userID,
		Kind:         "resource.deleted",
		ResourceType: "redis",
		ResourceID:   uuid.NullUUID{UUID: uuid.New(), Valid: true},
		Summary:      "deleted a redis resource",
		Metadata:     meta,
	}))

	app := auditFaultApp(t, db)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit.csv", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
