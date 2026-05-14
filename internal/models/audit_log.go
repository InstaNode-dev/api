package models

// audit_log.go — per-team event stream consumed by the dashboard's
// Recent Activity feed.
//
// Writes are best-effort: callers fire InsertAuditEvent in a goroutine
// and ignore the returned error. A failure to record an audit event
// must NEVER block a provision, claim, or rotate.
//
// Reads come from GET /api/v1/audit, capped at 200 rows per call.

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// auditMaxLimit caps the number of rows returned by ListAuditEventsByTeam.
// Keeps a single call from sweeping a large team's history; the dashboard
// uses limit=20 by default.
const auditMaxLimit = 200

// AuditEvent is one row in the audit_log table. Metadata is stored as
// raw JSONB bytes so callers can serialize arbitrary k/v without the
// model needing to know the shape.
//
// TeamID is the team that owns the event. Callers MAY pass uuid.Nil when
// the event fires before a team exists — e.g. an `auth.login` failure
// during signup, or an anonymous-tier action. uuid.Nil is translated to
// SQL NULL by InsertAuditEvent (the column is nullable as of migration
// 028). Dashboard reads filter by team_id = $1 which excludes NULLs in
// Postgres equality semantics, so legitimate per-team reads never see
// these admin-only rows.
type AuditEvent struct {
	ID           uuid.UUID
	TeamID       uuid.UUID
	UserID       uuid.NullUUID
	Actor        string
	Kind         string
	ResourceType string
	ResourceID   uuid.NullUUID
	Summary      string
	Metadata     []byte
	CreatedAt    time.Time
}

// InsertAuditEvent inserts a row best-effort. Callers should run this in
// a goroutine and ignore the error; an audit failure must never surface
// to the user. Defaults: Actor → "agent" when empty.
//
// TeamID semantics: uuid.Nil is treated as SQL NULL (migration 028 made
// the column nullable). This lets pre-team events like a failed signup
// audit-trail land without inventing a fake team id.
func InsertAuditEvent(ctx context.Context, db *sql.DB, ev AuditEvent) error {
	if ev.Actor == "" {
		ev.Actor = "agent"
	}
	// resource_type is NULL when empty (the column allows NULL).
	var resourceType interface{}
	if ev.ResourceType != "" {
		resourceType = ev.ResourceType
	}
	var metadata interface{}
	if len(ev.Metadata) > 0 {
		metadata = ev.Metadata
	}
	// team_id is NULL when uuid.Nil — for pre-team events.
	var teamID interface{}
	if ev.TeamID != uuid.Nil {
		teamID = ev.TeamID
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO audit_log (team_id, user_id, actor, kind, resource_type, resource_id, summary, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, teamID, ev.UserID, ev.Actor, ev.Kind, resourceType, ev.ResourceID, ev.Summary, metadata)
	if err != nil {
		return fmt.Errorf("models.InsertAuditEvent: %w", err)
	}
	return nil
}

// ListAuditEventsByTeam returns the most recent events for a team,
// newest first. kindFilter == "" means all kinds. Limit is capped at
// auditMaxLimit; non-positive limits default to 20.
func ListAuditEventsByTeam(ctx context.Context, db *sql.DB, teamID uuid.UUID, limit int, kindFilter string) ([]*AuditEvent, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > auditMaxLimit {
		limit = auditMaxLimit
	}

	var rows *sql.Rows
	var err error
	if kindFilter == "" {
		rows, err = db.QueryContext(ctx, `
			SELECT id, team_id, user_id, actor, kind, COALESCE(resource_type, ''), resource_id, summary, metadata, created_at
			FROM audit_log
			WHERE team_id = $1
			ORDER BY created_at DESC
			LIMIT $2
		`, teamID, limit)
	} else {
		rows, err = db.QueryContext(ctx, `
			SELECT id, team_id, user_id, actor, kind, COALESCE(resource_type, ''), resource_id, summary, metadata, created_at
			FROM audit_log
			WHERE team_id = $1 AND kind = $2
			ORDER BY created_at DESC
			LIMIT $3
		`, teamID, kindFilter, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("models.ListAuditEventsByTeam: %w", err)
	}
	defer rows.Close()

	out := make([]*AuditEvent, 0)
	for rows.Next() {
		ev := &AuditEvent{}
		var metadata sql.NullString
		if err := rows.Scan(
			&ev.ID, &ev.TeamID, &ev.UserID, &ev.Actor, &ev.Kind,
			&ev.ResourceType, &ev.ResourceID, &ev.Summary, &metadata, &ev.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("models.ListAuditEventsByTeam scan: %w", err)
		}
		if metadata.Valid {
			ev.Metadata = []byte(metadata.String)
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("models.ListAuditEventsByTeam rows: %w", err)
	}
	return out, nil
}
