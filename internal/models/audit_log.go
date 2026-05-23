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
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// auditMaxLimit caps the number of rows returned by ListAuditEventsByTeam.
// Keeps a single call from sweeping a large team's history; the dashboard
// uses limit=20 by default.
const auditMaxLimit = 200

// auditLogMsg is the slog message every audit event is logged under. NR Log
// alerts/dashboards filter on `message='audit.event'`, then on the
// per-event-kind `audit_kind` attribute (see auditLogKindField).
const auditLogMsg = "audit.event"

// auditLogKindField is the slog attribute key under which the audit event's
// kind is logged. It is DELIBERATELY `audit_kind` and NOT `kind`: River's
// job-middleware slog lines already log a `kind` attribute (the River job
// kind), so reusing `kind` here would collide in NR Log and make per-kind
// audit alerts ambiguous. The infra repo's NR alerts query this exact
// attribute name — do not rename it without updating those alerts in lockstep.
const auditLogKindField = "audit_kind"

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

	// Emit a structured slog line so the audit event reaches New Relic Log.
	// The Postgres row alone is invisible to NR — ~10 NR alerts and the
	// billing-dunning dashboard filter `FROM Log WHERE audit_kind=...`, and
	// without this line that field source never exists (P1-W3-01).
	//
	// The kind is logged under `audit_kind`, NOT `kind`: the River worker's
	// job middleware already emits a `kind` attribute, and reusing it here
	// would collide. The infra repo's NR alerts query `audit_kind` exactly.
	attrs := []any{
		auditLogKindField, ev.Kind,
		"actor", ev.Actor,
	}
	if ev.TeamID != uuid.Nil {
		attrs = append(attrs, "team_id", ev.TeamID.String())
	}
	if ev.ResourceType != "" {
		attrs = append(attrs, "resource_type", ev.ResourceType)
	}
	if ev.ResourceID.Valid {
		attrs = append(attrs, "resource_id", ev.ResourceID.UUID.String())
	}
	slog.InfoContext(ctx, auditLogMsg, attrs...)

	return nil
}

// SubscriptionChangeAuditExists reports whether a subscription-change
// audit row (subscription.upgraded / subscription.downgraded) already
// exists for the given (team_id, kind, subscription_id) triple.
//
// F9 (billing-trust audit 2026-05-19): the Razorpay webhook's up-front
// dedup claim is fail-open — if the claim INSERT itself errors during a
// DB brownout, two concurrent deliveries of the same subscription.charged
// event can both dispatch, each emitting a subscription.upgraded audit row
// and so triggering a duplicate upgrade-confirmation email. This lookup
// lets emitSubscriptionChangeAudit skip the second insert when an
// identical row is already present, making the audit emit idempotent on
// (team_id, kind, subscription_id) and suppressing the duplicate email.
//
// subscriptionID is matched against metadata->>'subscription_id' (the key
// emitSubscriptionChangeAudit writes). An empty subscriptionID always
// returns false: with no stable key there is nothing to dedup on, so the
// caller falls back to the prior always-insert behaviour.
func SubscriptionChangeAuditExists(ctx context.Context, db *sql.DB, teamID uuid.UUID, kind, subscriptionID string) (bool, error) {
	if subscriptionID == "" {
		return false, nil
	}
	var exists bool
	err := db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM audit_log
			 WHERE team_id = $1
			   AND kind = $2
			   AND metadata->>'subscription_id' = $3
		)
	`, teamID, kind, subscriptionID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("models.SubscriptionChangeAuditExists: %w", err)
	}
	return exists, nil
}

// AuditCustomerExportQuery is the parameter bundle for
// ListAuditEventsForCustomerExport. Carries every dial the public
// GET /api/v1/audit endpoint exposes — kept as a struct (not positional
// args) so future filters (resource_id, actor) don't ripple through
// every call site.
type AuditCustomerExportQuery struct {
	TeamID    uuid.UUID
	Limit     int       // capped at auditMaxLimit
	Before    time.Time // cursor: rows strictly older than this; zero means "no cursor"
	Kind      string    // exact match; "" means all (excluding admin.* — see below)
	Since     time.Time // inclusive lower bound; zero means "no lower bound"
	Until     time.Time // exclusive upper bound; zero means "no upper bound"
	LookbackS int64     // tier-derived lower bound in seconds; 0 means "unlimited"
}

// ListAuditEventsForCustomerExport returns audit rows scoped to a single
// team's surface, suitable for the customer-facing GET /api/v1/audit
// endpoint. Distinct from ListAuditEventsByTeam:
//
//   - Excludes any row whose kind starts with `admin.` — these are
//     internal-compliance rows about operator access, not customer-facing
//     transparency. Returning them would leak how the operator tooling
//     is shaped (a path-prefix probing primitive).
//   - Includes rows where the actor is the team (team_id = caller_team)
//     OR the row's metadata->>'resource_id' resolves to a resource the
//     team owns. The latter covers the case where a different actor
//     (operator, automation) acted on the team's resource — A4's
//     nullable team_id pattern.
//   - Supports cursor-style pagination via `before` on created_at.
//   - Supports time-range filtering (since/until) AND a tier-derived
//     hard lookback floor — Team is unbounded, Pro is 90 days, Hobby is
//     30 days. Anonymous/free never hits this path (the handler returns
//     402 before calling the model).
//
// Returns rows newest-first, capped at AuditExportMaxLimit (200).
func ListAuditEventsForCustomerExport(ctx context.Context, db *sql.DB, q AuditCustomerExportQuery) ([]*AuditEvent, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > auditMaxLimit {
		limit = auditMaxLimit
	}

	// Build dynamic WHERE clause. Args is parallel to $N placeholders.
	// Anchor predicates:
	//   $1  team_id (used twice: direct team_id match OR resource ownership)
	//   $2  limit
	// Optional predicates appended in order; index tracked via len(args).
	args := []interface{}{q.TeamID}
	// Note: we don't include teamID twice in args list; the SQL re-uses $1
	// in the EXISTS subquery via a literal $1 reference (parameterised
	// queries reuse positional markers).

	// admin.* exclusion is a hard rule — never returned regardless of
	// caller filter. If the caller passed kind=admin.something, the query
	// returns zero rows (the admin.* filter combined with the prefix
	// exclusion produces an empty intersection).
	query := `
		SELECT id, team_id, user_id, actor, kind, COALESCE(resource_type, ''), resource_id, summary, metadata, created_at
		  FROM audit_log
		 WHERE (
		         team_id = $1
		      OR (metadata IS NOT NULL
		          AND metadata ? 'resource_id'
		          AND EXISTS (
		                SELECT 1 FROM resources r
		                 WHERE r.team_id = $1
		                   AND r.id::text = metadata->>'resource_id'
		          )
		         )
		       )
		   AND kind NOT LIKE 'admin.%'`

	if q.Kind != "" {
		args = append(args, q.Kind)
		query += fmt.Sprintf(" AND kind = $%d", len(args))
	}
	if !q.Before.IsZero() {
		args = append(args, q.Before)
		query += fmt.Sprintf(" AND created_at < $%d", len(args))
	}
	if !q.Since.IsZero() {
		args = append(args, q.Since)
		query += fmt.Sprintf(" AND created_at >= $%d", len(args))
	}
	if !q.Until.IsZero() {
		args = append(args, q.Until)
		query += fmt.Sprintf(" AND created_at < $%d", len(args))
	}
	if q.LookbackS > 0 {
		// Hard tier floor — independent of `since`. If the caller passed
		// since=older-than-floor, the floor still wins.
		args = append(args, q.LookbackS)
		query += fmt.Sprintf(" AND created_at >= now() - ($%d * interval '1 second')", len(args))
	}

	args = append(args, limit)
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", len(args))

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("models.ListAuditEventsForCustomerExport: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]*AuditEvent, 0)
	for rows.Next() {
		ev := &AuditEvent{}
		var metadata sql.NullString
		if err := rows.Scan(
			&ev.ID, &ev.TeamID, &ev.UserID, &ev.Actor, &ev.Kind,
			&ev.ResourceType, &ev.ResourceID, &ev.Summary, &metadata, &ev.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("models.ListAuditEventsForCustomerExport scan: %w", err)
		}
		if metadata.Valid {
			ev.Metadata = []byte(metadata.String)
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("models.ListAuditEventsForCustomerExport rows: %w", err)
	}
	return out, nil
}

// AuditExportMaxLimit is the public, capped page size for the customer
// export endpoint. Exported so the handler can document it in OpenAPI
// without duplicating the constant.
const AuditExportMaxLimit = auditMaxLimit

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
	defer func() { _ = rows.Close() }()

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
