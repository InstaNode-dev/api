package models

// deploys_audit.go — append-only deploy-identity log. One row per unique
// (service, commit_id, image_digest) tuple that has ever booted on this
// platform.
//
// Why a dedicated model (not folded into audit_log): audit_log is
// per-team — every row carries a team_id and FKs to teams.id. Deploy
// identity is platform-global; there is no team that "owns" a binary
// roll. We don't want to invent a sentinel team_id for the founder to
// hang these rows from, and we don't want NULLable team_id breaking the
// audit_log invariants. Separate table, separate read path.
//
// Write path: InsertSelfReport, called once at process startup.
// Idempotent via the unique index on (service, commit_id, image_digest).
//
// Read path: ListDeploys, called by the admin endpoint. Service +
// since-timestamp filters are pushed to SQL so the founder can answer
// "what was running yesterday afternoon" with one round-trip.

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Service identifiers stamped on deploy_audit rows. Hard-coded so the set
// of accepted values is reviewable here, not derived from caller input.
// The admin read endpoint validates against this set before pushing to
// the WHERE clause — never interpolate raw user input into SQL.
const (
	DeployServiceAPI         = "api"
	DeployServiceWorker      = "worker"
	DeployServiceProvisioner = "provisioner"
)

// ValidDeployServices is the closed set used for input validation on the
// admin endpoint. Stored as a map for O(1) lookup.
var ValidDeployServices = map[string]bool{
	DeployServiceAPI:         true,
	DeployServiceWorker:      true,
	DeployServiceProvisioner: true,
}

// NoticedBy enumerates how a row landed in the table. Self-report is the
// common case (the binary inserted itself on boot). Admin-import is for
// historical backfill — an operator filling in rows that pre-date the
// self-report code. The handler does not currently expose admin-import
// writes; the constant is here so the column's value space is documented
// in one place.
const (
	DeployNoticedBySelfReport  = "self-report"
	DeployNoticedByAdminImport = "admin-import"
)

// DeployAudit mirrors one row of the deploys_audit table. BuildTime is
// nullable because an un-ldflagged dev build emits the sentinel string
// "unknown" rather than a real RFC-3339 timestamp; the model parses
// "unknown" as nil so JSON responses surface null rather than a parse
// error.
type DeployAudit struct {
	ID               uuid.UUID
	Service          string
	CommitID         string
	ImageDigest      string
	Version          sql.NullString
	BuildTime        sql.NullTime
	AppliedAt        time.Time
	MigrationVersion sql.NullString
	NoticedBy        string
}

// SelfReportParams collects the fields that the startup-time insert
// needs. Bundled so callers don't pass an 8-positional argument list,
// and so future fields (e.g. a pod name or k8s namespace) can be added
// without breaking every caller.
type SelfReportParams struct {
	Service          string
	CommitID         string
	ImageDigest      string
	Version          string
	BuildTime        string // RFC-3339 from buildinfo, or "unknown"
	MigrationVersion string // highest migration filename present, or ""
}

// buildinfoUnknown is the sentinel string buildinfo emits for an
// un-ldflagged build. Stored as nullable in the DB rather than the
// literal "unknown" so consumers can distinguish "not set" from a real
// value without string-matching.
const buildinfoUnknown = "unknown"

// InsertSelfReport writes one row keyed on (service, commit_id,
// image_digest). The ON CONFLICT clause makes the call idempotent — a
// pod restart, an autoscale event, or a misfiring probe never produces a
// duplicate row. Returns nil on both fresh-insert and conflict-skip
// paths; the caller treats either as success.
//
// Failures here are non-fatal — the audit row is observability, not a
// correctness gate. main.go logs the error and continues.
func InsertSelfReport(ctx context.Context, db *sql.DB, p SelfReportParams) error {
	if strings.TrimSpace(p.Service) == "" {
		return fmt.Errorf("models.InsertSelfReport: service is required")
	}
	if strings.TrimSpace(p.CommitID) == "" {
		return fmt.Errorf("models.InsertSelfReport: commit_id is required")
	}
	if strings.TrimSpace(p.ImageDigest) == "" {
		return fmt.Errorf("models.InsertSelfReport: image_digest is required")
	}

	var versionArg interface{}
	if v := strings.TrimSpace(p.Version); v != "" && v != buildinfoUnknown && v != "dev" {
		versionArg = v
	}

	var buildTimeArg interface{}
	if bt := strings.TrimSpace(p.BuildTime); bt != "" && bt != buildinfoUnknown {
		if parsed, err := time.Parse(time.RFC3339, bt); err == nil {
			buildTimeArg = parsed.UTC()
		}
		// Unparseable build_time → NULL. Surface the row with a missing
		// timestamp rather than refusing to write it at all; the deploy
		// happened either way.
	}

	var migArg interface{}
	if mv := strings.TrimSpace(p.MigrationVersion); mv != "" {
		migArg = mv
	}

	_, err := db.ExecContext(ctx, `
		INSERT INTO deploys_audit (service, commit_id, image_digest, version, build_time, migration_version, noticed_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (service, commit_id, image_digest) DO NOTHING
	`, p.Service, p.CommitID, p.ImageDigest, versionArg, buildTimeArg, migArg, DeployNoticedBySelfReport)
	if err != nil {
		return fmt.Errorf("models.InsertSelfReport: %w", err)
	}
	return nil
}

// ListDeploysParams collects the filters supported by the admin GET
// endpoint. Zero-values map to "no filter applied" for service / since;
// Limit clamps to deployListMaxLimit on the read side so a caller asking
// for ?limit=1000000 still gets a bounded response.
type ListDeploysParams struct {
	Service string    // "" → all services; otherwise must be in ValidDeployServices
	Since   time.Time // zero → no since filter; non-zero → applied_at >= since
	Limit   int       // <= 0 → DeployListDefaultLimit; > DeployListMaxLimit → clamp
}

// DeployListDefaultLimit / DeployListMaxLimit shape the admin read
// surface. The default is small so an operator browsing a long history
// doesn't pull the whole table; the max cap defends against
// `?limit=999999`.
const (
	DeployListDefaultLimit = 50
	DeployListMaxLimit     = 500
)

// ListDeploys returns deploy_audit rows newest-first, optionally
// filtered by service and an absolute since-timestamp. Pagination is
// keyed off Limit alone — the table grows slowly (once per unique
// deploy, not per request) so offset-style scrolling is overkill.
//
// Returns an empty slice (never nil) when no rows match, so JSON
// serialization produces `[]` instead of `null`.
func ListDeploys(ctx context.Context, db *sql.DB, p ListDeploysParams) ([]*DeployAudit, error) {
	if p.Service != "" && !ValidDeployServices[p.Service] {
		return nil, fmt.Errorf("models.ListDeploys: invalid service %q", p.Service)
	}

	limit := p.Limit
	if limit <= 0 {
		limit = DeployListDefaultLimit
	}
	if limit > DeployListMaxLimit {
		limit = DeployListMaxLimit
	}

	args := []interface{}{}
	whereParts := []string{"1=1"}
	if p.Service != "" {
		args = append(args, p.Service)
		whereParts = append(whereParts, fmt.Sprintf("service = $%d", len(args)))
	}
	if !p.Since.IsZero() {
		args = append(args, p.Since.UTC())
		whereParts = append(whereParts, fmt.Sprintf("applied_at >= $%d", len(args)))
	}
	args = append(args, limit)

	query := fmt.Sprintf(`
		SELECT id, service, commit_id, image_digest, version, build_time,
		       applied_at, migration_version, noticed_by
		FROM deploys_audit
		WHERE %s
		ORDER BY applied_at DESC
		LIMIT $%d
	`, strings.Join(whereParts, " AND "), len(args))

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("models.ListDeploys: query: %w", err)
	}
	defer rows.Close()

	out := make([]*DeployAudit, 0, limit)
	for rows.Next() {
		d := &DeployAudit{}
		if err := rows.Scan(
			&d.ID, &d.Service, &d.CommitID, &d.ImageDigest, &d.Version,
			&d.BuildTime, &d.AppliedAt, &d.MigrationVersion, &d.NoticedBy,
		); err != nil {
			return nil, fmt.Errorf("models.ListDeploys: scan: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("models.ListDeploys: rows: %w", err)
	}
	return out, nil
}
