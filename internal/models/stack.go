package models

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Stack represents a multi-service stack hosted on instant.dev (Phase 6).
//
// Env + ParentStackID were added in migration 015_stack_env.sql to support
// real env promotion as a Pro-tier feature (RETRO-2026-05-12 §10.17). Pre-
// migration stacks have Env="production" (column default) and ParentStackID
// nil. Promoted stacks point at the source via ParentStackID so the UI can
// group "production" / "staging" / "dev" copies of the same app together.
type Stack struct {
	ID            uuid.UUID
	TeamID        *uuid.UUID // nil for anonymous stacks
	Name          string
	Slug          string
	Namespace     string
	Status        string     // building|deploying|healthy|failed|stopped|deleting
	Tier          string
	Env           string     // production|staging|dev|... (default 'production')
	ParentStackID *uuid.UUID // nil for the root stack; set on promoted copies
	ExpiresAt     *time.Time // non-nil for anonymous stacks (24h TTL)
	Fingerprint   string     // set for anonymous stacks; used for dedup
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// StackService represents a single service within a Stack.
type StackService struct {
	ID        uuid.UUID
	StackID   uuid.UUID
	Name      string
	ImageTag  string
	Status    string // building|deploying|healthy|failed|stopped
	Expose    bool
	Port      int
	AppURL    string
	ErrorMsg  string
	CreatedAt time.Time
}

// CreateStackParams holds fields for inserting a new stack row.
//
// Env defaults to "production" when empty (matches the column default).
// ParentStackID is non-nil only for stacks created via the promote endpoint.
type CreateStackParams struct {
	TeamID        *uuid.UUID // nil for anonymous stacks
	Name          string
	Slug          string
	Tier          string
	Env           string     // empty → "production"
	ParentStackID *uuid.UUID // nil for root stacks; set when promoted
	ExpiresAt     *time.Time // non-nil for anonymous stacks
	Fingerprint   string     // set for anonymous stacks
}

// CreateStackServiceParams holds fields for inserting a new stack_service row.
type CreateStackServiceParams struct {
	StackID uuid.UUID
	Name    string
	Expose  bool
	Port    int
}

// ErrStackNotFound is returned when a stack lookup yields no rows.
type ErrStackNotFound struct{ Slug string }

func (e *ErrStackNotFound) Error() string { return "stack not found: " + e.Slug }

// GenerateStackSlug returns a random 8-char hex slug prefixed with "stk-".
// Example: "stk-a3b9c2d1"
func GenerateStackSlug() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("models.GenerateStackSlug: %w", err)
	}
	return "stk-" + hex.EncodeToString(b), nil
}

// scanStack reads a single stacks row into a Stack struct.
//
// Column order is fixed to:
//   id, team_id, name, slug, namespace, status, tier, env, parent_stack_id,
//   expires_at, fingerprint, created_at, updated_at
// — every query in this file must SELECT in this order.
func scanStack(row interface {
	Scan(dest ...any) error
}) (*Stack, error) {
	s := &Stack{}
	var teamID, parentID uuid.NullUUID
	var name, fingerprint, env sql.NullString
	var expiresAt sql.NullTime
	if err := row.Scan(
		&s.ID, &teamID, &name,
		&s.Slug, &s.Namespace, &s.Status, &s.Tier,
		&env, &parentID,
		&expiresAt, &fingerprint,
		&s.CreatedAt, &s.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if teamID.Valid {
		s.TeamID = &teamID.UUID
	}
	s.Name = name.String
	if env.Valid && env.String != "" {
		s.Env = env.String
	} else {
		s.Env = "production"
	}
	if parentID.Valid {
		s.ParentStackID = &parentID.UUID
	}
	if expiresAt.Valid {
		s.ExpiresAt = &expiresAt.Time
	}
	s.Fingerprint = fingerprint.String
	return s, nil
}

// scanStackService reads a single stack_services row into a StackService struct.
func scanStackService(row interface {
	Scan(dest ...any) error
}) (*StackService, error) {
	ss := &StackService{}
	var imageTag, appURL, errorMsg sql.NullString
	if err := row.Scan(
		&ss.ID, &ss.StackID, &ss.Name,
		&imageTag, &ss.Status, &ss.Expose, &ss.Port,
		&appURL, &errorMsg, &ss.CreatedAt,
	); err != nil {
		return nil, err
	}
	ss.ImageTag = imageTag.String
	ss.AppURL = appURL.String
	ss.ErrorMsg = errorMsg.String
	return ss, nil
}

// CreateStack inserts a new stack row. Namespace is set to "instant-stack-" + slug.
//
// Env defaults to "production" when CreateStackParams.Env is empty. ParentStackID
// is nullable — set only when the row is created by the promote endpoint.
func CreateStack(ctx context.Context, db *sql.DB, p CreateStackParams) (*Stack, error) {
	tier := p.Tier
	if tier == "" {
		tier = "hobby"
	}
	env := p.Env
	if env == "" {
		env = "production"
	}
	namespace := "instant-stack-" + p.Slug

	var nameVal, fingerprintVal interface{}
	if p.Name != "" {
		nameVal = p.Name
	}
	if p.Fingerprint != "" {
		fingerprintVal = p.Fingerprint
	}

	var teamIDVal interface{}
	if p.TeamID != nil {
		teamIDVal = *p.TeamID
	}

	var parentVal interface{}
	if p.ParentStackID != nil {
		parentVal = *p.ParentStackID
	}

	row := db.QueryRowContext(ctx, `
		INSERT INTO stacks (team_id, name, slug, namespace, tier, env, parent_stack_id, expires_at, fingerprint)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, team_id, name, slug, namespace, status, tier,
		          env, parent_stack_id,
		          expires_at, fingerprint, created_at, updated_at
	`, teamIDVal, nameVal, p.Slug, namespace, tier, env, parentVal, p.ExpiresAt, fingerprintVal)

	s, err := scanStack(row)
	if err != nil {
		return nil, fmt.Errorf("models.CreateStack: %w", err)
	}
	return s, nil
}

// GetStackBySlug returns a stack by its slug. Returns *ErrStackNotFound if missing.
func GetStackBySlug(ctx context.Context, db *sql.DB, slug string) (*Stack, error) {
	row := db.QueryRowContext(ctx, `
		SELECT id, team_id, name, slug, namespace, status, tier,
		       env, parent_stack_id,
		       expires_at, fingerprint, created_at, updated_at
		FROM stacks WHERE slug = $1
	`, slug)

	s, err := scanStack(row)
	if err == sql.ErrNoRows {
		return nil, &ErrStackNotFound{Slug: slug}
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetStackBySlug: %w", err)
	}
	return s, nil
}

// GetStackByID returns a stack by its primary key UUID.
func GetStackByID(ctx context.Context, db *sql.DB, id uuid.UUID) (*Stack, error) {
	row := db.QueryRowContext(ctx, `
		SELECT id, team_id, name, slug, namespace, status, tier,
		       env, parent_stack_id,
		       expires_at, fingerprint, created_at, updated_at
		FROM stacks WHERE id = $1
	`, id)

	s, err := scanStack(row)
	if err == sql.ErrNoRows {
		return nil, &ErrStackNotFound{Slug: id.String()}
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetStackByID: %w", err)
	}
	return s, nil
}

// GetStacksByTeam returns all stacks for a team, newest first.
func GetStacksByTeam(ctx context.Context, db *sql.DB, teamID uuid.UUID) ([]*Stack, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, team_id, name, slug, namespace, status, tier,
		       env, parent_stack_id,
		       expires_at, fingerprint, created_at, updated_at
		FROM stacks
		WHERE team_id = $1
		ORDER BY created_at DESC
	`, teamID)
	if err != nil {
		return nil, fmt.Errorf("models.GetStacksByTeam: %w", err)
	}
	defer rows.Close()

	var results []*Stack
	for rows.Next() {
		s, err := scanStack(rows)
		if err != nil {
			return nil, fmt.Errorf("models.GetStacksByTeam scan: %w", err)
		}
		results = append(results, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("models.GetStacksByTeam rows: %w", err)
	}
	return results, nil
}

// GetStackFamily returns every stack in the same env family as the given root.
// A "family" is: the stack itself + every stack whose parent_stack_id points
// at the root + the root's own parent (chain-up by one level for convenience).
// Used by the dashboard's "Environments" view on DeployDetailPage to surface
// production / staging / dev variants of the same app together.
//
// The cheap, correct definition: find the chain root (walk parent_stack_id
// until nil), then return every stack with parent_stack_id == root.id OR
// id == root.id. Callers stay team-scoped.
func GetStackFamily(ctx context.Context, db *sql.DB, teamID uuid.UUID, anyMemberID uuid.UUID) ([]*Stack, error) {
	// Step 1: resolve the root id with a recursive walk in a single query.
	// stacks rarely have deep parent chains (production usually IS the root),
	// so an iterative WITH RECURSIVE is overkill — a one-hop SELECT suffices.
	var rootID uuid.UUID
	err := db.QueryRowContext(ctx, `
		WITH RECURSIVE chain(id, parent_stack_id) AS (
			SELECT id, parent_stack_id FROM stacks WHERE id = $1 AND team_id = $2
			UNION ALL
			SELECT s.id, s.parent_stack_id
			  FROM stacks s
			  JOIN chain c ON c.parent_stack_id = s.id
			 WHERE s.team_id = $2
		)
		SELECT id FROM chain WHERE parent_stack_id IS NULL LIMIT 1
	`, anyMemberID, teamID).Scan(&rootID)
	if err == sql.ErrNoRows {
		// Caller's id isn't in the table or doesn't belong to the team — the
		// handler already checked ownership; treat as empty family.
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetStackFamily root walk: %w", err)
	}

	// Step 2: return root + all descendants (one level deep is enough for the
	// current promote endpoint, which only ever creates a direct child).
	rows, err := db.QueryContext(ctx, `
		SELECT id, team_id, name, slug, namespace, status, tier,
		       env, parent_stack_id,
		       expires_at, fingerprint, created_at, updated_at
		FROM stacks
		WHERE team_id = $1
		  AND (id = $2 OR parent_stack_id = $2)
		ORDER BY (id = $2) DESC, created_at ASC
	`, teamID, rootID)
	if err != nil {
		return nil, fmt.Errorf("models.GetStackFamily fetch: %w", err)
	}
	defer rows.Close()

	var results []*Stack
	for rows.Next() {
		s, err := scanStack(rows)
		if err != nil {
			return nil, fmt.Errorf("models.GetStackFamily scan: %w", err)
		}
		results = append(results, s)
	}
	return results, rows.Err()
}

// FindStackByEnvInFamily looks up a sibling stack with the same root + target
// env. Returns nil (not an error) when no sibling exists — callers use that
// to decide whether to update-in-place or create a new stack row.
func FindStackByEnvInFamily(ctx context.Context, db *sql.DB, teamID uuid.UUID, anyMemberID uuid.UUID, env string) (*Stack, error) {
	family, err := GetStackFamily(ctx, db, teamID, anyMemberID)
	if err != nil {
		return nil, err
	}
	for _, s := range family {
		if s.Env == env {
			return s, nil
		}
	}
	return nil, nil
}

// UpdateStackStatus updates status and updated_at for a stack.
// errMsg is accepted for API consistency (e.g. failure messages logged by callers)
// but is not persisted — the stacks table has no error_msg column; use
// UpdateStackServiceStatus to record per-service errors.
func UpdateStackStatus(ctx context.Context, db *sql.DB, id uuid.UUID, status, _ string) error {
	_, err := db.ExecContext(ctx, `
		UPDATE stacks
		SET status = $1, updated_at = now()
		WHERE id = $2
	`, status, id)
	if err != nil {
		return fmt.Errorf("models.UpdateStackStatus: %w", err)
	}
	return nil
}

// GetExpiredStacks returns anonymous stacks whose expires_at has passed and are
// still active (building|deploying|healthy). Used by the worker expiry job.
func GetExpiredStacks(ctx context.Context, db *sql.DB) ([]*Stack, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, team_id, name, slug, namespace, status, tier,
		       env, parent_stack_id,
		       expires_at, fingerprint, created_at, updated_at
		FROM stacks
		WHERE expires_at IS NOT NULL
		  AND expires_at < now()
		  AND status NOT IN ('deleted', 'deleting', 'failed', 'stopped')
	`)
	if err != nil {
		return nil, fmt.Errorf("models.GetExpiredStacks: %w", err)
	}
	defer rows.Close()

	var results []*Stack
	for rows.Next() {
		s, err := scanStack(rows)
		if err != nil {
			return nil, fmt.Errorf("models.GetExpiredStacks scan: %w", err)
		}
		results = append(results, s)
	}
	return results, rows.Err()
}

// DeleteStack hard-deletes the stack row. stack_services are cascade-deleted.
func DeleteStack(ctx context.Context, db *sql.DB, id uuid.UUID) error {
	_, err := db.ExecContext(ctx, `DELETE FROM stacks WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("models.DeleteStack: %w", err)
	}
	return nil
}

// CreateStackService inserts a new stack_service row.
func CreateStackService(ctx context.Context, db *sql.DB, p CreateStackServiceParams) (*StackService, error) {
	port := p.Port
	if port == 0 {
		port = 8080
	}

	row := db.QueryRowContext(ctx, `
		INSERT INTO stack_services (stack_id, name, expose, port)
		VALUES ($1, $2, $3, $4)
		RETURNING id, stack_id, name, image_tag, status, expose, port, app_url, error_msg, created_at
	`, p.StackID, p.Name, p.Expose, port)

	ss, err := scanStackService(row)
	if err != nil {
		return nil, fmt.Errorf("models.CreateStackService: %w", err)
	}
	return ss, nil
}

// GetStackServicesByStack returns all services for a stack, ordered by name.
func GetStackServicesByStack(ctx context.Context, db *sql.DB, stackID uuid.UUID) ([]*StackService, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, stack_id, name, image_tag, status, expose, port, app_url, error_msg, created_at
		FROM stack_services
		WHERE stack_id = $1
		ORDER BY name
	`, stackID)
	if err != nil {
		return nil, fmt.Errorf("models.GetStackServicesByStack: %w", err)
	}
	defer rows.Close()

	var results []*StackService
	for rows.Next() {
		ss, err := scanStackService(rows)
		if err != nil {
			return nil, fmt.Errorf("models.GetStackServicesByStack scan: %w", err)
		}
		results = append(results, ss)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("models.GetStackServicesByStack rows: %w", err)
	}
	return results, nil
}

// UpdateStackServiceStatus updates a stack_service's status, app_url, and error_msg.
// Pass empty strings for fields that should not change.
func UpdateStackServiceStatus(ctx context.Context, db *sql.DB, id uuid.UUID, status, appURL, errMsg string) error {
	var appURLVal, errMsgVal interface{}
	if appURL != "" {
		appURLVal = appURL
	}
	if errMsg != "" {
		errMsgVal = errMsg
	}
	_, err := db.ExecContext(ctx, `
		UPDATE stack_services
		SET status = $1, app_url = $2, error_msg = $3
		WHERE id = $4
	`, status, appURLVal, errMsgVal, id)
	if err != nil {
		return fmt.Errorf("models.UpdateStackServiceStatus: %w", err)
	}
	return nil
}

// UpdateStackServiceImageTag updates the image_tag for a stack service after a successful build.
func UpdateStackServiceImageTag(ctx context.Context, db *sql.DB, id uuid.UUID, imageTag string) error {
	_, err := db.ExecContext(ctx, `
		UPDATE stack_services SET image_tag = $1 WHERE id = $2
	`, imageTag, id)
	if err != nil {
		return fmt.Errorf("models.UpdateStackServiceImageTag: %w", err)
	}
	return nil
}
