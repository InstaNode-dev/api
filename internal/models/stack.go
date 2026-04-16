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
type Stack struct {
	ID          uuid.UUID
	TeamID      *uuid.UUID // nil for anonymous stacks
	Name        string
	Slug        string
	Namespace   string
	Status      string     // building|deploying|healthy|failed|stopped|deleting
	Tier        string
	ExpiresAt   *time.Time // non-nil for anonymous stacks (24h TTL)
	Fingerprint string     // set for anonymous stacks; used for dedup
	CreatedAt   time.Time
	UpdatedAt   time.Time
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
type CreateStackParams struct {
	TeamID      *uuid.UUID // nil for anonymous stacks
	Name        string
	Slug        string
	Tier        string
	ExpiresAt   *time.Time // non-nil for anonymous stacks
	Fingerprint string     // set for anonymous stacks
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
func scanStack(row interface {
	Scan(dest ...any) error
}) (*Stack, error) {
	s := &Stack{}
	var teamID uuid.NullUUID
	var name, fingerprint sql.NullString
	var expiresAt sql.NullTime
	if err := row.Scan(
		&s.ID, &teamID, &name,
		&s.Slug, &s.Namespace, &s.Status, &s.Tier,
		&expiresAt, &fingerprint,
		&s.CreatedAt, &s.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if teamID.Valid {
		s.TeamID = &teamID.UUID
	}
	s.Name = name.String
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
func CreateStack(ctx context.Context, db *sql.DB, p CreateStackParams) (*Stack, error) {
	tier := p.Tier
	if tier == "" {
		tier = "hobby"
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

	row := db.QueryRowContext(ctx, `
		INSERT INTO stacks (team_id, name, slug, namespace, tier, expires_at, fingerprint)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, team_id, name, slug, namespace, status, tier,
		          expires_at, fingerprint, created_at, updated_at
	`, teamIDVal, nameVal, p.Slug, namespace, tier, p.ExpiresAt, fingerprintVal)

	s, err := scanStack(row)
	if err != nil {
		return nil, fmt.Errorf("models.CreateStack: %w", err)
	}
	return s, nil
}

// GetStackBySlug returns a stack by its slug. Returns *ErrStackNotFound if missing.
func GetStackBySlug(ctx context.Context, db *sql.DB, slug string) (*Stack, error) {
	row := db.QueryRowContext(ctx, `
		SELECT id, team_id, name, slug, namespace, status, tier, expires_at, fingerprint, created_at, updated_at
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
		SELECT id, team_id, name, slug, namespace, status, tier, expires_at, fingerprint, created_at, updated_at
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
		SELECT id, team_id, name, slug, namespace, status, tier, expires_at, fingerprint, created_at, updated_at
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
