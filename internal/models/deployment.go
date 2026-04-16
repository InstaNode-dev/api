package models

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Deployment represents a user app hosted on instant.dev infrastructure (Phase 6).
type Deployment struct {
	ID           uuid.UUID
	TeamID       uuid.UUID
	ResourceID   uuid.NullUUID
	AppID        string
	ProviderID   string // k8s Deployment name, e.g. "app-{app_id}"
	Status       string // building | deploying | healthy | failed | stopped
	AppURL       string
	EnvVars      map[string]string
	Port         int
	Tier         string
	ErrorMessage string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// CreateDeploymentParams holds fields for inserting a new deployment row.
type CreateDeploymentParams struct {
	TeamID     uuid.UUID
	ResourceID *uuid.UUID
	AppID      string
	Port       int
	Tier       string
	EnvVars    map[string]string
}

// ErrDeploymentNotFound is returned when a deployment lookup yields no rows.
type ErrDeploymentNotFound struct {
	ID string
}

func (e *ErrDeploymentNotFound) Error() string {
	return fmt.Sprintf("deployment not found: %s", e.ID)
}

// scanDeployment reads a single deployments row into a Deployment struct.
// env_vars is stored as JSONB; error_message, provider_id, and app_url are nullable.
func scanDeployment(row interface {
	Scan(dest ...any) error
}) (*Deployment, error) {
	d := &Deployment{}
	var envVarsRaw []byte
	var providerID, appURL, errorMessage sql.NullString
	var resourceID uuid.NullUUID

	if err := row.Scan(
		&d.ID, &d.TeamID, &resourceID, &d.AppID,
		&providerID, &d.Status, &appURL,
		&envVarsRaw, &d.Port, &d.Tier, &errorMessage,
		&d.CreatedAt, &d.UpdatedAt,
	); err != nil {
		return nil, err
	}

	d.ResourceID = resourceID
	d.ProviderID = providerID.String
	d.AppURL = appURL.String
	d.ErrorMessage = errorMessage.String

	if len(envVarsRaw) > 0 {
		if err := json.Unmarshal(envVarsRaw, &d.EnvVars); err != nil {
			return nil, fmt.Errorf("unmarshal env_vars: %w", err)
		}
	}
	if d.EnvVars == nil {
		d.EnvVars = make(map[string]string)
	}

	return d, nil
}

// CreateDeployment inserts a new deployment row and returns it.
func CreateDeployment(ctx context.Context, db *sql.DB, p CreateDeploymentParams) (*Deployment, error) {
	var resourceID interface{}
	if p.ResourceID != nil {
		resourceID = *p.ResourceID
	}

	port := p.Port
	if port == 0 {
		port = 8080
	}

	envVars := p.EnvVars
	if envVars == nil {
		envVars = make(map[string]string)
	}
	envVarsJSON, err := json.Marshal(envVars)
	if err != nil {
		return nil, fmt.Errorf("models.CreateDeployment: marshal env_vars: %w", err)
	}

	row := db.QueryRowContext(ctx, `
		INSERT INTO deployments
			(team_id, resource_id, app_id, port, tier, env_vars)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, team_id, resource_id, app_id, provider_id, status, app_url,
		          env_vars, port, tier, error_message, created_at, updated_at
	`, p.TeamID, resourceID, p.AppID, port, p.Tier, envVarsJSON)

	d, err := scanDeployment(row)
	if err != nil {
		return nil, fmt.Errorf("models.CreateDeployment: %w", err)
	}
	return d, nil
}

// GetDeploymentByAppID fetches a deployment by its app_id slug (the short public token).
func GetDeploymentByAppID(ctx context.Context, db *sql.DB, appID string) (*Deployment, error) {
	row := db.QueryRowContext(ctx, `
		SELECT id, team_id, resource_id, app_id, provider_id, status, app_url,
		       env_vars, port, tier, error_message, created_at, updated_at
		FROM deployments WHERE app_id = $1
	`, appID)

	d, err := scanDeployment(row)
	if err == sql.ErrNoRows {
		return nil, &ErrDeploymentNotFound{ID: appID}
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetDeploymentByAppID: %w", err)
	}
	return d, nil
}

// GetDeploymentByID fetches a deployment by primary key UUID.
func GetDeploymentByID(ctx context.Context, db *sql.DB, id uuid.UUID) (*Deployment, error) {
	row := db.QueryRowContext(ctx, `
		SELECT id, team_id, resource_id, app_id, provider_id, status, app_url,
		       env_vars, port, tier, error_message, created_at, updated_at
		FROM deployments WHERE id = $1
	`, id)

	d, err := scanDeployment(row)
	if err == sql.ErrNoRows {
		return nil, &ErrDeploymentNotFound{ID: id.String()}
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetDeploymentByID: %w", err)
	}
	return d, nil
}

// GetDeploymentsByTeam returns all deployments for a team, ordered by creation time descending.
func GetDeploymentsByTeam(ctx context.Context, db *sql.DB, teamID uuid.UUID) ([]*Deployment, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, team_id, resource_id, app_id, provider_id, status, app_url,
		       env_vars, port, tier, error_message, created_at, updated_at
		FROM deployments
		WHERE team_id = $1
		ORDER BY created_at DESC
	`, teamID)
	if err != nil {
		return nil, fmt.Errorf("models.GetDeploymentsByTeam: %w", err)
	}
	defer rows.Close()

	var results []*Deployment
	for rows.Next() {
		d, err := scanDeployment(rows)
		if err != nil {
			return nil, fmt.Errorf("models.GetDeploymentsByTeam scan: %w", err)
		}
		results = append(results, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("models.GetDeploymentsByTeam rows: %w", err)
	}
	return results, nil
}

// UpdateDeploymentStatus updates the status and optional error_message for a deployment.
// updated_at is set to now() by the database.
func UpdateDeploymentStatus(ctx context.Context, db *sql.DB, id uuid.UUID, status, errorMessage string) error {
	var errMsg interface{}
	if errorMessage != "" {
		errMsg = errorMessage
	}
	_, err := db.ExecContext(ctx, `
		UPDATE deployments
		SET status = $1, error_message = $2, updated_at = now()
		WHERE id = $3
	`, status, errMsg, id)
	if err != nil {
		return fmt.Errorf("models.UpdateDeploymentStatus: %w", err)
	}
	return nil
}

// UpdateDeploymentProviderID records the k8s Deployment name and the resolved app URL
// after the k8s Deployment object has been successfully created.
// updated_at is set to now() by the database.
func UpdateDeploymentProviderID(ctx context.Context, db *sql.DB, id uuid.UUID, providerID, appURL string) error {
	_, err := db.ExecContext(ctx, `
		UPDATE deployments
		SET provider_id = $1, app_url = $2, updated_at = now()
		WHERE id = $3
	`, providerID, appURL, id)
	if err != nil {
		return fmt.Errorf("models.UpdateDeploymentProviderID: %w", err)
	}
	return nil
}

// UpdateDeploymentEnvVars replaces the env_vars JSONB blob for a deployment.
// updated_at is set to now() by the database.
func UpdateDeploymentEnvVars(ctx context.Context, db *sql.DB, id uuid.UUID, envVars map[string]string) error {
	if envVars == nil {
		envVars = make(map[string]string)
	}
	envVarsJSON, err := json.Marshal(envVars)
	if err != nil {
		return fmt.Errorf("models.UpdateDeploymentEnvVars: marshal: %w", err)
	}
	_, err = db.ExecContext(ctx, `
		UPDATE deployments
		SET env_vars = $1, updated_at = now()
		WHERE id = $2
	`, envVarsJSON, id)
	if err != nil {
		return fmt.Errorf("models.UpdateDeploymentEnvVars: %w", err)
	}
	return nil
}

// DeleteDeployment hard-deletes a deployment row.
// Compute resources are real money — no soft-delete; callers must deprovision
// the k8s Deployment before calling this.
func DeleteDeployment(ctx context.Context, db *sql.DB, id uuid.UUID) error {
	_, err := db.ExecContext(ctx, `DELETE FROM deployments WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("models.DeleteDeployment: %w", err)
	}
	return nil
}
