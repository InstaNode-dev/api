package models

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// OnboardingEvent tracks when an anonymous user was issued an upgrade JWT.
type OnboardingEvent struct {
	ID             uuid.UUID
	Fingerprint    string
	JWTIssuedAt    time.Time
	JWTExpiresAt   sql.NullTime
	ConvertedAt    sql.NullTime
	TeamID         uuid.NullUUID
	ResourceTokens []uuid.UUID
	JTI            string
}

// ErrOnboardingNotFound is returned when a JTI lookup yields no rows.
type ErrOnboardingNotFound struct {
	JTI string
}

func (e *ErrOnboardingNotFound) Error() string {
	return fmt.Sprintf("onboarding event not found for jti: %s", e.JTI)
}

// ErrOnboardingAlreadyUsed is returned when a JTI has already been converted.
type ErrOnboardingAlreadyUsed struct {
	JTI string
}

func (e *ErrOnboardingAlreadyUsed) Error() string {
	return fmt.Sprintf("onboarding token already used: %s", e.JTI)
}

// CreateOnboardingEvent inserts a new onboarding event record.
func CreateOnboardingEvent(ctx context.Context, db *sql.DB, fingerprint, jti string, expiresAt time.Time, tokens []uuid.UUID) (*OnboardingEvent, error) {
	tokenStrs := make([]string, len(tokens))
	for i, t := range tokens {
		tokenStrs[i] = t.String()
	}

	ev := &OnboardingEvent{}
	var resourceTokens pq.StringArray
	err := db.QueryRowContext(ctx, `
		INSERT INTO onboarding_events (fingerprint, jti, jwt_expires_at, resource_tokens)
		VALUES ($1, $2, $3, $4)
		RETURNING id, fingerprint, jwt_issued_at, jwt_expires_at, converted_at, team_id, resource_tokens, jti
	`, fingerprint, jti, expiresAt, pq.Array(tokenStrs)).Scan(
		&ev.ID, &ev.Fingerprint, &ev.JWTIssuedAt, &ev.JWTExpiresAt,
		&ev.ConvertedAt, &ev.TeamID, &resourceTokens, &ev.JTI,
	)
	if err != nil {
		return nil, fmt.Errorf("models.CreateOnboardingEvent: %w", err)
	}
	ev.ResourceTokens = make([]uuid.UUID, 0, len(resourceTokens))
	for _, s := range resourceTokens {
		if u, err := uuid.Parse(s); err == nil {
			ev.ResourceTokens = append(ev.ResourceTokens, u)
		}
	}
	return ev, nil
}

// GetOnboardingByJTI fetches an onboarding event by JTI.
func GetOnboardingByJTI(ctx context.Context, db *sql.DB, jti string) (*OnboardingEvent, error) {
	ev := &OnboardingEvent{}
	var tokenStrings pq.StringArray
	err := db.QueryRowContext(ctx, `
		SELECT id, fingerprint, jwt_issued_at, jwt_expires_at, converted_at, team_id, resource_tokens, jti
		FROM onboarding_events WHERE jti = $1
	`, jti).Scan(
		&ev.ID, &ev.Fingerprint, &ev.JWTIssuedAt, &ev.JWTExpiresAt,
		&ev.ConvertedAt, &ev.TeamID, &tokenStrings, &ev.JTI,
	)
	if err == sql.ErrNoRows {
		return nil, &ErrOnboardingNotFound{JTI: jti}
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetOnboardingByJTI: %w", err)
	}

	ev.ResourceTokens = make([]uuid.UUID, 0, len(tokenStrings))
	for _, s := range tokenStrings {
		if u, err := uuid.Parse(s); err == nil {
			ev.ResourceTokens = append(ev.ResourceTokens, u)
		}
	}
	return ev, nil
}

// MarkOnboardingConverted sets converted_at and team_id on an onboarding event.
func MarkOnboardingConverted(ctx context.Context, db *sql.DB, jti string, teamID uuid.UUID) error {
	result, err := db.ExecContext(ctx, `
		UPDATE onboarding_events
		SET converted_at = now(), team_id = $1
		WHERE jti = $2 AND converted_at IS NULL
	`, teamID, jti)
	if err != nil {
		return fmt.Errorf("models.MarkOnboardingConverted: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return &ErrOnboardingAlreadyUsed{JTI: jti}
	}
	return nil
}
