package models

// custom_domain.go — Pro+ custom hostnames for stacks.
//
// One row per hostname. The verification_token is the random value the customer
// includes in their TXT challenge record (`_instanode.<hostname>` →
// `instanode-verify-<token>`). Once we observe the TXT record, the row advances
// from "pending_verification" → "verified". The handler then creates an
// Ingress + cert-manager Certificate; status moves to "ingress_ready" and
// finally "cert_ready" / "live" once the cert is issued.

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Custom-domain status values. Strings are stored verbatim in the DB; do not
// rename without a migration.
const (
	CustomDomainStatusPending      = "pending_verification"
	CustomDomainStatusVerified     = "verified"
	CustomDomainStatusIngressReady = "ingress_ready"
	CustomDomainStatusCertReady    = "cert_ready"
	CustomDomainStatusLive         = "live"
	CustomDomainStatusFailed       = "failed"
)

// VerificationTokenPrefix is the literal prefix the customer must include in
// their TXT record value alongside the random token. Together they form the
// expected payload "instanode-verify-<token>".
const VerificationTokenPrefix = "instanode-verify-"

// CustomDomain is one row of the custom_domains table.
type CustomDomain struct {
	ID                uuid.UUID
	TeamID            uuid.UUID
	StackID           uuid.UUID
	Hostname          string
	VerificationToken string
	Status            string
	VerifiedAt        sql.NullTime
	CertReadyAt       sql.NullTime
	LastCheckAt       sql.NullTime
	LastCheckErr      sql.NullString
	CreatedAt         time.Time
}

// ErrCustomDomainNotFound is returned when a lookup yields no rows.
var ErrCustomDomainNotFound = errors.New("custom domain not found")

// ErrCustomDomainTaken is returned when the hostname is already bound to a
// different domain row (UNIQUE constraint violation).
var ErrCustomDomainTaken = errors.New("hostname already bound to another domain")

// generateVerificationToken returns a 32-char hex token (16 random bytes).
// The token is the per-row random part of the TXT challenge value.
func generateVerificationToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("models.generateVerificationToken: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// scanCustomDomain reads a custom_domains row into a CustomDomain.
func scanCustomDomain(row interface {
	Scan(dest ...any) error
}) (*CustomDomain, error) {
	d := &CustomDomain{}
	if err := row.Scan(
		&d.ID, &d.TeamID, &d.StackID, &d.Hostname,
		&d.VerificationToken, &d.Status,
		&d.VerifiedAt, &d.CertReadyAt,
		&d.LastCheckAt, &d.LastCheckErr,
		&d.CreatedAt,
	); err != nil {
		return nil, err
	}
	return d, nil
}

const customDomainSelectFields = `
	id, team_id, stack_id, hostname,
	verification_token, status,
	verified_at, cert_ready_at,
	last_check_at, last_check_err,
	created_at
`

// CreateCustomDomain inserts a row inside a transaction. The verification
// token is generated server-side. Returns ErrCustomDomainTaken on UNIQUE
// violation (another team or stack already claimed the hostname).
//
// All callers must provide a non-zero teamID, stackID, and lowercased hostname;
// the handler is responsible for hostname validation upstream.
func CreateCustomDomain(ctx context.Context, db *sql.DB, teamID, stackID uuid.UUID, hostname string) (*CustomDomain, error) {
	token, err := generateVerificationToken()
	if err != nil {
		return nil, err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("models.CreateCustomDomain: begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	row := tx.QueryRowContext(ctx, `
		INSERT INTO custom_domains (team_id, stack_id, hostname, verification_token)
		VALUES ($1, $2, $3, $4)
		RETURNING `+customDomainSelectFields,
		teamID, stackID, hostname, token,
	)
	d, scanErr := scanCustomDomain(row)
	if scanErr != nil {
		// Postgres UNIQUE violation → ErrCustomDomainTaken. The pq driver returns
		// a structured error but we keep the dependency surface small here and
		// match on the error string the way other models do.
		if isUniqueViolation(scanErr) {
			return nil, ErrCustomDomainTaken
		}
		return nil, fmt.Errorf("models.CreateCustomDomain: %w", scanErr)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("models.CreateCustomDomain: commit: %w", err)
	}
	committed = true
	return d, nil
}

// isUniqueViolation matches the Postgres SQLSTATE 23505 the lib/pq driver
// surfaces in its Error() text. Avoids a hard dependency on pq's error type
// in this file.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	// pq error: "ERROR: duplicate key value violates unique constraint ..."
	// pgx error: "ERROR: duplicate key value..."
	return strings.Contains(msg, "duplicate key value") || strings.Contains(msg, "23505")
}

// GetCustomDomainByID returns a single row or ErrCustomDomainNotFound.
func GetCustomDomainByID(ctx context.Context, db *sql.DB, id uuid.UUID) (*CustomDomain, error) {
	row := db.QueryRowContext(ctx, `
		SELECT `+customDomainSelectFields+`
		FROM custom_domains WHERE id = $1
	`, id)
	d, err := scanCustomDomain(row)
	if err == sql.ErrNoRows {
		return nil, ErrCustomDomainNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetCustomDomainByID: %w", err)
	}
	return d, nil
}

// ListCustomDomainsByStack returns every domain bound to the given stack,
// newest first.
func ListCustomDomainsByStack(ctx context.Context, db *sql.DB, stackID uuid.UUID) ([]*CustomDomain, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT `+customDomainSelectFields+`
		FROM custom_domains
		WHERE stack_id = $1
		ORDER BY created_at DESC
	`, stackID)
	if err != nil {
		return nil, fmt.Errorf("models.ListCustomDomainsByStack: %w", err)
	}
	defer rows.Close()

	out := make([]*CustomDomain, 0)
	for rows.Next() {
		d, err := scanCustomDomain(rows)
		if err != nil {
			return nil, fmt.Errorf("models.ListCustomDomainsByStack scan: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ListCustomDomainsByTeam returns every domain owned by the team, newest first.
func ListCustomDomainsByTeam(ctx context.Context, db *sql.DB, teamID uuid.UUID) ([]*CustomDomain, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT `+customDomainSelectFields+`
		FROM custom_domains
		WHERE team_id = $1
		ORDER BY created_at DESC
	`, teamID)
	if err != nil {
		return nil, fmt.Errorf("models.ListCustomDomainsByTeam: %w", err)
	}
	defer rows.Close()

	out := make([]*CustomDomain, 0)
	for rows.Next() {
		d, err := scanCustomDomain(rows)
		if err != nil {
			return nil, fmt.Errorf("models.ListCustomDomainsByTeam scan: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// UpdateCustomDomainStatus advances the status field and records the
// last-check metadata. lastCheckErr may be empty (sets NULL).
func UpdateCustomDomainStatus(ctx context.Context, db *sql.DB, id uuid.UUID, status, lastCheckErr string) error {
	var errVal interface{}
	if lastCheckErr != "" {
		errVal = lastCheckErr
	}
	res, err := db.ExecContext(ctx, `
		UPDATE custom_domains
		SET status = $1,
		    last_check_at = now(),
		    last_check_err = $2
		WHERE id = $3
	`, status, errVal, id)
	if err != nil {
		return fmt.Errorf("models.UpdateCustomDomainStatus: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrCustomDomainNotFound
	}
	return nil
}

// MarkCustomDomainVerified sets verified_at = now() and status = "verified".
// last_check_err is cleared because we just succeeded.
func MarkCustomDomainVerified(ctx context.Context, db *sql.DB, id uuid.UUID) error {
	res, err := db.ExecContext(ctx, `
		UPDATE custom_domains
		SET status = $1,
		    verified_at = now(),
		    last_check_at = now(),
		    last_check_err = NULL
		WHERE id = $2
	`, CustomDomainStatusVerified, id)
	if err != nil {
		return fmt.Errorf("models.MarkCustomDomainVerified: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrCustomDomainNotFound
	}
	return nil
}

// MarkCertReady sets cert_ready_at = now() and status = "cert_ready".
// last_check_err is cleared. Callers may transition further to "live" via
// UpdateCustomDomainStatus once they confirm the hostname resolves.
func MarkCertReady(ctx context.Context, db *sql.DB, id uuid.UUID) error {
	res, err := db.ExecContext(ctx, `
		UPDATE custom_domains
		SET status = $1,
		    cert_ready_at = now(),
		    last_check_at = now(),
		    last_check_err = NULL
		WHERE id = $2
	`, CustomDomainStatusCertReady, id)
	if err != nil {
		return fmt.Errorf("models.MarkCertReady: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrCustomDomainNotFound
	}
	return nil
}

// DeleteCustomDomain removes the row matching (id, teamID). Returns
// ErrCustomDomainNotFound when no such row exists for the team.
func DeleteCustomDomain(ctx context.Context, db *sql.DB, id, teamID uuid.UUID) error {
	res, err := db.ExecContext(ctx, `
		DELETE FROM custom_domains WHERE id = $1 AND team_id = $2
	`, id, teamID)
	if err != nil {
		return fmt.Errorf("models.DeleteCustomDomain: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrCustomDomainNotFound
	}
	return nil
}
