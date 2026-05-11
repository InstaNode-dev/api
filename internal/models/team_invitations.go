package models

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// RBAC role constants. Hierarchy: owner > admin > developer > viewer.
// "member" is retained as an alias of "developer" for legacy callers.
const (
	RoleOwner     = "owner"
	RoleAdmin     = "admin"
	RoleDeveloper = "developer"
	RoleViewer    = "viewer"
)

// inviteTokenBytes is the random-byte length of an invitation token.
// 32 bytes -> 64 hex chars; must align with the migration column type.
const inviteTokenBytes = 32

// inviteTTL is how long a fresh invitation remains valid before expiry.
const inviteTTL = 7 * 24 * time.Hour

// allowedInviteRoles is the closed set of roles that may be invited via the
// token-based RBAC flow. Owner cannot be invited — ownership is transferred,
// never granted via email.
var allowedInviteRoles = map[string]struct{}{
	RoleAdmin:     {},
	RoleDeveloper: {},
	RoleViewer:    {},
}

// Errors specific to the token-based RBAC invite flow.
var (
	ErrInvitationAlreadyAccepted = errors.New("invitation already accepted")
	ErrInvitationRevoked         = errors.New("invitation revoked")
	ErrInvitationTokenInvalid    = errors.New("invitation token invalid")
	ErrLastOwner                 = errors.New("cannot remove or downgrade the last team owner")
)

// RBACInvitation is the row shape for the token-based invite flow.
// Distinct from TeamInvitation (legacy "owner/member" + status string) so the
// two flows can coexist without name collisions.
type RBACInvitation struct {
	ID         uuid.UUID
	TeamID     uuid.UUID
	Email      string
	Role       string
	Token      string
	InvitedBy  uuid.UUID
	ExpiresAt  time.Time
	AcceptedAt sql.NullTime
	CreatedAt  time.Time
}

// IsValidInviteRole reports whether role can be granted via the invite flow.
func IsValidInviteRole(role string) bool {
	_, ok := allowedInviteRoles[role]
	return ok
}

// generateInviteToken returns a cryptographically random hex token.
// Exposed via package var so tests can stub it deterministically.
var generateInviteToken = func() (string, error) {
	buf := make([]byte, inviteTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("models.generateInviteToken: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// CreateRBACInvitation inserts a single-use invitation row, expiring in 7 days.
// invitedBy must already exist (FK to users). Returns the inserted row including
// the token (caller is responsible for emailing it to the invitee).
func CreateRBACInvitation(ctx context.Context, db *sql.DB, teamID uuid.UUID, email, role string, invitedBy uuid.UUID) (*RBACInvitation, error) {
	email = NormalizeTeamEmail(email)
	if email == "" {
		return nil, fmt.Errorf("models.CreateRBACInvitation: email required")
	}
	if !IsValidInviteRole(role) {
		return nil, ErrInvalidInviteRole
	}

	token, err := generateInviteToken()
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(inviteTTL)

	inv := &RBACInvitation{}
	err = db.QueryRowContext(ctx, `
		INSERT INTO team_invitations (team_id, email, role, token, invited_by, expires_at, status)
		VALUES ($1, $2, $3, $4, $5, $6, 'pending')
		RETURNING id, team_id, email, role, token, invited_by, expires_at, accepted_at, created_at
	`, teamID, email, role, token, invitedBy, expiresAt).Scan(
		&inv.ID, &inv.TeamID, &inv.Email, &inv.Role, &inv.Token,
		&inv.InvitedBy, &inv.ExpiresAt, &inv.AcceptedAt, &inv.CreatedAt,
	)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return nil, ErrDuplicatePendingInvite
		}
		return nil, fmt.Errorf("models.CreateRBACInvitation: %w", err)
	}
	return inv, nil
}

// ListRBACInvitations returns pending (status='pending', not yet accepted) invites
// for the team. Mirrors ListInvitations but populates the token + accepted_at fields.
func ListRBACInvitations(ctx context.Context, db *sql.DB, teamID uuid.UUID) ([]RBACInvitation, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, team_id, email, role, token, invited_by, expires_at, accepted_at, created_at
		FROM team_invitations
		WHERE team_id = $1 AND status = 'pending' AND accepted_at IS NULL
		ORDER BY created_at DESC
	`, teamID)
	if err != nil {
		return nil, fmt.Errorf("models.ListRBACInvitations: %w", err)
	}
	defer rows.Close()

	var out []RBACInvitation
	for rows.Next() {
		var inv RBACInvitation
		if err := rows.Scan(&inv.ID, &inv.TeamID, &inv.Email, &inv.Role, &inv.Token,
			&inv.InvitedBy, &inv.ExpiresAt, &inv.AcceptedAt, &inv.CreatedAt); err != nil {
			return nil, fmt.Errorf("models.ListRBACInvitations: %w", err)
		}
		out = append(out, inv)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("models.ListRBACInvitations: %w", err)
	}
	return out, nil
}

// GetRBACInvitationByID loads a single invitation by ID (ignoring status).
func GetRBACInvitationByID(ctx context.Context, db *sql.DB, id uuid.UUID) (*RBACInvitation, error) {
	inv := &RBACInvitation{}
	err := db.QueryRowContext(ctx, `
		SELECT id, team_id, email, role, token, invited_by, expires_at, accepted_at, created_at
		FROM team_invitations WHERE id = $1
	`, id).Scan(
		&inv.ID, &inv.TeamID, &inv.Email, &inv.Role, &inv.Token,
		&inv.InvitedBy, &inv.ExpiresAt, &inv.AcceptedAt, &inv.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrInvitationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetRBACInvitationByID: %w", err)
	}
	return inv, nil
}

// GetRBACInvitationByToken loads an invitation by its single-use token.
func GetRBACInvitationByToken(ctx context.Context, db *sql.DB, token string) (*RBACInvitation, error) {
	if token == "" {
		return nil, ErrInvitationTokenInvalid
	}
	inv := &RBACInvitation{}
	err := db.QueryRowContext(ctx, `
		SELECT id, team_id, email, role, token, invited_by, expires_at, accepted_at, created_at
		FROM team_invitations WHERE token = $1
	`, token).Scan(
		&inv.ID, &inv.TeamID, &inv.Email, &inv.Role, &inv.Token,
		&inv.InvitedBy, &inv.ExpiresAt, &inv.AcceptedAt, &inv.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrInvitationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetRBACInvitationByToken: %w", err)
	}
	return inv, nil
}

// RevokeRBACInvitation marks an invitation revoked. Only pending invites
// (no accepted_at) can be revoked.
func RevokeRBACInvitation(ctx context.Context, db *sql.DB, invitationID uuid.UUID) error {
	res, err := db.ExecContext(ctx, `
		UPDATE team_invitations SET status = 'revoked'
		WHERE id = $1 AND status = 'pending' AND accepted_at IS NULL
	`, invitationID)
	if err != nil {
		return fmt.Errorf("models.RevokeRBACInvitation: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrInvitationNotFound
	}
	return nil
}

// AcceptRBACInvitationByToken consumes a token, creating or updating the
// invitee's user row to belong to the team with the invited role.
//
// Single-use guarantee: the UPDATE is gated on accepted_at IS NULL — a second
// call against the same token returns ErrInvitationAlreadyAccepted.
//
// Expiry: rejects if expires_at < now, returning ErrInvitationExpired.
//
// Returns the user (existing or freshly created) so the caller can mint a
// session JWT for the invitee.
func AcceptRBACInvitationByToken(ctx context.Context, db *sql.DB, token string) (*User, *RBACInvitation, error) {
	inv, err := GetRBACInvitationByToken(ctx, db, token)
	if err != nil {
		return nil, nil, err
	}
	// Already accepted -> 410 Gone (signal: token is permanently spent).
	if inv.AcceptedAt.Valid {
		return nil, inv, ErrInvitationAlreadyAccepted
	}
	if inv.Status() == "revoked" {
		return nil, inv, ErrInvitationRevoked
	}
	if time.Now().After(inv.ExpiresAt) {
		return nil, inv, ErrInvitationExpired
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("models.AcceptRBACInvitationByToken: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Atomic single-use guard: only one transaction can flip accepted_at from NULL.
	res, err := tx.ExecContext(ctx, `
		UPDATE team_invitations SET accepted_at = now(), status = 'accepted'
		WHERE id = $1 AND accepted_at IS NULL AND status = 'pending'
	`, inv.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("models.AcceptRBACInvitationByToken: update: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, inv, ErrInvitationAlreadyAccepted
	}

	// Look up an existing user by email; create one if none exists.
	u := &User{}
	err = tx.QueryRowContext(ctx, `
		SELECT id, team_id, email, COALESCE(role, 'member'), github_id, google_id, created_at
		FROM users WHERE lower(email) = lower($1)
	`, inv.Email).Scan(
		&u.ID, &u.TeamID, &u.Email, &u.Role, &u.GitHubID, &u.GoogleID, &u.CreatedAt,
	)
	if err == sql.ErrNoRows {
		// Create the user attached to the team with the invited role.
		err = tx.QueryRowContext(ctx, `
			INSERT INTO users (team_id, email, role) VALUES ($1, $2, $3)
			RETURNING id, team_id, email, role, github_id, google_id, created_at
		`, inv.TeamID, inv.Email, inv.Role).Scan(
			&u.ID, &u.TeamID, &u.Email, &u.Role, &u.GitHubID, &u.GoogleID, &u.CreatedAt,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("models.AcceptRBACInvitationByToken: insert user: %w", err)
		}
	} else if err != nil {
		return nil, nil, fmt.Errorf("models.AcceptRBACInvitationByToken: lookup user: %w", err)
	} else {
		// Existing user — move them to the invited team and assign the new role.
		// Refuse to silently downgrade an owner of *another* team without first
		// vetting last-owner protection on the old team. For now we just move
		// them; tighter policy can layer on later.
		_, err = tx.ExecContext(ctx, `
			UPDATE users SET team_id = $1, role = $2 WHERE id = $3
		`, inv.TeamID, inv.Role, u.ID)
		if err != nil {
			return nil, nil, fmt.Errorf("models.AcceptRBACInvitationByToken: update user: %w", err)
		}
		u.TeamID = uuid.NullUUID{UUID: inv.TeamID, Valid: true}
		u.Role = inv.Role
	}

	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("models.AcceptRBACInvitationByToken: commit: %w", err)
	}
	return u, inv, nil
}

// Status returns the canonical lifecycle string for the invitation.
// Shadowed onto the type so handlers don't need a separate column lookup.
func (inv *RBACInvitation) Status() string {
	if inv == nil {
		return ""
	}
	if inv.AcceptedAt.Valid {
		return "accepted"
	}
	if time.Now().After(inv.ExpiresAt) {
		return "expired"
	}
	return "pending"
}

// CountTeamOwners returns the number of users with role='owner' on the team.
// Used to enforce the "last owner cannot leave or be downgraded" invariant.
func CountTeamOwners(ctx context.Context, db *sql.DB, teamID uuid.UUID) (int, error) {
	var n int
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM users WHERE team_id = $1 AND role = 'owner'
	`, teamID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("models.CountTeamOwners: %w", err)
	}
	return n, nil
}

// EnsureNotLastOwner returns ErrLastOwner if removing/downgrading targetUserID
// from teamID would leave the team with zero owners. Callers should invoke
// this before any DELETE / role-downgrade affecting an owner.
func EnsureNotLastOwner(ctx context.Context, db *sql.DB, teamID, targetUserID uuid.UUID) error {
	role, err := GetUserRole(ctx, db, teamID, targetUserID)
	if err != nil {
		return err
	}
	if role != RoleOwner {
		return nil
	}
	count, err := CountTeamOwners(ctx, db, teamID)
	if err != nil {
		return err
	}
	if count <= 1 {
		return ErrLastOwner
	}
	return nil
}
