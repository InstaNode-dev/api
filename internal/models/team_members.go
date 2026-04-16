package models

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Team membership / invitation errors.
var (
	ErrNotTeamOwner           = errors.New("must be team owner")
	ErrCannotRemoveOwner      = errors.New("cannot remove team owner")
	ErrOwnerCannotLeave       = errors.New("team owner cannot leave")
	ErrInvitationNotFound     = errors.New("invitation not found")
	ErrInvitationExpired      = errors.New("invitation expired")
	ErrInvitationNotPending   = errors.New("invitation is not pending")
	ErrEmailMismatchInvite    = errors.New("invitation email does not match signed-in user")
	ErrMemberLimitReached     = errors.New("team member limit reached")
	ErrAlreadyTeamMember      = errors.New("user is already on this team")
	ErrInvalidInviteRole      = errors.New("invalid invitation role")
	ErrDuplicatePendingInvite = errors.New("pending invitation already exists for this email")
)

// TeamMember is a user row scoped to team listing APIs.
type TeamMember struct {
	ID        uuid.UUID
	Email     string
	Role      string
	CreatedAt time.Time
}

// TeamInvitation is a pending or historical invite row.
type TeamInvitation struct {
	ID        uuid.UUID
	TeamID    uuid.UUID
	Email     string
	Role      string
	Status    string
	InvitedBy uuid.UUID
	CreatedAt time.Time
	ExpiresAt time.Time
}

// NormalizeTeamEmail lowercases and trims an email for comparisons and storage.
func NormalizeTeamEmail(s string) string {
	return strings.TrimSpace(strings.ToLower(s))
}

// GetUserRole returns the user's role for the given team, or empty if not on the team.
func GetUserRole(ctx context.Context, db *sql.DB, teamID, userID uuid.UUID) (string, error) {
	var role string
	err := db.QueryRowContext(ctx, `
		SELECT COALESCE(role, 'member') FROM users WHERE id = $1 AND team_id = $2
	`, userID, teamID).Scan(&role)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("models.GetUserRole: %w", err)
	}
	return role, nil
}

// ListTeamMembers returns all users on the team ordered by created_at.
func ListTeamMembers(ctx context.Context, db *sql.DB, teamID uuid.UUID) ([]TeamMember, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, email, COALESCE(role, 'member'), created_at
		FROM users WHERE team_id = $1 ORDER BY created_at ASC
	`, teamID)
	if err != nil {
		return nil, fmt.Errorf("models.ListTeamMembers: %w", err)
	}
	defer rows.Close()

	var out []TeamMember
	for rows.Next() {
		var m TeamMember
		if err := rows.Scan(&m.ID, &m.Email, &m.Role, &m.CreatedAt); err != nil {
			return nil, fmt.Errorf("models.ListTeamMembers: %w", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("models.ListTeamMembers: %w", err)
	}
	return out, nil
}

// CountTeamMembers returns the number of users on the team.
func CountTeamMembers(ctx context.Context, db *sql.DB, teamID uuid.UUID) (int, error) {
	var n int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE team_id = $1`, teamID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("models.CountTeamMembers: %w", err)
	}
	return n, nil
}

// CountPendingInvitations returns pending invitations for the team.
func CountPendingInvitations(ctx context.Context, db *sql.DB, teamID uuid.UUID) (int, error) {
	var n int
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM team_invitations WHERE team_id = $1 AND status = 'pending'
	`, teamID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("models.CountPendingInvitations: %w", err)
	}
	return n, nil
}

// teamSeatTotal is members + pending invites (each invite reserves one seat).
func teamSeatTotal(ctx context.Context, db *sql.DB, teamID uuid.UUID) (int, error) {
	members, err := CountTeamMembers(ctx, db, teamID)
	if err != nil {
		return 0, err
	}
	pending, err := CountPendingInvitations(ctx, db, teamID)
	if err != nil {
		return 0, err
	}
	return members + pending, nil
}

// withinMemberLimit returns true if one more seat can be allocated (invite or join).
func withinMemberLimit(ctx context.Context, db *sql.DB, teamID uuid.UUID, planLimit int) (bool, error) {
	if planLimit < 0 {
		return true, nil
	}
	total, err := teamSeatTotal(ctx, db, teamID)
	if err != nil {
		return false, err
	}
	return total < planLimit, nil
}

// InviteMember creates a pending invitation. invitedBy must belong to teamID. memberLimit is from plans (-1 = unlimited).
func InviteMember(ctx context.Context, db *sql.DB, teamID uuid.UUID, email, role string, invitedBy uuid.UUID, memberLimit int) (*TeamInvitation, error) {
	email = NormalizeTeamEmail(email)
	if email == "" {
		return nil, fmt.Errorf("models.InviteMember: email required")
	}
	if role != "member" {
		return nil, ErrInvalidInviteRole
	}

	inviterRole, err := GetUserRole(ctx, db, teamID, invitedBy)
	if err != nil {
		return nil, err
	}
	if inviterRole != "owner" {
		return nil, ErrNotTeamOwner
	}

	ok, err := withinMemberLimit(ctx, db, teamID, memberLimit)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrMemberLimitReached
	}

	var existing int
	_ = db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM users WHERE team_id = $1 AND lower(email) = lower($2)
	`, teamID, email).Scan(&existing)
	if existing > 0 {
		return nil, ErrAlreadyTeamMember
	}

	inv := &TeamInvitation{}
	err = db.QueryRowContext(ctx, `
		INSERT INTO team_invitations (team_id, email, role, invited_by, status)
		VALUES ($1, $2, $3, $4, 'pending')
		RETURNING id, team_id, email, role, status, invited_by, created_at, expires_at
	`, teamID, email, role, invitedBy).Scan(
		&inv.ID, &inv.TeamID, &inv.Email, &inv.Role, &inv.Status, &inv.InvitedBy, &inv.CreatedAt, &inv.ExpiresAt,
	)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return nil, ErrDuplicatePendingInvite
		}
		return nil, fmt.Errorf("models.InviteMember: %w", err)
	}
	return inv, nil
}

// ListInvitations returns pending invitations for the team.
func ListInvitations(ctx context.Context, db *sql.DB, teamID uuid.UUID) ([]TeamInvitation, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, team_id, email, role, status, invited_by, created_at, expires_at
		FROM team_invitations
		WHERE team_id = $1 AND status = 'pending'
		ORDER BY created_at DESC
	`, teamID)
	if err != nil {
		return nil, fmt.Errorf("models.ListInvitations: %w", err)
	}
	defer rows.Close()

	var out []TeamInvitation
	for rows.Next() {
		var inv TeamInvitation
		if err := rows.Scan(&inv.ID, &inv.TeamID, &inv.Email, &inv.Role, &inv.Status, &inv.InvitedBy, &inv.CreatedAt, &inv.ExpiresAt); err != nil {
			return nil, fmt.Errorf("models.ListInvitations: %w", err)
		}
		out = append(out, inv)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("models.ListInvitations: %w", err)
	}
	return out, nil
}

// GetInvitationByID loads an invitation by primary key.
func GetInvitationByID(ctx context.Context, db *sql.DB, id uuid.UUID) (*TeamInvitation, error) {
	inv := &TeamInvitation{}
	err := db.QueryRowContext(ctx, `
		SELECT id, team_id, email, role, status, invited_by, created_at, expires_at
		FROM team_invitations WHERE id = $1
	`, id).Scan(
		&inv.ID, &inv.TeamID, &inv.Email, &inv.Role, &inv.Status, &inv.InvitedBy, &inv.CreatedAt, &inv.ExpiresAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrInvitationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetInvitationByID: %w", err)
	}
	return inv, nil
}

// RevokeInvitation marks a pending invitation revoked.
func RevokeInvitation(ctx context.Context, db *sql.DB, invitationID uuid.UUID) error {
	res, err := db.ExecContext(ctx, `
		UPDATE team_invitations SET status = 'revoked'
		WHERE id = $1 AND status = 'pending'
	`, invitationID)
	if err != nil {
		return fmt.Errorf("models.RevokeInvitation: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrInvitationNotFound
	}
	return nil
}

// AcceptInvitation assigns the authenticated user to the invited team if email matches.
func AcceptInvitation(ctx context.Context, db *sql.DB, invitationID, userID uuid.UUID, memberLimit int) error {
	inv, err := GetInvitationByID(ctx, db, invitationID)
	if err != nil {
		return err
	}
	if inv.Status != "pending" {
		return ErrInvitationNotPending
	}
	if time.Now().After(inv.ExpiresAt) {
		return ErrInvitationExpired
	}

	u, err := GetUserByID(ctx, db, userID)
	if err != nil {
		return err
	}
	if NormalizeTeamEmail(u.Email) != NormalizeTeamEmail(inv.Email) {
		return ErrEmailMismatchInvite
	}

	if !u.TeamID.Valid || u.TeamID.UUID != inv.TeamID {
		var cnt int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE team_id = $1`, inv.TeamID).Scan(&cnt); err != nil {
			return fmt.Errorf("models.AcceptInvitation: %w", err)
		}
		if memberLimit >= 0 && cnt >= memberLimit {
			return ErrMemberLimitReached
		}
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("models.AcceptInvitation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	role := inv.Role
	if role != "member" && role != "owner" {
		role = "member"
	}
	if role == "owner" {
		var owners int
		_ = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE team_id = $1 AND role = 'owner'`, inv.TeamID).Scan(&owners)
		if owners > 0 {
			role = "member"
		}
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE users SET team_id = $1, role = $2 WHERE id = $3
	`, inv.TeamID, role, userID); err != nil {
		return fmt.Errorf("models.AcceptInvitation: update user: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE team_invitations SET status = 'accepted' WHERE id = $1 AND status = 'pending'
	`, invitationID); err != nil {
		return fmt.Errorf("models.AcceptInvitation: update invite: %w", err)
	}
	return tx.Commit()
}

// CreatePersonalTeamAndReassignUser moves a user to a new solo team as owner.
func CreatePersonalTeamAndReassignUser(ctx context.Context, db *sql.DB, userID uuid.UUID) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("models.CreatePersonalTeamAndReassignUser: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var email string
	if err := tx.QueryRowContext(ctx, `SELECT email FROM users WHERE id = $1`, userID).Scan(&email); err != nil {
		return fmt.Errorf("models.CreatePersonalTeamAndReassignUser: %w", err)
	}
	teamName := strings.Split(email, "@")[0]
	if teamName == "" {
		teamName = "Personal"
	}

	var teamID uuid.UUID
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO teams (name) VALUES ($1) RETURNING id
	`, teamName).Scan(&teamID); err != nil {
		return fmt.Errorf("models.CreatePersonalTeamAndReassignUser: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE users SET team_id = $1, role = 'owner' WHERE id = $2
	`, teamID, userID); err != nil {
		return fmt.Errorf("models.CreatePersonalTeamAndReassignUser: %w", err)
	}
	return tx.Commit()
}

// RemoveMember removes a user from the team by assigning them a new personal team (owner cannot be removed).
func RemoveMember(ctx context.Context, db *sql.DB, teamID, targetUserID uuid.UUID) error {
	var role string
	err := db.QueryRowContext(ctx, `
		SELECT COALESCE(role, 'member') FROM users WHERE id = $1 AND team_id = $2
	`, targetUserID, teamID).Scan(&role)
	if err == sql.ErrNoRows {
		return &ErrUserNotFound{Email: fmt.Sprintf("id:%s", targetUserID)}
	}
	if err != nil {
		return fmt.Errorf("models.RemoveMember: %w", err)
	}
	if role == "owner" {
		return ErrCannotRemoveOwner
	}
	return CreatePersonalTeamAndReassignUser(ctx, db, targetUserID)
}

// LeaveTeam moves the current user to a personal team if they are not the owner.
func LeaveTeam(ctx context.Context, db *sql.DB, teamID, userID uuid.UUID) error {
	role, err := GetUserRole(ctx, db, teamID, userID)
	if err != nil {
		return err
	}
	if role == "" {
		return &ErrUserNotFound{Email: fmt.Sprintf("id:%s", userID)}
	}
	if role == "owner" {
		return ErrOwnerCannotLeave
	}
	return CreatePersonalTeamAndReassignUser(ctx, db, userID)
}
