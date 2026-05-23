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
	ErrCannotRemovePrimary    = errors.New("cannot remove the primary user; promote another member to primary first")
	ErrOwnerCannotLeave       = errors.New("team owner cannot leave")
	ErrInvitationNotFound     = errors.New("invitation not found")
	ErrInvitationExpired      = errors.New("invitation expired")
	ErrInvitationNotPending   = errors.New("invitation is not pending")
	ErrEmailMismatchInvite    = errors.New("invitation email does not match signed-in user")
	ErrMemberLimitReached     = errors.New("team member limit reached")
	ErrAlreadyTeamMember      = errors.New("user is already on this team")
	ErrInvalidInviteRole      = errors.New("invalid invitation role")
	ErrDuplicatePendingInvite = errors.New("pending invitation already exists for this email")
	ErrInvalidMemberRole      = errors.New("invalid member role")
	ErrCannotAssignOwnerRole  = errors.New("owner role cannot be assigned via role update; use promote-to-primary instead")
	ErrTargetNotOnTeam        = errors.New("target user is not on this team")
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
	defer func() { _ = rows.Close() }()

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
	defer func() { _ = rows.Close() }()

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

// AcceptInvitationResult is the return shape from AcceptInvitation. Carries
// the role the invitee was granted plus a non-empty Warning string when the
// model silently demoted the requested role — see DEMOTION SEMANTICS below.
// The handler surfaces Warning as a response field so the caller (and the
// LLM agent reading the JSON) knows the requested role was not what landed.
type AcceptInvitationResult struct {
	Role    string
	Warning string
}

// AcceptInvitation assigns the authenticated user to the invited team if email
// matches.
//
// DEMOTION SEMANTICS (finding #53): If the invitation row's role is "owner"
// but the team already has an owner, we silently downgrade the new joinee to
// "member" — there can be at most one owner per team in the legacy schema
// (the partial unique index uq_users_one_primary_per_team in migration 029
// extends this guarantee to is_primary). The Result.Warning field carries an
// English string explaining the downgrade so the caller can re-surface it to
// the LLM agent; downstream handlers attach this to the JSON response. The
// canonical path to actually transfer ownership is
// PromoteMemberToPrimary — that function atomically demotes the existing
// primary in the same transaction.
func AcceptInvitation(ctx context.Context, db *sql.DB, invitationID, userID uuid.UUID, memberLimit int) (AcceptInvitationResult, error) {
	var result AcceptInvitationResult
	inv, err := GetInvitationByID(ctx, db, invitationID)
	if err != nil {
		return result, err
	}
	if inv.Status != "pending" {
		return result, ErrInvitationNotPending
	}
	if time.Now().After(inv.ExpiresAt) {
		return result, ErrInvitationExpired
	}

	u, err := GetUserByID(ctx, db, userID)
	if err != nil {
		return result, err
	}
	if NormalizeTeamEmail(u.Email) != NormalizeTeamEmail(inv.Email) {
		return result, ErrEmailMismatchInvite
	}

	if !u.TeamID.Valid || u.TeamID.UUID != inv.TeamID {
		var cnt int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE team_id = $1`, inv.TeamID).Scan(&cnt); err != nil {
			return result, fmt.Errorf("models.AcceptInvitation: %w", err)
		}
		if memberLimit >= 0 && cnt >= memberLimit {
			return result, ErrMemberLimitReached
		}
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return result, fmt.Errorf("models.AcceptInvitation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	role := inv.Role
	if role != "member" && role != "owner" {
		role = "member"
	}
	// Silent owner-demote: see DEMOTION SEMANTICS in the doc comment.
	// Records a Warning string so the handler can echo it in the JSON
	// response.
	if role == "owner" {
		var owners int
		_ = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE team_id = $1 AND role = 'owner'`, inv.TeamID).Scan(&owners)
		if owners > 0 {
			role = "member"
			result.Warning = "Invitation requested role=owner, but the team already has an owner. " +
				"You were added as a member. Use POST /api/v1/team/members/<your_id>/promote-to-primary " +
				"to transfer ownership atomically."
		}
	}

	// is_primary is always cleared on accept: joining a team via invitation
	// never grants the primary slot (that is a separate promote-to-primary
	// transfer). If the user was the primary of their previous team, leaving
	// it set would violate uq_users_one_primary_per_team once they land on a
	// team that already has a primary.
	if _, err := tx.ExecContext(ctx, `
		UPDATE users SET team_id = $1, role = $2, is_primary = false WHERE id = $3
	`, inv.TeamID, role, userID); err != nil {
		return result, fmt.Errorf("models.AcceptInvitation: update user: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE team_invitations SET status = 'accepted' WHERE id = $1 AND status = 'pending'
	`, invitationID); err != nil {
		return result, fmt.Errorf("models.AcceptInvitation: update invite: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return result, fmt.Errorf("models.AcceptInvitation: %w", err)
	}
	result.Role = role
	return result, nil
}

// CreatePersonalTeamAndReassignUser moves a user to a new solo team as owner.
// Returns the new personal team's UUID so callers can surface it in their
// response — fixes finding #52 where RemoveMember silently spawned an orphan
// personal team and the caller had no way to audit it.
func CreatePersonalTeamAndReassignUser(ctx context.Context, db *sql.DB, userID uuid.UUID) (uuid.UUID, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return uuid.Nil, fmt.Errorf("models.CreatePersonalTeamAndReassignUser: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var email string
	if err := tx.QueryRowContext(ctx, `SELECT email FROM users WHERE id = $1`, userID).Scan(&email); err != nil {
		return uuid.Nil, fmt.Errorf("models.CreatePersonalTeamAndReassignUser: %w", err)
	}
	teamName := strings.Split(email, "@")[0]
	if teamName == "" {
		teamName = "Personal"
	}

	var teamID uuid.UUID
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO teams (name) VALUES ($1) RETURNING id
	`, teamName).Scan(&teamID); err != nil {
		return uuid.Nil, fmt.Errorf("models.CreatePersonalTeamAndReassignUser: %w", err)
	}
	// Reassign the user to the new team as owner. Also clear is_primary
	// from any old assignment (a primary user being removed should be
	// caught upstream by ErrCannotRemovePrimary, but we defensively
	// reset the flag here so the new team's partial unique index sees
	// no carried-over true value) and flip is_primary=true on the new
	// team (since they're the sole user there).
	if _, err := tx.ExecContext(ctx, `
		UPDATE users SET team_id = $1, role = 'owner', is_primary = true WHERE id = $2
	`, teamID, userID); err != nil {
		return uuid.Nil, fmt.Errorf("models.CreatePersonalTeamAndReassignUser: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return uuid.Nil, fmt.Errorf("models.CreatePersonalTeamAndReassignUser: %w", err)
	}
	return teamID, nil
}

// RemoveMember removes a user from the team by assigning them a new personal
// team. Refuses when the target is the team's primary (is_primary=true) —
// migration 029's partial unique index makes "primary" the authoritative
// "team's anchor user" pointer that admin/customer-facing tooling depends on.
// Owner role is ALSO refused, preserving the legacy guard for callers that
// haven't migrated to is_primary yet.
//
// Returns the orphan team's UUID so the caller can surface it in the
// response (finding #52).
func RemoveMember(ctx context.Context, db *sql.DB, teamID, targetUserID uuid.UUID) (uuid.UUID, error) {
	var role string
	var isPrimary bool
	err := db.QueryRowContext(ctx, `
		SELECT COALESCE(role, 'member'), is_primary FROM users WHERE id = $1 AND team_id = $2
	`, targetUserID, teamID).Scan(&role, &isPrimary)
	if err == sql.ErrNoRows {
		return uuid.Nil, &ErrUserNotFound{Email: fmt.Sprintf("id:%s", targetUserID)}
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("models.RemoveMember: %w", err)
	}
	if isPrimary {
		return uuid.Nil, ErrCannotRemovePrimary
	}
	if role == "owner" {
		return uuid.Nil, ErrCannotRemoveOwner
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
	_, err = CreatePersonalTeamAndReassignUser(ctx, db, userID)
	return err
}

// allowedMemberRoles is the closed set of roles UpdateMemberRole accepts.
// Owner is excluded by design — promotion to owner flows through
// PromoteMemberToPrimary, which atomically demotes the existing
// owner/primary in the same transaction. "member" is retained as a legacy
// alias of developer for callers that haven't migrated to the RBAC names.
var allowedMemberRoles = map[string]struct{}{
	RoleAdmin:        {},
	RoleDeveloper:    {},
	RoleViewer:       {},
	"member":         {}, // legacy alias of developer
}

// UpdateMemberRole rewrites users.role for a target team-member. Refuses to
// assign owner (use PromoteMemberToPrimary for that), refuses unknown roles,
// and refuses to touch a user not on the team. The primary flag is NOT
// flipped here — role and is_primary are orthogonal once migration 029
// landed.
//
// Returns the user's new role on success. Idempotent: assigning the role a
// user already has is a no-op.
func UpdateMemberRole(ctx context.Context, db *sql.DB, teamID, targetUserID uuid.UUID, newRole string) (string, error) {
	newRole = strings.TrimSpace(strings.ToLower(newRole))
	if newRole == "" {
		return "", ErrInvalidMemberRole
	}
	if newRole == RoleOwner {
		return "", ErrCannotAssignOwnerRole
	}
	if _, ok := allowedMemberRoles[newRole]; !ok {
		return "", ErrInvalidMemberRole
	}

	res, err := db.ExecContext(ctx, `
		UPDATE users SET role = $1 WHERE id = $2 AND team_id = $3
	`, newRole, targetUserID, teamID)
	if err != nil {
		return "", fmt.Errorf("models.UpdateMemberRole: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return "", ErrTargetNotOnTeam
	}
	return newRole, nil
}

// PromoteMemberToPrimary atomically transfers the team's primary anchor
// (and the legacy owner role) from whoever currently holds it to the named
// target user. The whole flip happens inside one BEGIN/COMMIT so the
// partial unique index uq_users_one_primary_per_team (migration 029) can
// never observe a two-primary state — and so concurrent callers race to
// commit, with exactly one winning per the index's unique constraint.
//
// Behaviour:
//   - Target must already be on the team (refuses with ErrTargetNotOnTeam).
//   - Existing primary's is_primary flips to false; their role drops to
//     'admin' so they retain elevated permissions without holding the
//     owner slot.
//   - Target's is_primary flips to true; their role is promoted to
//     'owner'.
//   - If the caller passes their own user id and they are already primary,
//     the call is a no-op (returns nil).
func PromoteMemberToPrimary(ctx context.Context, db *sql.DB, teamID, targetUserID uuid.UUID) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("models.PromoteMemberToPrimary: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Verify target is on the team. Lock the row so concurrent promote
	// calls serialize through the same FOR UPDATE wait — without this
	// two concurrent promotes against different targets could both
	// observe the existing primary, both attempt to flip, and one would
	// fail on the unique index (acceptable) but the other might already
	// have demoted the old primary leaving the team primary-less for a
	// transient window. FOR UPDATE keeps the demote-then-promote pair
	// atomic from a concurrent reader's perspective.
	var targetRole string
	var targetIsPrimary bool
	err = tx.QueryRowContext(ctx, `
		SELECT COALESCE(role, 'member'), is_primary
		  FROM users
		 WHERE id = $1 AND team_id = $2
		 FOR UPDATE
	`, targetUserID, teamID).Scan(&targetRole, &targetIsPrimary)
	if err == sql.ErrNoRows {
		return ErrTargetNotOnTeam
	}
	if err != nil {
		return fmt.Errorf("models.PromoteMemberToPrimary: %w", err)
	}
	if targetIsPrimary {
		// Already primary — make the call idempotent. Ensure role is
		// owner in case a prior partial transfer left it stale.
		if targetRole != RoleOwner {
			if _, err := tx.ExecContext(ctx, `
				UPDATE users SET role = 'owner' WHERE id = $1 AND team_id = $2
			`, targetUserID, teamID); err != nil {
				return fmt.Errorf("models.PromoteMemberToPrimary: %w", err)
			}
		}
		return tx.Commit()
	}

	// Demote the existing primary. We do this BEFORE promoting the new
	// one to satisfy uq_users_one_primary_per_team — otherwise the second
	// UPDATE would violate the partial unique index. Setting role to
	// 'admin' preserves their elevated permissions; the caller can
	// follow up with UpdateMemberRole if a stricter demote is desired.
	if _, err := tx.ExecContext(ctx, `
		UPDATE users SET is_primary = false, role = 'admin'
		 WHERE team_id = $1 AND is_primary = true AND id <> $2
	`, teamID, targetUserID); err != nil {
		return fmt.Errorf("models.PromoteMemberToPrimary: demote old primary: %w", err)
	}

	// Promote the new primary + owner.
	res, err := tx.ExecContext(ctx, `
		UPDATE users SET is_primary = true, role = 'owner'
		 WHERE id = $1 AND team_id = $2
	`, targetUserID, teamID)
	if err != nil {
		return fmt.Errorf("models.PromoteMemberToPrimary: promote target: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrTargetNotOnTeam
	}
	return tx.Commit()
}
