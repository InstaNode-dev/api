package models

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Team represents a billing/organizational unit.
//
// TODO(no-trial-policy 2026-05-13): TrialEndsAt + the trial_ends_at column +
// the StartTrial / SendTrialStarted / SendTrialWarning code paths predate the
// "no trial — pay from day one" policy (see plans_policy_test.go). The
// trial_days config has been removed; the column itself is left in place so
// existing rows aren't corrupted, but new writes should not populate it. A
// follow-up migration should NULL out trial_ends_at across all teams and then
// drop the column.
type Team struct {
	ID                     uuid.UUID
	Name                   sql.NullString
	PlanTier               string
	RazorpaySubscriptionID sql.NullString
	TrialEndsAt            sql.NullTime
	CreatedAt              time.Time
}

// User represents an authenticated user belonging to a team.
type User struct {
	ID        uuid.UUID
	TeamID    uuid.NullUUID
	Email     string
	Role      string
	GitHubID  sql.NullString
	GoogleID  sql.NullString
	CreatedAt time.Time
}

// ErrTeamNotFound is returned when a team lookup yields no rows.
type ErrTeamNotFound struct {
	ID uuid.UUID
}

func (e *ErrTeamNotFound) Error() string {
	return fmt.Sprintf("team not found: %s", e.ID)
}

// ErrUserNotFound is returned when a user lookup yields no rows.
type ErrUserNotFound struct {
	Email string
}

func (e *ErrUserNotFound) Error() string {
	return fmt.Sprintf("user not found: %s", e.Email)
}

// CreateTeam inserts a new team and returns it.
//
// New teams start at plan_tier='free' (claimed-but-unpaid). The schema also
// defaults to 'free', but we set it explicitly here so this code path is
// independent of the DB default — drifting either side is a clear bug rather
// than a silent shift in onboarding semantics. Pay-from-day-one: the team
// stays on 'free' until the Razorpay subscription.charged webhook runs
// UpdatePlanTier with a paid tier.
func CreateTeam(ctx context.Context, db *sql.DB, name string) (*Team, error) {
	t := &Team{}
	err := db.QueryRowContext(ctx, `
		INSERT INTO teams (name, plan_tier) VALUES ($1, 'free')
		RETURNING id, name, plan_tier, stripe_customer_id, trial_ends_at, created_at
	`, name).Scan(
		&t.ID, &t.Name, &t.PlanTier, &t.RazorpaySubscriptionID, &t.TrialEndsAt, &t.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("models.CreateTeam: %w", err)
	}
	return t, nil
}

// GetTeamByID fetches a team by primary key.
func GetTeamByID(ctx context.Context, db *sql.DB, id uuid.UUID) (*Team, error) {
	t := &Team{}
	err := db.QueryRowContext(ctx, `
		SELECT id, name, plan_tier, stripe_customer_id, trial_ends_at, created_at
		FROM teams WHERE id = $1
	`, id).Scan(
		&t.ID, &t.Name, &t.PlanTier, &t.RazorpaySubscriptionID, &t.TrialEndsAt, &t.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, &ErrTeamNotFound{ID: id}
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetTeamByID: %w", err)
	}
	return t, nil
}

// CreateUser inserts a new user and returns it. role must be "owner" or "member"; empty defaults to "member".
func CreateUser(ctx context.Context, db *sql.DB, teamID uuid.UUID, email, githubID, googleID, role string) (*User, error) {
	var ghID, gID sql.NullString
	if githubID != "" {
		ghID = sql.NullString{String: githubID, Valid: true}
	}
	if googleID != "" {
		gID = sql.NullString{String: googleID, Valid: true}
	}
	if role == "" {
		role = "member"
	}

	u := &User{}
	err := db.QueryRowContext(ctx, `
		INSERT INTO users (team_id, email, github_id, google_id, role)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, team_id, email, role, github_id, google_id, created_at
	`, teamID, email, ghID, gID, role).Scan(
		&u.ID, &u.TeamID, &u.Email, &u.Role, &u.GitHubID, &u.GoogleID, &u.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("models.CreateUser: %w", err)
	}
	return u, nil
}

// GetUserByID fetches a user by primary key UUID.
func GetUserByID(ctx context.Context, db *sql.DB, id uuid.UUID) (*User, error) {
	u := &User{}
	err := db.QueryRowContext(ctx, `
		SELECT id, team_id, email, COALESCE(role, 'member'), github_id, google_id, created_at
		FROM users WHERE id = $1
	`, id).Scan(
		&u.ID, &u.TeamID, &u.Email, &u.Role, &u.GitHubID, &u.GoogleID, &u.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, &ErrUserNotFound{Email: fmt.Sprintf("id:%s", id)}
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetUserByID: %w", err)
	}
	return u, nil
}

// GetUserByEmail fetches a user by email address.
func GetUserByEmail(ctx context.Context, db *sql.DB, email string) (*User, error) {
	u := &User{}
	err := db.QueryRowContext(ctx, `
		SELECT id, team_id, email, COALESCE(role, 'member'), github_id, google_id, created_at
		FROM users WHERE email = $1
	`, email).Scan(
		&u.ID, &u.TeamID, &u.Email, &u.Role, &u.GitHubID, &u.GoogleID, &u.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, &ErrUserNotFound{Email: email}
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetUserByEmail: %w", err)
	}
	return u, nil
}

// GetUserByGitHubID fetches a user by their GitHub ID.
func GetUserByGitHubID(ctx context.Context, db *sql.DB, githubID string) (*User, error) {
	u := &User{}
	err := db.QueryRowContext(ctx, `
		SELECT id, team_id, email, COALESCE(role, 'member'), github_id, google_id, created_at
		FROM users WHERE github_id = $1
	`, githubID).Scan(
		&u.ID, &u.TeamID, &u.Email, &u.Role, &u.GitHubID, &u.GoogleID, &u.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, &ErrUserNotFound{Email: fmt.Sprintf("github:%s", githubID)}
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetUserByGitHubID: %w", err)
	}
	return u, nil
}

// UpdateRazorpaySubscriptionID stores the Razorpay subscription ID on the team.
//
// TODO: rename column stripe_customer_id → razorpay_subscription_id in a
// future migration. Stripe is not used anywhere in this codebase; the column
// name is a vestige of the original Stripe integration before the switch to
// Razorpay. Razorpay covers all payment surfaces we need (subscriptions,
// webhooks, invoices, plan upgrades). Per the user's directive, treat any
// remaining "stripe_*" string in the schema as legacy ballast to migrate.
func UpdateRazorpaySubscriptionID(ctx context.Context, db *sql.DB, teamID uuid.UUID, subscriptionID string) error {
	_, err := db.ExecContext(ctx, `
		UPDATE teams SET stripe_customer_id = $1 WHERE id = $2
	`, subscriptionID, teamID)
	if err != nil {
		return fmt.Errorf("models.UpdateRazorpaySubscriptionID: %w", err)
	}
	return nil
}

// UpdatePlanTier updates team.plan_tier and clears trial_ends_at.
func UpdatePlanTier(ctx context.Context, db *sql.DB, teamID uuid.UUID, tier string) error {
	_, err := db.ExecContext(ctx, `
		UPDATE teams SET plan_tier = $1, trial_ends_at = NULL WHERE id = $2
	`, tier, teamID)
	if err != nil {
		return fmt.Errorf("models.UpdatePlanTier: %w", err)
	}
	return nil
}

// GetTeamByRazorpaySubscriptionID looks up a team by Razorpay subscription ID.
func GetTeamByRazorpaySubscriptionID(ctx context.Context, db *sql.DB, subscriptionID string) (*Team, error) {
	t := &Team{}
	err := db.QueryRowContext(ctx, `
		SELECT id, name, plan_tier, stripe_customer_id, trial_ends_at, created_at
		FROM teams WHERE stripe_customer_id = $1
	`, subscriptionID).Scan(
		&t.ID, &t.Name, &t.PlanTier, &t.RazorpaySubscriptionID, &t.TrialEndsAt, &t.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, &ErrTeamNotFound{}
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetTeamByRazorpaySubscriptionID: %w", err)
	}
	return t, nil
}

// StartTrial sets trial_ends_at to now+14 days and plan_tier='hobby'.
func StartTrial(ctx context.Context, db *sql.DB, teamID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `
		UPDATE teams
		SET plan_tier = 'hobby',
		    trial_ends_at = now() + interval '14 days'
		WHERE id = $1
	`, teamID)
	if err != nil {
		return fmt.Errorf("models.StartTrial: %w", err)
	}
	return nil
}

// GetUserByTeamID fetches an owner for the team, or the earliest member if none is marked owner.
func GetUserByTeamID(ctx context.Context, db *sql.DB, teamID uuid.UUID) (*User, error) {
	u := &User{}
	err := db.QueryRowContext(ctx, `
		SELECT id, team_id, email, COALESCE(role, 'member'), github_id, google_id, created_at
		FROM users WHERE team_id = $1 AND role = 'owner'
		ORDER BY created_at ASC LIMIT 1
	`, teamID).Scan(
		&u.ID, &u.TeamID, &u.Email, &u.Role, &u.GitHubID, &u.GoogleID, &u.CreatedAt,
	)
	if err == sql.ErrNoRows {
		err = db.QueryRowContext(ctx, `
			SELECT id, team_id, email, COALESCE(role, 'member'), github_id, google_id, created_at
			FROM users WHERE team_id = $1 ORDER BY created_at ASC LIMIT 1
		`, teamID).Scan(
			&u.ID, &u.TeamID, &u.Email, &u.Role, &u.GitHubID, &u.GoogleID, &u.CreatedAt,
		)
	}
	if err == sql.ErrNoRows {
		return nil, &ErrUserNotFound{Email: fmt.Sprintf("team:%s", teamID)}
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetUserByTeamID: %w", err)
	}
	return u, nil
}

// LinkGoogleID sets google_id on an existing user when it is currently NULL.
func LinkGoogleID(ctx context.Context, db *sql.DB, userID uuid.UUID, googleID string) error {
	res, err := db.ExecContext(ctx, `
		UPDATE users SET google_id = $1 WHERE id = $2 AND google_id IS NULL
	`, googleID, userID)
	if err != nil {
		return fmt.Errorf("models.LinkGoogleID: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("models.LinkGoogleID rows: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("models.LinkGoogleID: user %s not updated (already has google_id?)", userID)
	}
	return nil
}

// GetUserByGoogleID fetches a user by their Google ID.
func GetUserByGoogleID(ctx context.Context, db *sql.DB, googleID string) (*User, error) {
	u := &User{}
	err := db.QueryRowContext(ctx, `
		SELECT id, team_id, email, COALESCE(role, 'member'), github_id, google_id, created_at
		FROM users WHERE google_id = $1
	`, googleID).Scan(
		&u.ID, &u.TeamID, &u.Email, &u.Role, &u.GitHubID, &u.GoogleID, &u.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, &ErrUserNotFound{Email: fmt.Sprintf("google:%s", googleID)}
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetUserByGoogleID: %w", err)
	}
	return u, nil
}
