package models

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// NormalizeEmail canonicalises an email address for storage and lookup:
// surrounding whitespace trimmed, then lower-cased. Every code path that
// reads or writes users.email MUST funnel through this so that
// "Victim@X.com", " victim@x.com " and "victim@x.com" all resolve to one
// identity. This is the model-layer guarantee behind the unique index on
// lower(email) (migration 052) and the /claim account-takeover guard
// (P7, 2026-05-17): an exact-match GetUserByEmail with no normalisation
// let a case/whitespace variant slip past the existing-account check.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

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
	// DefaultDeploymentTTLPolicy is the team's preferred default for
	// POST /deploy/new (Wave FIX-J — migration 045). Valid values:
	//   "auto_24h"  — deploys default to a 24h TTL (server default)
	//   "permanent" — deploys default to NO TTL (user explicitly opted in)
	// Per-request ttl_policy in the deploy body always overrides this.
	// Only owner/admin can mutate via PATCH /api/v1/team/settings.
	DefaultDeploymentTTLPolicy string
	// IsTestCohort marks a team as part of the synthetic-monitoring test
	// cohort (migration 067, W0 / PR-1). Inert by default (every real team is
	// false). Seeder-set true on the durable per-tier test teams so that
	// charge-initiation / conversion-funnel / background-email paths can no-op
	// or exclude them — keeping synthetic traffic out of the real
	// funnel/billing/email surfaces. See
	// docs/sessions/2026-06-04/TEST-ACCOUNTS-AND-NR-SYNTHETICS-PLAN.md §1.6.
	IsTestCohort bool
	CreatedAt    time.Time
}

// User represents an authenticated user belonging to a team.
type User struct {
	ID       uuid.UUID
	TeamID   uuid.NullUUID
	Email    string
	Role     string
	GitHubID sql.NullString
	GoogleID sql.NullString
	// EmailVerified records whether the account holder has demonstrated
	// control of the email address (migration 052). New /claim accounts
	// start false — the claim does not prove inbox ownership; magic-link
	// and OAuth logins set it true. Billing/upgrade actions are gated on
	// this flag (see handlers/billing.go). Pre-052 users were grandfathered
	// to true by the migration backfill.
	EmailVerified bool
	CreatedAt     time.Time
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
		RETURNING id, name, plan_tier, stripe_customer_id, created_at,
		          COALESCE(default_deployment_ttl_policy, 'auto_24h'), is_test_cohort
	`, name).Scan(
		&t.ID, &t.Name, &t.PlanTier, &t.RazorpaySubscriptionID, &t.CreatedAt,
		&t.DefaultDeploymentTTLPolicy, &t.IsTestCohort,
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
		SELECT id, name, plan_tier, stripe_customer_id, created_at,
		       COALESCE(default_deployment_ttl_policy, 'auto_24h'), is_test_cohort
		FROM teams WHERE id = $1
	`, id).Scan(
		&t.ID, &t.Name, &t.PlanTier, &t.RazorpaySubscriptionID, &t.CreatedAt,
		&t.DefaultDeploymentTTLPolicy, &t.IsTestCohort,
	)
	if err == sql.ErrNoRows {
		return nil, &ErrTeamNotFound{ID: id}
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetTeamByID: %w", err)
	}
	return t, nil
}

// UpdateTeamDefaultDeploymentTTLPolicy sets the team's default TTL policy.
// Valid values: "auto_24h" | "permanent". Caller validates input.
// Backs PATCH /api/v1/team/settings (Wave FIX-J — migration 045).
func UpdateTeamDefaultDeploymentTTLPolicy(ctx context.Context, db *sql.DB, teamID uuid.UUID, policy string) error {
	_, err := db.ExecContext(ctx, `
		UPDATE teams SET default_deployment_ttl_policy = $1 WHERE id = $2
	`, policy, teamID)
	if err != nil {
		return fmt.Errorf("models.UpdateTeamDefaultDeploymentTTLPolicy: %w", err)
	}
	return nil
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

	// is_primary: the first user we INSERT for a team becomes its
	// primary. Migration 029's uq_users_one_primary_per_team partial
	// unique index guarantees at most one true value per team, so the
	// inline NOT EXISTS check is the canonical owner-detection point.
	// Subsequent inserts get false even if they're owners — primary
	// transfer is a separate operation (todo: AdminTransferPrimary).
	// Canonicalise the email at the write boundary so every stored row is
	// already lower-cased + trimmed — the precondition for the unique
	// lower(email) index and for GetUserByEmail's exact-match to be a
	// reliable identity check (P7).
	email = NormalizeEmail(email)

	// email_verified always starts false here (the column default). This is
	// correct for /claim (the caller has not proven inbox ownership) and is
	// the safe default for OAuth/magic-link paths too — those flip it true
	// via SetEmailVerified once inbox/identity control IS proven. Inserting
	// the literal keeps this code path independent of the DB default, so a
	// future default change is a visible diff rather than a silent shift.
	u := &User{}
	err := db.QueryRowContext(ctx, `
		INSERT INTO users (team_id, email, github_id, google_id, role, is_primary, email_verified)
		VALUES (
			$1, $2, $3, $4, $5,
			NOT EXISTS (
				SELECT 1 FROM users
				 WHERE team_id = $1 AND is_primary = true
			),
			false
		)
		RETURNING id, team_id, email, role, github_id, google_id, email_verified, created_at
	`, teamID, email, ghID, gID, role).Scan(
		&u.ID, &u.TeamID, &u.Email, &u.Role, &u.GitHubID, &u.GoogleID, &u.EmailVerified, &u.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("models.CreateUser: %w", err)
	}
	return u, nil
}

// SetEmailVerified marks a user's email address as verified. It is called by
// every account path that proves inbox/identity control: magic-link login
// (the user clicked a link delivered to that inbox), Google OAuth (Google
// only returns verified addresses), and GitHub OAuth (the handler filters
// /user/emails on the Verified flag). /claim does NOT call this — a claim
// does not prove the caller owns the email.
//
// Idempotent: calling it on an already-verified user is a harmless no-op
// UPDATE. The caller should treat a returned error as best-effort — a verify
// flip failing must not break the login flow itself.
func SetEmailVerified(ctx context.Context, db *sql.DB, userID uuid.UUID) error {
	_, err := db.ExecContext(ctx, `
		UPDATE users SET email_verified = true WHERE id = $1
	`, userID)
	if err != nil {
		return fmt.Errorf("models.SetEmailVerified: %w", err)
	}
	return nil
}

// GetPrimaryUserByTeamID returns the team's primary user (is_primary=true).
//
// Used by the billing webhook handlers (B11-P1, 2026-05-20) to resolve the
// authoritative recipient for dunning / payment-failure emails — instead of
// trusting the `email` field on a Razorpay payload (which any holder of the
// webhook secret can spoof to fanout dunning emails to arbitrary recipients).
//
// Returns ErrUserNotFound when no primary user exists for the team
// (shouldn't happen in well-formed data — every team has a primary on
// CreateTeam, and team_members.PromoteMemberToPrimary maintains the
// invariant — but a defensive return so callers can fall back to "no
// email sent" rather than panicking).
func GetPrimaryUserByTeamID(ctx context.Context, db *sql.DB, teamID uuid.UUID) (*User, error) {
	u := &User{}
	err := db.QueryRowContext(ctx, `
		SELECT id, team_id, email, COALESCE(role, 'member'), github_id, google_id, email_verified, created_at
		FROM users
		WHERE team_id = $1 AND is_primary = true
		LIMIT 1
	`, teamID).Scan(
		&u.ID, &u.TeamID, &u.Email, &u.Role, &u.GitHubID, &u.GoogleID, &u.EmailVerified, &u.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, &ErrUserNotFound{Email: fmt.Sprintf("team:%s/primary", teamID)}
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetPrimaryUserByTeamID: %w", err)
	}
	return u, nil
}

// GetUserByID fetches a user by primary key UUID.
func GetUserByID(ctx context.Context, db *sql.DB, id uuid.UUID) (*User, error) {
	u := &User{}
	err := db.QueryRowContext(ctx, `
		SELECT id, team_id, email, COALESCE(role, 'member'), github_id, google_id, email_verified, created_at
		FROM users WHERE id = $1
	`, id).Scan(
		&u.ID, &u.TeamID, &u.Email, &u.Role, &u.GitHubID, &u.GoogleID, &u.EmailVerified, &u.CreatedAt,
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
//
// The lookup is case/whitespace-insensitive: the input is normalised via
// NormalizeEmail and matched against lower(email). This is what makes the
// /claim account-takeover guard (P7) sound — without it "Victim@X.com"
// would not match the stored "victim@x.com" row and the guard would let a
// duplicate-identity account through. The WHERE clause uses lower(email)
// (not = $1) so it is also robust against any legacy non-normalised rows
// written before migration 052, and so the planner can use the
// idx_users_email_lower functional index.
func GetUserByEmail(ctx context.Context, db *sql.DB, email string) (*User, error) {
	email = NormalizeEmail(email)
	u := &User{}
	err := db.QueryRowContext(ctx, `
		SELECT id, team_id, email, COALESCE(role, 'member'), github_id, google_id, email_verified, created_at
		FROM users WHERE lower(email) = $1
	`, email).Scan(
		&u.ID, &u.TeamID, &u.Email, &u.Role, &u.GitHubID, &u.GoogleID, &u.EmailVerified, &u.CreatedAt,
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
		SELECT id, team_id, email, COALESCE(role, 'member'), github_id, google_id, email_verified, created_at
		FROM users WHERE github_id = $1
	`, githubID).Scan(
		&u.ID, &u.TeamID, &u.Email, &u.Role, &u.GitHubID, &u.GoogleID, &u.EmailVerified, &u.CreatedAt,
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

// UpdatePlanTier updates team.plan_tier.
//
// Trial-clearing semantics are no longer relevant — the platform has no trial
// (see policy memory project_no_trial_pay_day_one.md). The trial_ends_at column
// was dropped in migration 034.
func UpdatePlanTier(ctx context.Context, db *sql.DB, teamID uuid.UUID, tier string) error {
	_, err := db.ExecContext(ctx, `
		UPDATE teams SET plan_tier = $1 WHERE id = $2
	`, tier, teamID)
	if err != nil {
		return fmt.Errorf("models.UpdatePlanTier: %w", err)
	}
	return nil
}

// IsTestCohort reports whether a team is part of the synthetic-monitoring test
// cohort (migration 067). It is the single lookup every api-side charge /
// conversion path keys off to no-op for a synthetic team so that continuous
// synthetic traffic never pollutes the real funnel / billing / email surfaces
// (W0 / PR-1 — see TEST-ACCOUNTS-AND-NR-SYNTHETICS-PLAN.md §1.6).
//
// A missing team is treated as NOT a test cohort: callers reach this only with
// an already-authenticated team id, and a stricter ErrNoRows surface here would
// just turn a 404 into a 500 on the chargeable path. The flag is inert by
// default — every real team is false until a seeder sets it true via
// SetTestCohort — so the common case returns false with one indexed lookup.
func IsTestCohort(ctx context.Context, db *sql.DB, teamID uuid.UUID) (bool, error) {
	var isTest bool
	err := db.QueryRowContext(ctx, `
		SELECT is_test_cohort FROM teams WHERE id = $1
	`, teamID).Scan(&isTest)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("models.IsTestCohort: %w", err)
	}
	return isTest, nil
}

// SetTestCohort flips teams.is_test_cohort for a single team. It is the only
// writer of the cohort flag and is intended for the worker-side synthetic
// seeder job (flow_synthetic_seed) — there is deliberately NO public HTTP
// surface that mutates it (a self-serve "mark my team as test" would let any
// caller opt out of billing/quota). Idempotent: setting the same value twice
// is a harmless no-op UPDATE.
func SetTestCohort(ctx context.Context, db *sql.DB, teamID uuid.UUID, isTest bool) error {
	res, err := db.ExecContext(ctx, `
		UPDATE teams SET is_test_cohort = $1 WHERE id = $2
	`, isTest, teamID)
	if err != nil {
		return fmt.Errorf("models.SetTestCohort: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("models.SetTestCohort rows: %w", err)
	}
	if rows == 0 {
		return &ErrTeamNotFound{ID: teamID}
	}
	return nil
}

// UpgradeTeamAllTiers atomically upgrades the team tier and promotes every
// active resource, deployment, and stack owned by that team. All four updates
// run inside a single transaction so a partial failure (e.g. ElevateDeployments
// succeeds but Commit fails) cannot leave the DB in a half-upgraded state.
//
// This is the authoritative upgrade function. Call sites:
//   - billing.go handleSubscriptionCharged (Razorpay webhook)
//   - handlers/dev.go POST /internal/set-tier
//
// The admin tier-change path (admin_customers.go ChangeTier) intentionally does
// NOT use this function because (a) it already has its own UpdatePlanTier call
// followed by best-effort elevation, and (b) the admin path also handles
// demotions where the elevation step is skipped entirely. Keeping that path
// separate avoids conflating two different flows.
//
// ElevateResourceTiersByTeam carries the reaper-race guard
// (expires_at > now()), so already-expired resources are never resurrected.
// ElevateDeploymentTiersByTeam and ElevateStackTiersByTeam carry analogous
// terminal-status filters.
func UpgradeTeamAllTiers(ctx context.Context, db *sql.DB, teamID uuid.UUID, newTier string) error {
	return UpgradeTeamAllTiersWithSubscription(ctx, db, teamID, newTier, "")
}

// UpgradeTeamAllTiersWithSubscription is UpgradeTeamAllTiers + an
// atomic SET of teams.stripe_customer_id (the legacy column name for
// razorpay_subscription_id) inside the same transaction.
//
// T4 P2-4 (BugHunt 2026-05-20): the previous flow was
// UpgradeTeamAllTiers → UpdateRazorpaySubscriptionID as two separate
// statements. A crash between them left the team on the paid tier
// with stripe_customer_id still NULL — a later subscription.cancelled
// could not match the team by sub_id and the team stayed paid forever.
// Folding the sub_id write into the upgrade tx closes that window:
// either the team upgrades AND has the sub_id, or nothing changes.
//
// Pass subscriptionID = "" to skip the column update (admin/dev paths
// that have no Razorpay subscription).
func UpgradeTeamAllTiersWithSubscription(ctx context.Context, db *sql.DB, teamID uuid.UUID, newTier, subscriptionID string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("models.UpgradeTeamAllTiers: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// 1a. Update the team's plan tier.
	//
	// B11-P1 (2026-05-20): the UPDATE used to be silent on 0 rows
	// affected. A Razorpay webhook carrying notes.team_id pointing at a
	// non-existent team (typo, deleted-team race, forged synthetic event
	// from anyone with the webhook secret) would land here, the UPDATE
	// would no-op, the function returned nil, and the webhook handler
	// happily 200'd the event — burning the dedup claim and silently
	// "applying" an upgrade to nothing. The downstream
	// EnqueuePendingPropagation then queued a propagation row for a
	// dangling team_id, the entitlement_reconciler logged WARNs forever,
	// and ops had no signal anything was wrong.
	//
	// Fix: check RowsAffected on the team UPDATE. 0 rows → ErrTeamNotFound
	// (returned unwrapped so callers can errors.As). The billing webhook
	// handler maps this to HTTP 404 — Razorpay treats 4xx as non-retryable
	// (won't replay) AND our deleteRazorpayWebhookClaim path releases the
	// dedup claim row so a future event with the correct team_id can be
	// re-processed.
	res, err := tx.ExecContext(ctx, `
		UPDATE teams SET plan_tier = $1 WHERE id = $2
	`, newTier, teamID)
	if err != nil {
		return fmt.Errorf("models.UpgradeTeamAllTiers: update_plan_tier: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("models.UpgradeTeamAllTiers: rows_affected: %w", err)
	}
	if rows == 0 {
		return &ErrTeamNotFound{ID: teamID}
	}

	// 1b. Same row — atomic stripe_customer_id (= razorpay_subscription_id)
	//     write iff a non-empty id was supplied. Inside the same tx so a
	//     crash between the two SETs can't leave NULL sub_id on a paid team.
	if subscriptionID != "" {
		if _, err := tx.ExecContext(ctx, `
			UPDATE teams SET stripe_customer_id = $1 WHERE id = $2
		`, subscriptionID, teamID); err != nil {
			return fmt.Errorf("models.UpgradeTeamAllTiers: set_sub_id: %w", err)
		}
	}

	// 2. Resources — reaper-race guard: only lift non-expired rows.
	// Include 'paused' rows so that a terminated-then-reinstated team's paused
	// resources are promoted to the new tier. Without this, a hobby team that was
	// terminated (resources paused + tier→free) and then re-subscribed to hobby
	// would have their resources stuck at tier='free' and be unable to resume them
	// (the Resume handler re-derives access rights from the resource tier).
	if _, err := tx.ExecContext(ctx, `
		UPDATE resources
		SET tier = $1, expires_at = NULL
		WHERE team_id = $2
		  AND status IN ('active', 'paused')
		  AND (expires_at IS NULL OR expires_at > now())
	`, newTier, teamID); err != nil {
		return fmt.Errorf("models.UpgradeTeamAllTiers: elevate_resources: %w", err)
	}

	// 3. Deployments — clear 24h TTL; skip terminal statuses.
	if _, err := tx.ExecContext(ctx, `
		UPDATE deployments
		SET tier             = $1,
		    expires_at       = NULL,
		    ttl_policy       = 'permanent',
		    reminders_sent   = 0,
		    last_reminder_at = NULL,
		    updated_at       = now()
		WHERE team_id = $2
		  AND status NOT IN ('deleted', 'expired')
	`, newTier, teamID); err != nil {
		return fmt.Errorf("models.UpgradeTeamAllTiers: elevate_deployments: %w", err)
	}

	// 4. Stacks — clear anonymous 24h TTL; skip mid-teardown rows.
	if _, err := tx.ExecContext(ctx, `
		UPDATE stacks
		SET tier       = $1,
		    expires_at = NULL,
		    updated_at = now()
		WHERE team_id = $2
		  AND status NOT IN ('deleting')
	`, newTier, teamID); err != nil {
		return fmt.Errorf("models.UpgradeTeamAllTiers: elevate_stacks: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("models.UpgradeTeamAllTiers: commit: %w", err)
	}
	return nil
}

// GetTeamByRazorpaySubscriptionID looks up a team by Razorpay subscription ID.
func GetTeamByRazorpaySubscriptionID(ctx context.Context, db *sql.DB, subscriptionID string) (*Team, error) {
	t := &Team{}
	err := db.QueryRowContext(ctx, `
		SELECT id, name, plan_tier, stripe_customer_id, created_at,
		       COALESCE(default_deployment_ttl_policy, 'auto_24h'), is_test_cohort
		FROM teams WHERE stripe_customer_id = $1
	`, subscriptionID).Scan(
		&t.ID, &t.Name, &t.PlanTier, &t.RazorpaySubscriptionID, &t.CreatedAt,
		&t.DefaultDeploymentTTLPolicy, &t.IsTestCohort,
	)
	if err == sql.ErrNoRows {
		return nil, &ErrTeamNotFound{}
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetTeamByRazorpaySubscriptionID: %w", err)
	}
	return t, nil
}

// StartTrial removed — see policy memory project_no_trial_pay_day_one.md.
// Anonymous (24h TTL) is the only free tier; hobby/pro/team are paid from
// signup. Migration 034 dropped the trial_ends_at column.

// GetUserByTeamID fetches an owner for the team, or the earliest member if none is marked owner.
func GetUserByTeamID(ctx context.Context, db *sql.DB, teamID uuid.UUID) (*User, error) {
	u := &User{}
	err := db.QueryRowContext(ctx, `
		SELECT id, team_id, email, COALESCE(role, 'member'), github_id, google_id, email_verified, created_at
		FROM users WHERE team_id = $1 AND role = 'owner'
		ORDER BY created_at ASC LIMIT 1
	`, teamID).Scan(
		&u.ID, &u.TeamID, &u.Email, &u.Role, &u.GitHubID, &u.GoogleID, &u.EmailVerified, &u.CreatedAt,
	)
	if err == sql.ErrNoRows {
		err = db.QueryRowContext(ctx, `
			SELECT id, team_id, email, COALESCE(role, 'member'), github_id, google_id, email_verified, created_at
			FROM users WHERE team_id = $1 ORDER BY created_at ASC LIMIT 1
		`, teamID).Scan(
			&u.ID, &u.TeamID, &u.Email, &u.Role, &u.GitHubID, &u.GoogleID, &u.EmailVerified, &u.CreatedAt,
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

// LinkGitHubID sets github_id on an existing user when it is currently NULL.
// Used by the GitHub OAuth find-or-create path to attach a GitHub identity to
// an account first created via magic-link or Google, preventing account
// fragmentation. Mirrors LinkGoogleID.
func LinkGitHubID(ctx context.Context, db *sql.DB, userID uuid.UUID, githubID string) error {
	res, err := db.ExecContext(ctx, `
		UPDATE users SET github_id = $1 WHERE id = $2 AND github_id IS NULL
	`, githubID, userID)
	if err != nil {
		return fmt.Errorf("models.LinkGitHubID: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("models.LinkGitHubID rows: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("models.LinkGitHubID: user %s not updated (already has github_id?)", userID)
	}
	return nil
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
		SELECT id, team_id, email, COALESCE(role, 'member'), github_id, google_id, email_verified, created_at
		FROM users WHERE google_id = $1
	`, googleID).Scan(
		&u.ID, &u.TeamID, &u.Email, &u.Role, &u.GitHubID, &u.GoogleID, &u.EmailVerified, &u.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, &ErrUserNotFound{Email: fmt.Sprintf("google:%s", googleID)}
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetUserByGoogleID: %w", err)
	}
	return u, nil
}
