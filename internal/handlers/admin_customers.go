package handlers

// admin_customers.go — founder-facing customer-management surface served
// under /api/v1/admin/*. All four endpoints are gated on RequireAdmin
// (middleware reads the JWT email against ADMIN_EMAILS, closed by default).
//
// Why this exists: the team dashboard shows the *founder's* team — not all
// teams. To find a paying customer's storage usage, MRR contribution, or
// deploy count without writing a one-off SQL session, the founder needs a
// read-and-light-mutation surface they can hit from a browser or curl.
// HubSpot/Salesforce can't see this data; Postgres can.
//
// Aggregation freshness: every read is a live SQL query against the
// platform DB (no Redis cache). Admin views are low-frequency by definition
// (founder hits the page a few times a day), so the per-request cost is
// trivial and "the dashboard might be 30 seconds stale" is the wrong
// tradeoff here — admin should see ground truth.
//
// All four endpoints return JSON; no HTML. The success agent_action for
// mutating endpoints (tier change, promo issue) follows the U3 contract so
// an LLM agent calling these on behalf of the founder gets verbatim copy
// to relay.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
)

// ─────────────────────────────────────────────────────────────────────────────
// Named constants — every magic string in this file
// ─────────────────────────────────────────────────────────────────────────────

// Tier values an admin is allowed to set via POST /admin/customers/:id/tier.
// Hard-coded (rather than reading from plans.Registry at handler-init time)
// because the admin surface is the operator's safety net — we want the set
// of accepted tiers to be reviewable here, not derived from a YAML file.
const (
	AdminTierFree  = "free"
	AdminTierHobby = "hobby"
	AdminTierPro   = "pro"
	AdminTierTeam  = "team"
)

// adminAllowedTiers is the closed set used for validation. Order matters
// only for the OpenAPI enum order; runtime checks are O(1) via the map.
var adminAllowedTiers = map[string]bool{
	AdminTierFree:  true,
	AdminTierHobby: true,
	AdminTierPro:   true,
	AdminTierTeam:  true,
}

// Audit-log kinds emitted by this handler. Single source of truth for the
// audit-trail consumer (dashboard Recent Activity, BI exports) so a new
// admin action just adds one constant here + writes the row.
//
// AuditKindSubscriptionCanceledByAdmin lives on the models package (so the
// Loops forwarder + webhook handlers can reference the same constant) — see
// models.AuditKindSubscriptionCanceledByAdmin. Aliased here as a local name
// for symmetry with the other admin-handler-emitted kinds.
const (
	AuditKindAdminTierChanged            = "admin.tier_changed"
	AuditKindAdminPromoIssued            = "admin.promo_issued"
	AuditKindSubscriptionCanceledByAdmin = models.AuditKindSubscriptionCanceledByAdmin
)

// Sort keys accepted by GET /admin/customers. Validated against this set
// before going into the ORDER BY clause — never interpolate user-supplied
// strings into SQL.
const (
	AdminSortMRR          = "mrr"
	AdminSortLastActive   = "last_active"
	AdminSortCreatedAt    = "created_at"
	AdminSortStorageBytes = "storage_bytes"
)

// adminListDefaults — defaults applied to GET /admin/customers query
// parameters. defaultLimit is small so a routine browse doesn't pull the
// whole table; the maxLimit cap protects against `?limit=999999`.
const (
	adminListDefaultLimit = 50
	adminListMaxLimit     = 500
	adminAuditDetailLimit = 20
)

// ─────────────────────────────────────────────────────────────────────────────
// Handler
// ─────────────────────────────────────────────────────────────────────────────

// AdminCustomersHandler serves /api/v1/admin/customers/*.
//
// Holds the plans Registry so it can compute monthly-equivalent MRR for
// yearly subscriptions in one place. The DB is the platform DB (teams,
// resources, deployments, audit_log).
//
// CancelSubscription is the indirection used by ChangeTier when a demote
// must also cancel the customer's active Razorpay subscription. Defaulted
// in NewAdminCustomersHandler to a no-op-returning-error so test rigs that
// don't wire a Razorpay portal don't accidentally hit the live API; the
// router replaces it with a portal-backed call. Tests substitute their own
// fake here to assert call-shape + drive the failure path.
type AdminCustomersHandler struct {
	db                 *sql.DB
	plans              *plans.Registry
	CancelSubscription func(subscriptionID string) error
}

// errBillingNotConfigured is the sentinel returned by the default
// CancelSubscription when no Razorpay portal is wired up. Exposed (lowercase)
// only inside this package — handlers swallow it after logging, never
// returning it to the caller. Named (rather than fmt.Errorf at the call
// site) so a future test can errors.Is against it.
var errBillingNotConfigured = errors.New("admin_customers: CancelSubscription not wired — Razorpay portal unavailable")

// NewAdminCustomersHandler constructs the handler. The plans Registry is
// required because MRR computation needs PriceMonthly per tier.
//
// CancelSubscription defaults to a no-op error stub. Callers that need real
// Razorpay cancellation on demote must override CancelSubscription on the
// returned value (see internal/router/router.go for the wiring).
func NewAdminCustomersHandler(db *sql.DB, planRegistry *plans.Registry) *AdminCustomersHandler {
	return &AdminCustomersHandler{
		db:    db,
		plans: planRegistry,
		CancelSubscription: func(string) error {
			return errBillingNotConfigured
		},
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/v1/admin/customers — list teams with aggregates
// ─────────────────────────────────────────────────────────────────────────────

// CustomerListItem is one row in the response.customers array. MRR fields
// are denominated in cents. Yearly subscriptions contribute their
// monthly-equivalent (annual_price / 12) so MRR comparisons are apples-to-
// apples regardless of the customer's billing cycle.
type CustomerListItem struct {
	TeamID            string     `json:"team_id"`
	PrimaryEmail      string     `json:"primary_email"`
	Name              string     `json:"name"`
	Tier              string     `json:"tier"`
	MRRMonthlyCents   int        `json:"mrr_monthly"`
	MRRYearlyCents    int        `json:"mrr_yearly"`
	StorageBytes      int64      `json:"storage_bytes"`
	DeploymentsActive int        `json:"deployments_active"`
	LastActive        *time.Time `json:"last_active"`
	CreatedAt         time.Time  `json:"created_at"`
}

// List handles GET /api/v1/admin/customers. Aggregates per-team usage in
// a single SQL query (no N+1 across resources / deployments / audit_log)
// so a 500-team list still resolves in one round trip.
//
// Query params:
//
//	q         — case-insensitive substring match on users.email (the team's
//	             primary email, picked as the earliest-joined owner). Uses
//	             lower(email) LIKE lower('%q%') so "FOUNDER" matches
//	             "founder@x.com" and "fou" matches "founder@x.com".
//	tier      — exact match on teams.plan_tier ("free", "hobby", "pro", "team").
//	             Empty string → no filter. Multi-value via comma:
//	             tier=hobby,pro → WHERE plan_tier IN ('hobby','pro').
//	             Unknown tier values are silently dropped from the IN list
//	             (rather than 400-ing) so the dashboard's filter pills are
//	             stable: a typo / stale UI value returns an empty list, not
//	             an error banner.
//	sort_by   — mrr | last_active | created_at | storage_bytes (default: mrr)
//	limit     — 1..adminListMaxLimit (default: adminListDefaultLimit)
//	offset    — >= 0 (default: 0)
//
// Response: { ok, customers: [...], total }
func (h *AdminCustomersHandler) List(c *fiber.Ctx) error {
	q := strings.TrimSpace(c.Query("q"))
	tierRaw := strings.TrimSpace(c.Query("tier"))
	sortBy := strings.TrimSpace(c.Query("sort_by"))
	limit := adminParseLimit(c.Query("limit"), adminListDefaultLimit, adminListMaxLimit)
	offset := adminParseOffset(c.Query("offset"))

	// Parse the tier filter. Empty → no filter. Otherwise split on comma
	// (so the dashboard filter pills can OR multiple tiers in one call),
	// validate each value against the closed set, drop unknowns. If every
	// value is unknown we short-circuit to an empty result — see comment
	// on tierAllUnknown below for why this is "UI-stable" rather than 400.
	tiers, tierAllUnknown := adminParseTierFilter(tierRaw)

	orderClause, err := adminOrderClause(sortBy)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_sort_by",
			fmt.Sprintf("sort_by must be one of: %s, %s, %s, %s", AdminSortMRR, AdminSortLastActive, AdminSortCreatedAt, AdminSortStorageBytes))
	}

	// If the user passed only bogus tier values (e.g. stale pill from an
	// older UI build), return an empty list rather than 400. The
	// dashboard's filter UI is "OR a set of pills"; an unknown pill should
	// degrade gracefully ("no customers match that filter") instead of
	// hard-erroring. This is the same posture as `tier=` (no filter, but
	// also no results expected to surface) — UI-stable wins over strict.
	if tierAllUnknown {
		return c.JSON(fiber.Map{
			"ok":        true,
			"customers": []CustomerListItem{},
			"total":     0,
		})
	}

	// Build the aggregation. One CTE per dimension keeps the query plan
	// straightforward and avoids N+1: we LEFT JOIN each aggregate back to
	// teams in the final SELECT. Per the freshness comment at top of file,
	// this is uncached — admin views are low-traffic and need ground truth.
	//
	// MRR is computed in Go from team.plan_tier (handler-side) because the
	// price table lives in plans.yaml, not the DB. We could push it into a
	// CASE WHEN here but that would be a second source of truth — instead
	// we ORDER BY plan_tier (free < hobby < pro < team) when sort_by=mrr,
	// which preserves the visual ordering without duplicating the price
	// table.
	args := []interface{}{}
	whereParts := []string{"1=1"}
	if q != "" {
		// Escape LIKE metacharacters in the user-supplied term so a query of
		// "%" or "_" is matched literally instead of as a wildcard (it would
		// otherwise return every customer). Backslash is the escape char and
		// must itself be escaped first.
		args = append(args, "%"+escapeLikePattern(strings.ToLower(q))+"%")
		whereParts = append(whereParts, fmt.Sprintf("lower(coalesce(u.email,'')) LIKE $%d ESCAPE '\\'", len(args)))
	}
	if len(tiers) == 1 {
		// Single-tier path preserves the existing exact-match query
		// shape (`t.plan_tier = $N`) so PR #48's planner stats stay
		// valid and the EXPLAIN doesn't change for the dominant case.
		args = append(args, tiers[0])
		whereParts = append(whereParts, fmt.Sprintf("t.plan_tier = $%d", len(args)))
	} else if len(tiers) > 1 {
		// Multi-tier path: build a parameterized IN list. Each tier value
		// has already been validated against adminAllowedTiers, so no
		// further escaping is needed beyond the $N placeholders.
		placeholders := make([]string, 0, len(tiers))
		for _, t := range tiers {
			args = append(args, t)
			placeholders = append(placeholders, fmt.Sprintf("$%d", len(args)))
		}
		whereParts = append(whereParts,
			fmt.Sprintf("t.plan_tier IN (%s)", strings.Join(placeholders, ",")))
	}
	where := strings.Join(whereParts, " AND ")

	args = append(args, limit, offset)
	limitOffset := fmt.Sprintf("LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	query := fmt.Sprintf(`
		WITH primary_user AS (
			-- Migration 029 added users.is_primary as the authoritative
			-- "primary user" flag, enforced by uq_users_one_primary_per_team.
			-- We prefer is_primary=true rows, falling back to the legacy
			-- earliest-created-member rule for teams whose backfill is
			-- racing with new signups (defensive only — at-most-one-primary
			-- is a DB invariant).
			SELECT DISTINCT ON (team_id) team_id, email, created_at
			FROM users
			WHERE team_id IS NOT NULL
			ORDER BY team_id, is_primary DESC, (role = 'owner') DESC, created_at ASC
		),
		resource_agg AS (
			SELECT team_id,
			       COALESCE(SUM(storage_bytes), 0) AS total_storage_bytes,
			       MAX(created_at) AS last_resource_at
			FROM resources
			WHERE team_id IS NOT NULL AND status = 'active'
			GROUP BY team_id
		),
		deploy_agg AS (
			-- "active" = a deployment running a pod (building/deploying/healthy),
			-- the same definition models.CountActiveDeploymentsByTeam uses.
			-- P1-E (bug hunt 2026-05-17 round 2): the previous
			-- NOT IN ('deleted','expired') filter counted 'failed' and
			-- 'stopped' deployments too, so this admin column disagreed with
			-- the tier-cap and dashboard counters. The deployments table has no
			-- deleted_at column — lifecycle is tracked entirely via status.
			SELECT team_id, COUNT(*) AS active_deployments, MAX(created_at) AS last_deploy_at
			FROM deployments
			WHERE team_id IS NOT NULL AND status IN ('building', 'deploying', 'healthy')
			GROUP BY team_id
		),
		audit_agg AS (
			SELECT team_id, MAX(created_at) AS last_event_at
			FROM audit_log
			GROUP BY team_id
		)
		SELECT t.id, t.plan_tier, COALESCE(t.name,'') AS name, t.created_at,
		       COALESCE(u.email,'') AS primary_email,
		       COALESCE(r.total_storage_bytes, 0) AS storage_bytes,
		       COALESCE(d.active_deployments, 0) AS deployments_active,
		       GREATEST(
		           COALESCE(a.last_event_at, 'epoch'::timestamptz),
		           COALESCE(d.last_deploy_at, 'epoch'::timestamptz),
		           COALESCE(r.last_resource_at, 'epoch'::timestamptz)
		       ) AS last_active,
		       COUNT(*) OVER () AS total_count
		FROM teams t
		LEFT JOIN primary_user u ON u.team_id = t.id
		LEFT JOIN resource_agg  r ON r.team_id = t.id
		LEFT JOIN deploy_agg    d ON d.team_id = t.id
		LEFT JOIN audit_agg     a ON a.team_id = t.id
		WHERE %s
		ORDER BY %s
		%s
	`, where, orderClause, limitOffset)

	rows, err := h.db.QueryContext(c.Context(), query, args...)
	if err != nil {
		slog.Error("admin.customers.list.query_failed", "error", err)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed",
			"Failed to list customers")
	}
	defer func() { _ = rows.Close() }()

	out := make([]CustomerListItem, 0, limit)
	var total int
	for rows.Next() {
		var (
			id            uuid.UUID
			planTier      string
			name          string
			createdAt     time.Time
			email         string
			storageBytes  int64
			deploys       int
			lastActiveRaw time.Time
		)
		if err := rows.Scan(&id, &planTier, &name, &createdAt, &email,
			&storageBytes, &deploys, &lastActiveRaw, &total); err != nil {
			slog.Error("admin.customers.list.scan_failed", "error", err)
			return respondError(c, fiber.StatusServiceUnavailable, "db_failed",
				"Failed to scan customer row")
		}
		monthly, yearly := h.computeMRR(planTier)
		item := CustomerListItem{
			TeamID:            id.String(),
			PrimaryEmail:      email,
			Name:              name,
			Tier:              planTier,
			MRRMonthlyCents:   monthly,
			MRRYearlyCents:    yearly,
			StorageBytes:      storageBytes,
			DeploymentsActive: deploys,
			CreatedAt:         createdAt,
		}
		// Don't surface the 'epoch' sentinel — turn it into nil so the
		// dashboard can show "—" instead of "1970-01-01".
		if !lastActiveRaw.IsZero() && lastActiveRaw.Year() > 1970 {
			la := lastActiveRaw
			item.LastActive = &la
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		slog.Error("admin.customers.list.rows_err", "error", err)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed",
			"Failed to iterate customer rows")
	}

	// When sort_by=mrr the SQL ORDER BY uses plan_tier rank — but identical
	// tiers should be ordered by the actual monthly price (yearly customers
	// > monthly customers if their yearly happens to be discounted, etc.).
	// In practice all customers on the same canonical tier carry the same
	// monthly-equivalent MRR, so this resolves to a stable tie-break by
	// created_at DESC which the SQL already does. No extra sort needed.

	return c.JSON(fiber.Map{
		"ok":        true,
		"customers": out,
		"total":     total,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/v1/admin/customers/:team_id — customer detail
// ─────────────────────────────────────────────────────────────────────────────

// CustomerDetailUser is one user row in the detail response.
type CustomerDetailUser struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

// CustomerDetailResourceSummary aggregates per-resource-type totals.
type CustomerDetailResourceSummary struct {
	ResourceType string `json:"resource_type"`
	Count        int    `json:"count"`
	StorageBytes int64  `json:"storage_bytes"`
}

// CustomerDetailAuditItem is one recent audit_log row.
type CustomerDetailAuditItem struct {
	ID        string          `json:"id"`
	Actor     string          `json:"actor"`
	Kind      string          `json:"kind"`
	Summary   string          `json:"summary"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

// CustomerDetail is the full response for GET /admin/customers/:team_id.
//
// Historical note: TrialEndsAt was a field on this struct until 2026-05-14;
// removed per policy memory project_no_trial_pay_day_one.md.
type CustomerDetail struct {
	TeamID                 string                          `json:"team_id"`
	Name                   string                          `json:"name"`
	Tier                   string                          `json:"tier"`
	MRRMonthlyCents        int                             `json:"mrr_monthly"`
	CreatedAt              time.Time                       `json:"created_at"`
	RazorpaySubscriptionID string                          `json:"razorpay_subscription_id,omitempty"`
	Users                  []CustomerDetailUser            `json:"users"`
	Resources              []CustomerDetailResourceSummary `json:"resources"`
	DeploymentsActive      int                             `json:"deployments_active"`
	RecentAudit            []CustomerDetailAuditItem       `json:"recent_audit"`
}

// Detail handles GET /api/v1/admin/customers/:team_id.
func (h *AdminCustomersHandler) Detail(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(c.Params("team_id"))
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_team_id", "team_id must be a UUID")
	}

	team, err := models.GetTeamByID(c.Context(), h.db, teamID)
	if err != nil {
		var nf *models.ErrTeamNotFound
		if errors.As(err, &nf) {
			return respondError(c, fiber.StatusNotFound, "team_not_found", "no such team")
		}
		slog.Error("admin.customers.detail.team_query_failed", "error", err, "team_id", teamID)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "Failed to load team")
	}

	monthly, _ := h.computeMRR(team.PlanTier)
	out := CustomerDetail{
		TeamID:          team.ID.String(),
		Name:            team.Name.String,
		Tier:            team.PlanTier,
		MRRMonthlyCents: monthly,
		CreatedAt:       team.CreatedAt,
		Users:           []CustomerDetailUser{},
		Resources:       []CustomerDetailResourceSummary{},
		RecentAudit:     []CustomerDetailAuditItem{},
	}
	if team.RazorpaySubscriptionID.Valid {
		out.RazorpaySubscriptionID = team.RazorpaySubscriptionID.String
	}
	// trial removed — see project_no_trial_pay_day_one.md.

	// Users.
	userRows, err := h.db.QueryContext(c.Context(), `
		SELECT id, email, COALESCE(role,'member'), created_at
		FROM users
		WHERE team_id = $1
		ORDER BY created_at ASC
	`, teamID)
	if err != nil {
		slog.Error("admin.customers.detail.users_query_failed", "error", err, "team_id", teamID)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "Failed to load users")
	}
	for userRows.Next() {
		var u CustomerDetailUser
		var id uuid.UUID
		if err := userRows.Scan(&id, &u.Email, &u.Role, &u.CreatedAt); err != nil {
			_ = userRows.Close() // result set fully consumed; close error irrelevant
			return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "Failed to scan user row")
		}
		u.ID = id.String()
		out.Users = append(out.Users, u)
	}
	_ = userRows.Close() // result set fully consumed; close error irrelevant

	// Resource summary.
	resRows, err := h.db.QueryContext(c.Context(), `
		SELECT resource_type, COUNT(*), COALESCE(SUM(storage_bytes), 0)
		FROM resources
		WHERE team_id = $1 AND status = 'active'
		GROUP BY resource_type
		ORDER BY resource_type
	`, teamID)
	if err != nil {
		slog.Error("admin.customers.detail.resources_query_failed", "error", err, "team_id", teamID)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "Failed to load resources")
	}
	for resRows.Next() {
		var rs CustomerDetailResourceSummary
		if err := resRows.Scan(&rs.ResourceType, &rs.Count, &rs.StorageBytes); err != nil {
			_ = resRows.Close() // result set fully consumed; close error irrelevant
			return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "Failed to scan resource row")
		}
		out.Resources = append(out.Resources, rs)
	}
	_ = resRows.Close() // result set fully consumed; close error irrelevant

	// Deployment count.
	deployCount, err := models.CountActiveDeploymentsByTeam(c.Context(), h.db, teamID)
	if err != nil {
		// Non-fatal — log and continue with 0.
		slog.Warn("admin.customers.detail.deploy_count_failed", "error", err, "team_id", teamID)
	}
	out.DeploymentsActive = deployCount

	// Recent audit — newest first, capped at adminAuditDetailLimit.
	auditRows, err := h.db.QueryContext(c.Context(), `
		SELECT id, actor, kind, summary, metadata, created_at
		FROM audit_log
		WHERE team_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`, teamID, adminAuditDetailLimit)
	if err != nil {
		slog.Error("admin.customers.detail.audit_query_failed", "error", err, "team_id", teamID)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "Failed to load audit log")
	}
	for auditRows.Next() {
		var ai CustomerDetailAuditItem
		var id uuid.UUID
		var meta sql.NullString
		if err := auditRows.Scan(&id, &ai.Actor, &ai.Kind, &ai.Summary, &meta, &ai.CreatedAt); err != nil {
			_ = auditRows.Close() // result set fully consumed; close error irrelevant
			return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "Failed to scan audit row")
		}
		ai.ID = id.String()
		if meta.Valid && meta.String != "" {
			ai.Metadata = json.RawMessage(meta.String)
		}
		out.RecentAudit = append(out.RecentAudit, ai)
	}
	_ = auditRows.Close() // result set fully consumed; close error irrelevant

	return c.JSON(fiber.Map{
		"ok":       true,
		"customer": out,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/v1/admin/customers/:team_id/tier — manual tier change
// ─────────────────────────────────────────────────────────────────────────────

// adminTierChangeRequest is the JSON body for POST /admin/customers/:id/tier.
type adminTierChangeRequest struct {
	Tier   string `json:"tier"`
	Reason string `json:"reason"`
}

// adminTierChangeMetadata is what gets stored in audit_log.metadata so a
// future BI consumer can answer "who changed which team's tier and why."
// Promoted to a named struct rather than an inline map so the audit schema
// is a typed contract.
type adminTierChangeMetadata struct {
	From         string `json:"from"`
	To           string `json:"to"`
	ByAdminEmail string `json:"by_admin_email"`
	Reason       string `json:"reason"`
}

// adminSubscriptionCanceledByAdminMetadata is the audit_log.metadata payload
// emitted alongside an admin demote when an active Razorpay subscription
// gets canceled out-of-band. The shape is provider-agnostic on purpose: the
// Brevo / Loops template ID is operator-defined and keyed on the audit
// `kind`, not on this metadata. Fields:
//
//	FromTier / ToTier      — the demote transition (e.g. pro → hobby).
//	ByAdminEmail           — who pushed the button (same as the tier-change row).
//	Reason                 — the admin-supplied reason string.
//	SubscriptionID         — the Razorpay sub id that was canceled (or
//	                         empty when the team had no active sub).
//	CancelAttempted        — true iff we made the Razorpay API call. False
//	                         when SubscriptionID was empty (nothing to cancel).
//	CancelSucceeded        — true iff the Razorpay call returned no error.
//	                         When false + CancelAttempted true, the operator
//	                         must manually reconcile in the Razorpay dashboard;
//	                         Brevo must NOT send a "we canceled" email.
//	CancelError            — short error string for the operator (only set
//	                         when CancelSucceeded is false). Not surfaced to
//	                         the customer — internal-only.
type adminSubscriptionCanceledByAdminMetadata struct {
	FromTier        string `json:"from_tier"`
	ToTier          string `json:"to_tier"`
	ByAdminEmail    string `json:"by_admin_email"`
	Reason          string `json:"reason"`
	SubscriptionID  string `json:"subscription_id"`
	CancelAttempted bool   `json:"cancel_attempted"`
	CancelSucceeded bool   `json:"cancel_succeeded"`
	CancelError     string `json:"cancel_error,omitempty"`
}

// ChangeTier handles POST /api/v1/admin/customers/:team_id/tier.
//
// Promote path (toTier > fromTier): does NOT touch Razorpay — the use case
// is comp / customer-success promotion ("on-the-house upgrade for this beta
// tester"). For an actual paid upgrade the customer hits checkout and the
// Razorpay webhook drives the tier change.
//
// Demote path (toTier < fromTier): ALSO cancels the team's active Razorpay
// subscription via h.CancelSubscription (immediate cancel — see
// razorpaybilling.Portal.CancelImmediately for the rationale around
// MRR-cycle hygiene). If the team has no subscription_id, we skip the
// Razorpay call but still emit a subscription.canceled_by_admin audit row
// (with cancel_attempted=false) so the audit log is consistent across the
// "they were paying" vs "they were on a comp tier" cases. If the Razorpay
// call fails the handler STILL returns 200 — the DB-side demote already
// succeeded, the audit row records cancel_succeeded=false, and the operator
// reconciles manually in the Razorpay dashboard. This fail-open posture is
// the same we use for resource elevation: never block an admin action on a
// downstream provider hiccup.
func (h *AdminCustomersHandler) ChangeTier(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(c.Params("team_id"))
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_team_id", "team_id must be a UUID")
	}

	var req adminTierChangeRequest
	if err := c.BodyParser(&req); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "JSON body required")
	}
	req.Tier = strings.TrimSpace(strings.ToLower(req.Tier))
	req.Reason = strings.TrimSpace(req.Reason)
	if !adminAllowedTiers[req.Tier] {
		return respondError(c, fiber.StatusBadRequest, "invalid_tier",
			fmt.Sprintf("tier must be one of: %s, %s, %s, %s", AdminTierFree, AdminTierHobby, AdminTierPro, AdminTierTeam))
	}
	if req.Reason == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_reason",
			"reason is required so the audit trail records why the tier changed")
	}

	team, err := models.GetTeamByID(c.Context(), h.db, teamID)
	if err != nil {
		var nf *models.ErrTeamNotFound
		if errors.As(err, &nf) {
			return respondError(c, fiber.StatusNotFound, "team_not_found", "no such team")
		}
		slog.Error("admin.customers.tier.team_query_failed", "error", err, "team_id", teamID)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "Failed to load team")
	}
	fromTier := team.PlanTier
	if fromTier == req.Tier {
		return respondError(c, fiber.StatusConflict, "tier_unchanged",
			fmt.Sprintf("team is already on tier %s", req.Tier))
	}

	if err := models.UpdatePlanTier(c.Context(), h.db, teamID, req.Tier); err != nil {
		slog.Error("admin.customers.tier.update_failed", "error", err, "team_id", teamID)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "Failed to update tier")
	}

	fromR := plans.Rank(fromTier)
	toR := plans.Rank(req.Tier)
	// Guard against the -1 sentinel (unknown tier on either side).
	// adminAllowedTiers already restricts req.Tier to {free,hobby,pro,team}
	// at validate-time, but fromTier comes straight from the DB and could
	// historically have been anonymous/growth on some teams — treat any
	// negative rank as "no transition direction" rather than guessing.
	isDemote := fromR >= 0 && toR >= 0 && toR < fromR

	// Promote existing permanent resources only when this is a real
	// promotion (rank goes up). Downgrades leave existing rows on their
	// current tier — same user-benefit policy as the Razorpay path.
	if toR > fromR {
		if err := models.ElevateResourceTiersByTeam(c.Context(), h.db, teamID, req.Tier); err != nil {
			slog.Warn("admin.customers.tier.elevate_resources_failed", "error", err, "team_id", teamID)
		}
		if err := models.ElevateDeploymentTiersByTeam(c.Context(), h.db, teamID, req.Tier); err != nil {
			slog.Warn("admin.customers.tier.elevate_deployments_failed", "error", err, "team_id", teamID)
		}
		if err := models.ElevateStackTiersByTeam(c.Context(), h.db, teamID, req.Tier); err != nil {
			slog.Warn("admin.customers.tier.elevate_stacks_failed", "error", err, "team_id", teamID)
		}
	}

	adminEmail := middleware.GetEmail(c)
	meta, _ := json.Marshal(adminTierChangeMetadata{
		From:         fromTier,
		To:           req.Tier,
		ByAdminEmail: adminEmail,
		Reason:       req.Reason,
	})
	_ = models.InsertAuditEvent(c.Context(), h.db, models.AuditEvent{
		TeamID:   teamID,
		Actor:    "admin",
		Kind:     AuditKindAdminTierChanged,
		Summary:  fmt.Sprintf("admin %s changed tier %s → %s", adminEmail, fromTier, req.Tier),
		Metadata: meta,
	})

	// Demote → cancel Razorpay subscription (best-effort) + emit the
	// canceled_by_admin audit row. Promotes skip this block entirely so the
	// comp-promotion path is unchanged.
	if isDemote {
		h.cancelOnDemote(c, teamID, team, fromTier, req.Tier, req.Reason, adminEmail)
	}

	return c.JSON(fiber.Map{
		"ok":           true,
		"team_id":      teamID.String(),
		"from":         fromTier,
		"to":           req.Tier,
		"agent_action": newAgentActionAdminTierChanged(teamID.String(), req.Tier),
	})
}

// cancelOnDemote is the demote-side leg of ChangeTier. Extracted so the
// happy path remains readable and so the cancel + audit semantics live in
// one place. Never returns an error — failures are logged + recorded in
// the audit row's cancel_succeeded=false field. The caller continues with
// a 200 response regardless.
//
// Three branches:
//
//  1. team has no Razorpay subscription_id on file (comp-tier customer,
//     never paid) → no Razorpay call, audit row written with
//     cancel_attempted=false. Logged at WARN so the operator notices a
//     paying-tier team without a subscription_id (data inconsistency).
//
//  2. CancelSubscription returns nil → audit row records
//     cancel_attempted=true + cancel_succeeded=true. Brevo can fire its
//     "we canceled your subscription" template.
//
//  3. CancelSubscription returns an error → audit row records
//     cancel_attempted=true + cancel_succeeded=false + a short error
//     string. Logged at ERROR so on-call sees it. Brevo template must
//     check cancel_succeeded before claiming we canceled anything.
func (h *AdminCustomersHandler) cancelOnDemote(c *fiber.Ctx, teamID uuid.UUID, team *models.Team, fromTier, toTier, reason, adminEmail string) {
	subID := ""
	if team.RazorpaySubscriptionID.Valid {
		subID = strings.TrimSpace(team.RazorpaySubscriptionID.String)
	}

	auditMeta := adminSubscriptionCanceledByAdminMetadata{
		FromTier:       fromTier,
		ToTier:         toTier,
		ByAdminEmail:   adminEmail,
		Reason:         reason,
		SubscriptionID: subID,
	}

	switch subID {
	case "":
		// No subscription on file. Still emit an audit row so the BI/Loops
		// consumer sees the demote transition uniformly — but with
		// cancel_attempted=false so the email template knows nothing was
		// charged-to-canceled.
		slog.Warn("admin.customers.tier.demote_no_subscription_id",
			"team_id", teamID, "from", fromTier, "to", toTier,
			"reason", "team has paying tier but no razorpay_subscription_id — operator should verify")
		auditMeta.CancelAttempted = false
		auditMeta.CancelSucceeded = false

	default:
		auditMeta.CancelAttempted = true
		if err := h.CancelSubscription(subID); err != nil {
			// Log loudly. The team is already demoted in our DB, so the
			// operator must reconcile manually in Razorpay (or retry the
			// demote, which is now a same-tier 409 — so they'd cancel
			// directly in the Razorpay dashboard).
			slog.Error("admin.customers.tier.razorpay_cancel_failed",
				"team_id", teamID, "subscription_id", subID,
				"from", fromTier, "to", toTier, "error", err)
			auditMeta.CancelSucceeded = false
			auditMeta.CancelError = err.Error()
		} else {
			auditMeta.CancelSucceeded = true
		}
	}

	metaBlob, _ := json.Marshal(auditMeta)
	summary := fmt.Sprintf("admin %s canceled subscription on demote %s → %s", adminEmail, fromTier, toTier)
	if auditMeta.CancelAttempted && !auditMeta.CancelSucceeded {
		summary = fmt.Sprintf("admin %s attempted to cancel subscription on demote %s → %s — RAZORPAY CALL FAILED", adminEmail, fromTier, toTier)
	}
	if !auditMeta.CancelAttempted {
		summary = fmt.Sprintf("admin %s demoted %s → %s — no Razorpay subscription on file", adminEmail, fromTier, toTier)
	}
	_ = models.InsertAuditEvent(c.Context(), h.db, models.AuditEvent{
		TeamID:   teamID,
		Actor:    "admin",
		Kind:     AuditKindSubscriptionCanceledByAdmin,
		Summary:  summary,
		Metadata: metaBlob,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/v1/admin/customers/:team_id/promo — issue a single-use promo code
// ─────────────────────────────────────────────────────────────────────────────

// adminIssuePromoRequest is the JSON body for POST /admin/customers/:id/promo.
type adminIssuePromoRequest struct {
	Kind         string `json:"kind"`
	Value        int    `json:"value"`
	AppliesTo    int    `json:"applies_to"`
	ValidForDays int    `json:"valid_for_days"`
}

// adminPromoIssueMetadata is the audit_log.metadata blob for promo issuance.
type adminPromoIssueMetadata struct {
	Code         string `json:"code"`
	Kind         string `json:"kind"`
	Value        int    `json:"value"`
	AppliesTo    int    `json:"applies_to,omitempty"`
	ValidForDays int    `json:"valid_for_days"`
	ByAdminEmail string `json:"by_admin_email"`
}

// IssuePromo handles POST /api/v1/admin/customers/:team_id/promo.
func (h *AdminCustomersHandler) IssuePromo(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(c.Params("team_id"))
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_team_id", "team_id must be a UUID")
	}

	var req adminIssuePromoRequest
	if err := c.BodyParser(&req); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "JSON body required")
	}
	req.Kind = strings.TrimSpace(strings.ToLower(req.Kind))
	if !models.IsValidPromoKind(req.Kind) {
		return respondError(c, fiber.StatusBadRequest, "invalid_kind",
			fmt.Sprintf("kind must be one of: %s, %s, %s",
				models.PromoKindPercentOff, models.PromoKindFirstMonthFree, models.PromoKindAmountOff))
	}
	if req.ValidForDays <= 0 {
		return respondError(c, fiber.StatusBadRequest, "invalid_valid_for_days",
			"valid_for_days must be > 0")
	}
	if req.Kind == models.PromoKindPercentOff && (req.Value <= 0 || req.Value > 100) {
		return respondError(c, fiber.StatusBadRequest, "invalid_value",
			"percent_off value must be 1..100")
	}
	if req.Kind == models.PromoKindAmountOff && req.Value <= 0 {
		return respondError(c, fiber.StatusBadRequest, "invalid_value",
			"amount_off value (cents) must be > 0")
	}

	if _, err := models.GetTeamByID(c.Context(), h.db, teamID); err != nil {
		var nf *models.ErrTeamNotFound
		if errors.As(err, &nf) {
			return respondError(c, fiber.StatusNotFound, "team_not_found", "no such team")
		}
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "Failed to load team")
	}

	adminEmail := middleware.GetEmail(c)
	row, err := models.IssueAdminPromoCode(c.Context(), h.db, models.CreateAdminPromoCodeParams{
		TeamID:        teamID,
		IssuedByEmail: adminEmail,
		Kind:          req.Kind,
		Value:         req.Value,
		AppliesTo:     req.AppliesTo,
		ValidForDays:  req.ValidForDays,
	})
	if err != nil {
		if errors.Is(err, models.ErrInvalidPromoKind) ||
			errors.Is(err, models.ErrInvalidPromoDuration) ||
			errors.Is(err, models.ErrInvalidPromoValue) {
			return respondError(c, fiber.StatusBadRequest, "invalid_promo", err.Error())
		}
		slog.Error("admin.customers.promo.insert_failed", "error", err, "team_id", teamID)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "Failed to issue promo code")
	}

	meta, _ := json.Marshal(adminPromoIssueMetadata{
		Code:         row.Code,
		Kind:         row.Kind,
		Value:        row.Value,
		AppliesTo:    req.AppliesTo,
		ValidForDays: req.ValidForDays,
		ByAdminEmail: adminEmail,
	})
	_ = models.InsertAuditEvent(c.Context(), h.db, models.AuditEvent{
		TeamID:   teamID,
		Actor:    "admin",
		Kind:     AuditKindAdminPromoIssued,
		Summary:  fmt.Sprintf("admin %s issued promo %s (%s/%d)", adminEmail, row.Code, row.Kind, row.Value),
		Metadata: meta,
	})

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"ok":           true,
		"code":         row.Code,
		"team_id":      teamID.String(),
		"kind":         row.Kind,
		"value":        row.Value,
		"expires_at":   row.ExpiresAt,
		"agent_action": newAgentActionAdminPromoIssued(teamID.String(), row.Code),
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// computeMRR returns (monthly_cents, yearly_cents) for a canonical tier.
// Yearly is the annualized version (monthly * 12); monthly is the per-month
// charge regardless of the customer's billing cycle (so a $99 yearly
// subscription on Pro contributes ~$8/month for sort-by-MRR purposes).
//
// All canonical tiers are looked up via the plans Registry — never
// hardcoded. Unknown tiers (e.g. test fixtures) resolve to 0.
func (h *AdminCustomersHandler) computeMRR(tier string) (int, int) {
	if h.plans == nil {
		return 0, 0
	}
	canonical := plans.CanonicalTier(tier)
	monthly := h.plans.PriceMonthly(canonical)
	return monthly, monthly * 12
}

// adminParseTierFilter parses the ?tier query value into the deduped set
// of valid tier strings to OR together in the WHERE clause.
//
// Return contract:
//
//	raw=""              → (nil,   false)  — no filter, fetch everything
//	raw="pro"           → (["pro"], false) — single-tier (preserves PR #48 path)
//	raw="hobby,pro"     → (["hobby","pro"], false)
//	raw="hobby, ,pro"   → (["hobby","pro"], false)  — whitespace/empty tolerated
//	raw="HOBBY"         → (["hobby"], false)         — case-insensitive
//	raw="platinum"      → (nil, true)  — all values unknown; caller short-circuits to empty list
//	raw="pro,platinum"  → (["pro"], false) — partial-unknown: keep the valid ones
//
// The "all unknown → empty list" branch keeps the dashboard filter pills
// UI-stable: a stale or typo'd value renders "no results" rather than a
// 400 error banner. See the comment in List() for the full rationale.
// likeEscapeReplacer escapes the three SQL LIKE metacharacters with a
// backslash. Backslash itself is escaped first (it is also the ESCAPE char),
// so the replacement order is fixed and order-independent here.
var likeEscapeReplacer = strings.NewReplacer(
	`\`, `\\`,
	`%`, `\%`,
	`_`, `\_`,
)

// escapeLikePattern makes a user-supplied search term safe to embed in a
// `LIKE '%' || term || '%' ESCAPE '\'` clause: "%" and "_" become literal
// characters instead of wildcards. Without it an admin search of "%" returns
// every customer.
func escapeLikePattern(s string) string {
	return likeEscapeReplacer.Replace(s)
}

func adminParseTierFilter(raw string) ([]string, bool) {
	if raw == "" {
		return nil, false
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]bool{}
	sawAny := false
	for _, p := range parts {
		v := strings.ToLower(strings.TrimSpace(p))
		if v == "" {
			continue
		}
		sawAny = true
		if !adminAllowedTiers[v] {
			continue
		}
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	if len(out) == 0 {
		// Distinguish "no values at all (whitespace, commas)" — treat as
		// no filter — from "values present but all unknown" — caller
		// short-circuits to an empty result.
		if !sawAny {
			return nil, false
		}
		return nil, true
	}
	return out, false
}

// adminParseLimit clamps a ?limit query value into [1, max], defaulting to
// def when missing/invalid. Centralized so all four admin endpoints agree.
func adminParseLimit(raw string, def, max int) int {
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

// adminParseOffset clamps a ?offset query value to >= 0.
func adminParseOffset(raw string) int {
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// adminOrderClause maps sort_by to a safe ORDER BY clause. NEVER
// interpolate raw sort_by into SQL — this whitelist is what makes the path
// injection-proof.
//
// Tie-break is always created_at DESC so paging is deterministic. NULLS
// LAST on last_active so empty teams don't pin to the top.
func adminOrderClause(sortBy string) (string, error) {
	switch sortBy {
	case "", AdminSortMRR:
		// SQL can't see plan_tier prices (those live in plans.yaml), but
		// the canonical tier ordering matches MRR rank: team > pro >
		// hobby > free. Use a CASE so the ORDER BY is a pure SQL
		// expression — no Go-side post-sort needed for paging.
		return `CASE t.plan_tier
		           WHEN 'team' THEN 4
		           WHEN 'pro' THEN 3
		           WHEN 'hobby' THEN 2
		           WHEN 'free' THEN 1
		           ELSE 0
		        END DESC, t.created_at DESC`, nil
	case AdminSortLastActive:
		return `GREATEST(
		           COALESCE(a.last_event_at, 'epoch'::timestamptz),
		           COALESCE(d.last_deploy_at, 'epoch'::timestamptz),
		           COALESCE(r.last_resource_at, 'epoch'::timestamptz)
		        ) DESC NULLS LAST, t.created_at DESC`, nil
	case AdminSortCreatedAt:
		return `t.created_at DESC`, nil
	case AdminSortStorageBytes:
		return `COALESCE(r.total_storage_bytes, 0) DESC, t.created_at DESC`, nil
	}
	return "", fmt.Errorf("invalid sort_by: %s", sortBy)
}
