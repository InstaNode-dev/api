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
const (
	AuditKindAdminTierChanged = "admin.tier_changed"
	AuditKindAdminPromoIssued = "admin.promo_issued"
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
type AdminCustomersHandler struct {
	db    *sql.DB
	plans *plans.Registry
}

// NewAdminCustomersHandler constructs the handler. The plans Registry is
// required because MRR computation needs PriceMonthly per tier.
func NewAdminCustomersHandler(db *sql.DB, planRegistry *plans.Registry) *AdminCustomersHandler {
	return &AdminCustomersHandler{db: db, plans: planRegistry}
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
//	             primary email, picked as the earliest-joined owner)
//	tier      — exact match on teams.plan_tier ("free", "hobby", "pro", "team")
//	sort_by   — mrr | last_active | created_at | storage_bytes (default: mrr)
//	limit     — 1..adminListMaxLimit (default: adminListDefaultLimit)
//	offset    — >= 0 (default: 0)
//
// Response: { ok, customers: [...], total }
func (h *AdminCustomersHandler) List(c *fiber.Ctx) error {
	q := strings.TrimSpace(c.Query("q"))
	tier := strings.TrimSpace(c.Query("tier"))
	sortBy := strings.TrimSpace(c.Query("sort_by"))
	limit := adminParseLimit(c.Query("limit"), adminListDefaultLimit, adminListMaxLimit)
	offset := adminParseOffset(c.Query("offset"))

	if tier != "" && !adminAllowedTiers[tier] {
		return respondError(c, fiber.StatusBadRequest, "invalid_tier",
			fmt.Sprintf("tier must be one of: %s, %s, %s, %s", AdminTierFree, AdminTierHobby, AdminTierPro, AdminTierTeam))
	}

	orderClause, err := adminOrderClause(sortBy)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_sort_by",
			fmt.Sprintf("sort_by must be one of: %s, %s, %s, %s", AdminSortMRR, AdminSortLastActive, AdminSortCreatedAt, AdminSortStorageBytes))
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
		args = append(args, "%"+strings.ToLower(q)+"%")
		whereParts = append(whereParts, fmt.Sprintf("lower(coalesce(u.email,'')) LIKE $%d", len(args)))
	}
	if tier != "" {
		args = append(args, tier)
		whereParts = append(whereParts, fmt.Sprintf("t.plan_tier = $%d", len(args)))
	}
	where := strings.Join(whereParts, " AND ")

	args = append(args, limit, offset)
	limitOffset := fmt.Sprintf("LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	query := fmt.Sprintf(`
		WITH primary_user AS (
			SELECT DISTINCT ON (team_id) team_id, email, created_at
			FROM users
			WHERE team_id IS NOT NULL
			ORDER BY team_id, (role = 'owner') DESC, created_at ASC
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
			SELECT team_id, COUNT(*) AS active_deployments, MAX(created_at) AS last_deploy_at
			FROM deployments
			WHERE team_id IS NOT NULL AND deleted_at IS NULL
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
	defer rows.Close()

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
type CustomerDetail struct {
	TeamID                 string                          `json:"team_id"`
	Name                   string                          `json:"name"`
	Tier                   string                          `json:"tier"`
	MRRMonthlyCents        int                             `json:"mrr_monthly"`
	CreatedAt              time.Time                       `json:"created_at"`
	RazorpaySubscriptionID string                          `json:"razorpay_subscription_id,omitempty"`
	TrialEndsAt            *time.Time                      `json:"trial_ends_at,omitempty"`
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
	if team.TrialEndsAt.Valid {
		ts := team.TrialEndsAt.Time
		out.TrialEndsAt = &ts
	}

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
			userRows.Close()
			return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "Failed to scan user row")
		}
		u.ID = id.String()
		out.Users = append(out.Users, u)
	}
	userRows.Close()

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
			resRows.Close()
			return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "Failed to scan resource row")
		}
		out.Resources = append(out.Resources, rs)
	}
	resRows.Close()

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
			auditRows.Close()
			return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "Failed to scan audit row")
		}
		ai.ID = id.String()
		if meta.Valid && meta.String != "" {
			ai.Metadata = json.RawMessage(meta.String)
		}
		out.RecentAudit = append(out.RecentAudit, ai)
	}
	auditRows.Close()

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

// ChangeTier handles POST /api/v1/admin/customers/:team_id/tier.
//
// Does NOT touch Razorpay — the use case is comp / customer-success
// promotion ("on-the-house upgrade for this beta tester"). For an actual
// paid upgrade the customer hits checkout and the Razorpay webhook drives
// the tier change. Documented at the route + in the OpenAPI description.
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

	// Promote existing permanent resources only when this is a real
	// promotion (rank goes up). Downgrades leave existing rows on their
	// current tier — same user-benefit policy as the Razorpay path.
	if adminTierRank(req.Tier) > adminTierRank(fromTier) {
		if err := models.ElevateResourceTiersByTeam(c.Context(), h.db, teamID, req.Tier); err != nil {
			slog.Warn("admin.customers.tier.elevate_failed", "error", err, "team_id", teamID)
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

	return c.JSON(fiber.Map{
		"ok":           true,
		"team_id":      teamID.String(),
		"from":         fromTier,
		"to":           req.Tier,
		"agent_action": newAgentActionAdminTierChanged(teamID.String(), req.Tier),
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

// adminTierRank returns the rank of a tier for promote-vs-downgrade
// detection. Higher = more privileged. Unknown tiers rank as -1 so they
// never trigger an unintended elevation.
func adminTierRank(tier string) int {
	switch tier {
	case AdminTierTeam:
		return 4
	case AdminTierPro:
		return 3
	case AdminTierHobby:
		return 2
	case AdminTierFree:
		return 1
	}
	return -1
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

