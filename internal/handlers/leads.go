package handlers

// leads.go — POST /api/v1/leads (Wave-3 task A5).
//
// Captures enterprise/Team-tier contact intent from the pricing page "Talk to
// us" form, replacing the mailto: link with a durable DB record. Public
// endpoint — no auth required. An authenticated caller's team_id is recorded
// so we can skip duplicate outreach for known teams.
//
// Flow:
//   POST /api/v1/leads {email, name?, company?, use_case?}
//     → validate → INSERT enterprise_leads → 201 {ok:true, id:"<uuid>"}
//
// Rate-limited to 5 submissions per /24+ASN fingerprint per hour to prevent
// form-spam without blocking legitimate submits from corporate NAT.

import (
	"context"
	"database/sql"
	"log/slog"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"instant.dev/internal/middleware"
)

const (
	leadsEmailMaxLen   = 254
	leadsNameMaxLen    = 128
	leadsCompanyMaxLen = 128
	leadsUseCaseMaxLen = 1024
)

// LeadsHandler serves POST /api/v1/leads.
type LeadsHandler struct {
	db *sql.DB
}

func NewLeadsHandler(db *sql.DB) *LeadsHandler {
	return &LeadsHandler{db: db}
}

type createLeadBody struct {
	Email   string `json:"email"`
	Name    string `json:"name,omitempty"`
	Company string `json:"company,omitempty"`
	UseCase string `json:"use_case,omitempty"`
}

// Create handles POST /api/v1/leads.
// Public — no RequireAuth. The caller's team_id is captured when present
// (authenticated request) so outreach can be correlated to an existing account.
func (h *LeadsHandler) Create(c *fiber.Ctx) error {
	var body createLeadBody
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "Request body must be valid JSON")
	}

	body.Email = strings.TrimSpace(body.Email)
	body.Name = strings.TrimSpace(body.Name)
	body.Company = strings.TrimSpace(body.Company)
	body.UseCase = strings.TrimSpace(body.UseCase)

	if body.Email == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_email", "email is required")
	}
	if len(body.Email) > leadsEmailMaxLen {
		return respondError(c, fiber.StatusBadRequest, "invalid_email_format", "email exceeds maximum length")
	}
	if !isValidEmail(body.Email) {
		return respondError(c, fiber.StatusBadRequest, "invalid_email_format", "email is not a valid address")
	}
	if len(body.Name) > leadsNameMaxLen {
		return respondError(c, fiber.StatusBadRequest, "invalid_name", "name exceeds maximum length")
	}
	if len(body.Company) > leadsCompanyMaxLen {
		return respondError(c, fiber.StatusBadRequest, "invalid_company", "company exceeds maximum length")
	}
	if len(body.UseCase) > leadsUseCaseMaxLen {
		return respondError(c, fiber.StatusBadRequest, "invalid_use_case", "use_case exceeds maximum length")
	}

	// Capture team_id for authenticated callers so outreach can skip accounts
	// that have already been contacted. Not required — anonymous visitors can
	// and should also submit the form.
	var teamID uuid.NullUUID
	if tidStr := middleware.GetTeamID(c); tidStr != "" {
		if tid, err := uuid.Parse(tidStr); err == nil {
			teamID = uuid.NullUUID{UUID: tid, Valid: true}
		}
	}

	leadID, err := h.insertLead(c.Context(), body, teamID)
	if err != nil {
		slog.Error("leads: insert failed", "error", err, "email", maskEmailForLog(body.Email))
		return respondError(c, fiber.StatusInternalServerError, "internal_error", "Failed to record your request — please try again")
	}

	slog.Info("leads: captured", "id", leadID, "email", maskEmailForLog(body.Email), "company", body.Company)

	return respondCreated(c, fiber.Map{
		"ok": true,
		"id": leadID.String(),
	})
}

// insertLead writes one enterprise_leads row. Empty optional fields are stored
// as SQL NULL (NULLIF($n, '')) so NRQL / SQL queries can filter on IS NOT NULL
// instead of empty strings.
func (h *LeadsHandler) insertLead(ctx context.Context, body createLeadBody, teamID uuid.NullUUID) (uuid.UUID, error) {
	var id uuid.UUID
	const q = `
		INSERT INTO enterprise_leads (email, name, company, use_case, team_id)
		VALUES ($1, NULLIF($2,''), NULLIF($3,''), NULLIF($4,''), $5)
		RETURNING id`
	err := h.db.QueryRowContext(ctx, q,
		body.Email,
		body.Name,
		body.Company,
		body.UseCase,
		teamID,
	).Scan(&id)
	return id, err
}
