package handlers

// experiments.go — POST /api/v1/experiments/converted.
//
// Records that a user took the conversion action for an active
// experiment. The dashboard fires this from the click handler on the
// experimental UI element (e.g. the "Upgrade to Pro" button) BEFORE
// navigating away, so the audit_log row captures the exact variant
// the user clicked.
//
// Request shape:
//
//	{ "experiment": "upgrade_button", "variant": "urgent", "action": "checkout_started" }
//
// Server-side guards:
//
//   - The experiment must be registered (otherwise we'd happily
//     record garbage names).
//   - The variant must be one of the experiment's registered
//     variants — and it must match what the server itself would
//     have bucketed this team into. A mismatch indicates a stale
//     client or a tampered request; we reject with 400 rather
//     than silently log misleading data.
//   - action is free-form but length-capped to 64 bytes.
//
// The audit-event write is best-effort: if it fails the user still
// gets a 200 (we never want the analytics tail to wag the conversion
// dog) but we log at error level so the failure is observable.

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"instant.dev/internal/experiments"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
)

// ExperimentsHandler serves POST /api/v1/experiments/converted.
type ExperimentsHandler struct {
	db *sql.DB
}

// NewExperimentsHandler constructs an ExperimentsHandler.
func NewExperimentsHandler(db *sql.DB) *ExperimentsHandler {
	return &ExperimentsHandler{db: db}
}

// experimentConvertedBody is the JSON body the dashboard posts. Field
// names are snake_case to match the rest of the v1 API.
type experimentConvertedBody struct {
	Experiment string `json:"experiment"`
	Variant    string `json:"variant"`
	Action     string `json:"action"`
}

// actionMaxLen caps the action_taken metadata field. The dashboard
// only ever sends short identifiers like "checkout_started" but a
// hostile client could try to balloon the audit row; 64 is enough
// for any sensible action name.
const actionMaxLen = 64

// Converted handles POST /api/v1/experiments/converted.
//
// Returns 200 with {ok:true} on success, 400 on a bad body, and
// silently 200 even when the audit write fails (the write is logged).
func (h *ExperimentsHandler) Converted(c *fiber.Ctx) error {
	teamIDStr := middleware.GetTeamID(c)
	teamID, err := uuid.Parse(teamIDStr)
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Authentication required")
	}
	userIDStr := middleware.GetUserID(c)
	var userID uuid.NullUUID
	if u, err := uuid.Parse(userIDStr); err == nil {
		userID = uuid.NullUUID{UUID: u, Valid: true}
	}

	var body experimentConvertedBody
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "Invalid JSON body")
	}
	body.Experiment = strings.TrimSpace(body.Experiment)
	body.Variant = strings.TrimSpace(body.Variant)
	body.Action = strings.TrimSpace(body.Action)
	if body.Experiment == "" || body.Variant == "" {
		return respondError(c, fiber.StatusBadRequest, "invalid_body",
			"experiment and variant are required")
	}
	if len(body.Action) > actionMaxLen {
		body.Action = body.Action[:actionMaxLen]
	}

	// Verify the experiment is registered. Unknown names get a
	// 400 — otherwise we'd accept arbitrary strings into the
	// audit log and pollute the conversion data.
	exp, ok := experiments.Get(body.Experiment)
	if !ok {
		return respondError(c, fiber.StatusBadRequest, "unknown_experiment",
			"Unknown experiment")
	}

	// Verify the client-supplied variant is actually one this
	// experiment knows about. A typo'd variant ("contrl") would
	// otherwise sneak in and ruin the bucket counts.
	validVariant := false
	for _, v := range exp.Variants {
		if v == body.Variant {
			validVariant = true
			break
		}
	}
	if !validVariant {
		return respondError(c, fiber.StatusBadRequest, "invalid_variant",
			"Variant is not registered for this experiment")
	}

	// Cross-check: the variant the client says it saw must equal
	// the variant the server would have bucketed this team into.
	// A mismatch usually means the dashboard cached an old /auth/me
	// response across a salt rotation; rejecting is safer than
	// logging misleading data. Identifier is team_id, matching
	// /auth/me's bucketing key.
	serverVariant := experiments.Pick(body.Experiment, teamID.String())
	if serverVariant != body.Variant {
		return respondError(c, fiber.StatusBadRequest, "variant_mismatch",
			"Variant does not match server bucket")
	}

	// Build the metadata blob. JSON marshalling can't realistically
	// fail for this shape — but if it ever does, fall through with
	// nil metadata rather than failing the request.
	metaBlob, _ := json.Marshal(map[string]string{
		"experiment":   body.Experiment,
		"variant":      body.Variant,
		"action_taken": body.Action,
	})

	actor := "user"
	if !userID.Valid {
		actor = "agent"
	}

	// Best-effort audit write — detached context so the goroutine
	// outlives the request cycle. A failure here logs but doesn't
	// surface to the user.
	go func(tid uuid.UUID, uid uuid.NullUUID, meta []byte, expName string) {
		if err := models.InsertAuditEvent(context.Background(), h.db, models.AuditEvent{
			TeamID:   tid,
			UserID:   uid,
			Actor:    actor,
			Kind:     "experiment.conversion",
			Summary:  "user converted on experiment <code>" + expName + "</code>",
			Metadata: meta,
		}); err != nil {
			slog.Error("experiments.converted.audit_write_failed",
				"team_id", tid, "experiment", expName, "error", err)
		}
	}(teamID, userID, metaBlob, body.Experiment)

	return c.JSON(fiber.Map{"ok": true})
}
