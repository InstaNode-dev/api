package handlers

// twin.go — slice 3 of env-aware deployments.
//
// POST /api/v1/resources/:id/provision-twin
//   Body: { env: "staging", name?: "my-app-db-staging" }
//
// Creates a fresh env-twin of an existing resource: same resource_type,
// same family root, different env. The id parameter can be the family
// root or any sibling — the handler resolves the root via the existing
// family helpers.
//
// Why the dispatch lives in twin.go (not inline on each handler):
//   - The three "real" provisionable types share the same skeleton:
//     CreateResource → provisionX → encrypt+persist URL → audit log.
//     The variation is only the low-level `provisionX` call.
//   - Embedding the twin logic on each handler would mean three
//     near-identical wrappers; centralising it lets cross-cutting
//     concerns (tier gate, family validation, agent_action shape)
//     stay in one place.
//   - The three existing handlers expose `ProvisionForTwin(ctx, resource)`
//     entry points so this file never reaches into provider internals.
//
// Out of scope (return 400 unsupported_for_twin):
//   - webhook (just a stored token; no per-env infra to provision)
//   - queue   (NATS subject is logical; no env-twin semantics)
//   - storage (DO Spaces bucket prefix is per-token, not per-env)
// Stack twins go through POST /api/v1/stacks/:slug/promote, which
// already covers the multi-service case end-to-end.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/safego"
)

// TwinHandler orchestrates POST /api/v1/resources/:id/provision-twin.
// It composes the existing DB/Cache/NoSQL handlers so we don't fork the
// provisioning pipelines — each handler's ProvisionForTwin method runs
// the same side-effects as its /db/new, /cache/new, /nosql/new flow.
type TwinHandler struct {
	dbH    *DBHandler
	cacheH *CacheHandler
	nosqlH *NoSQLHandler
}

// NewTwinHandler constructs a TwinHandler from the existing per-service
// handlers. All three are required — passing a nil panics at construction
// time (preferred to surfacing a confusing 500 at request time).
func NewTwinHandler(dbH *DBHandler, cacheH *CacheHandler, nosqlH *NoSQLHandler) *TwinHandler {
	if dbH == nil || cacheH == nil || nosqlH == nil {
		panic("handlers.NewTwinHandler: db, cache, and nosql handlers are all required")
	}
	return &TwinHandler{dbH: dbH, cacheH: cacheH, nosqlH: nosqlH}
}

// provisionTwinRequest is the on-the-wire JSON body shape.
type provisionTwinRequest struct {
	Env  string `json:"env"`
	Name string `json:"name"`
	// ApprovalID is the manual-trigger escape for the email-link approval
	// workflow (migration 026). When the operator has clicked the
	// approval link OUTSIDE the worker poll loop, they can pass
	// approval_id here to have the API run the twin provision
	// immediately. Empty in the normal flow. Dev-env twins ignore it.
	ApprovalID string `json:"approval_id,omitempty"`
}

// ProvisionTwin handles POST /api/v1/resources/:id/provision-twin.
//
// Response shape on 201 is the same as the per-service /new endpoints
// (id, token, connection_url, tier, env, limits, …) so existing dashboard
// + MCP code that consumes /db/new etc. can render twin responses with
// zero branching.
//
// Errors:
//
//	400 invalid_id / invalid_env / unsupported_for_twin
//	401 unauthorized
//	402 upgrade_required (hobby/free) — carries agent_action + upgrade_url
//	403 forbidden       (caller doesn't own source resource)
//	404 not_found       (source resource doesn't exist)
//	409 twin_exists     (family already has a row in the requested env)
//	503 provision_failed (downstream provisioner returned an error)
func (h *TwinHandler) ProvisionTwin(c *fiber.Ctx) error {
	start := time.Now()
	ctx := c.UserContext()
	requestID := middleware.GetRequestID(c)

	teamID, err := parseTeamID(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session token required")
	}

	tokenStr := c.Params("id")
	tokenUUID, parseErr := uuid.Parse(tokenStr)
	if parseErr != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_id", "Resource ID must be a valid UUID")
	}

	var body provisionTwinRequest
	if err := parseProvisionBody(c, &body); err != nil {
		return err
	}
	cleanName, sanErr := sanitizeNameForRequest(c, body.Name)
	if sanErr != nil {
		return sanErr
	}
	body.Name = cleanName

	if body.Env == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_env",
			"env is required — pick the target environment for the twin (e.g. \"staging\")")
	}
	normalisedEnv, ok := models.NormalizeEnv(body.Env)
	if !ok {
		return respondError(c, fiber.StatusBadRequest, "invalid_env",
			"env must match ^[a-z0-9-]{1,32}$ (lowercase letters, digits, dashes; max 32 chars)")
	}

	// Resolve the source resource. The :id param is the public token —
	// match the convention used by every other /resources/:id endpoint.
	source, err := models.GetResourceByToken(ctx, h.dbH.db, tokenUUID)
	if err != nil {
		var notFound *models.ErrResourceNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Source resource not found")
		}
		slog.Error("twin.source_lookup_failed",
			"error", err, "token", tokenStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch source resource")
	}
	if !source.TeamID.Valid || source.TeamID.UUID != teamID {
		// 404 not 403: never confirm the existence of resources owned by
		// other teams. Mirrors GetCredentials/Get/Delete/Pause/Resume.
		return respondError(c, fiber.StatusNotFound, "not_found", "Source resource not found")
	}

	// Only the three "real" provisionable resource types are in scope —
	// see file-header note. Webhook/queue/storage callers get a clear
	// 400 with an agent_action hint rather than a generic refusal.
	if !isTwinSupportedType(source.ResourceType) {
		return respondError(c, fiber.StatusBadRequest, "unsupported_for_twin",
			"provision-twin only supports postgres, redis, and mongodb resources; for stacks use POST /api/v1/stacks/:slug/promote")
	}

	// Target env must differ from source env. Otherwise the duplicate-twin
	// guard would fire (409) and the agent would have to guess why; a 400
	// with a typed code makes the intent error explicit, and matches the
	// "one twin per env per family" rule from the design doc.
	if normalisedEnv == source.Env {
		return respondError(c, fiber.StatusBadRequest, "same_env",
			"env must differ from the source resource's env (source is in \""+source.Env+"\")")
	}

	// Tier gate. Multi-env workflows are a Pro+ feature — symmetric with
	// the stack family / promote endpoints. We re-use those helpers so the
	// 402 response shape matches across the env-aware surface.
	team, err := models.GetTeamByID(ctx, h.dbH.db, teamID)
	if err != nil {
		slog.Error("twin.team_lookup_failed",
			"error", err, "team_id", teamID, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "team_lookup_failed", "Failed to look up team")
	}
	if !multiEnvTierAllowed(team.PlanTier) {
		return respondMultiEnvUpgradeRequired(c, team.PlanTier)
	}

	// Email-link approval gate. Per product directive (2026-05-12): any
	// twin provision targeting a non-development env requires the
	// operator to click a single-use email link before the twin is
	// actually created. Dev-env twins bypass this gate entirely.
	//
	// The pending path short-circuits BEFORE we call into the per-type
	// handler — no DB row is created in the resources table, no
	// downstream provisioner call is made. The cached payload carries
	// everything needed to replay the call once approval lands.
	if normalisedEnv != envDevelopment && body.ApprovalID == "" {
		row, pendingErr := h.beginTwinApproval(c, team, source, body, normalisedEnv)
		if pendingErr != nil {
			return pendingErr
		}
		return c.Status(fiber.StatusAccepted).JSON(fiber.Map{
			"ok":           true,
			"status":       "pending_approval",
			"approval_id":  row.ID.String(),
			"expires_at":   row.ExpiresAt.UTC().Format(time.RFC3339),
			"from":         source.Env,
			"to":           normalisedEnv,
			"source":       tokenStr,
			"agent_action": newAgentActionPromoteApprovalSent(normalisedEnv, row.RequestedByEmail),
			"note":         "Click the link in your email to approve the twin. Dev-env twins skip this step.",
		})
	}
	if body.ApprovalID != "" {
		// Manual-trigger fallback. Verify the approval_id matches an
		// approved resource_twin row for THIS team with matching
		// from/to envs, and flip it to executed before continuing.
		// Reuse stack.go's consumer — it's kind-agnostic.
		if err := h.consumeApprovedTwin(c, team, body, source.Env, normalisedEnv); err != nil {
			return err
		}
	}

	// Validate the family link. ValidateFamilyParent does the heavy lifting:
	//   - same-team (already enforced above, but defence-in-depth)
	//   - same-type
	//   - no existing twin in target env (409 instead of letting the
	//     partial unique index fire a Postgres error)
	// The returned rootID is what we store on the new row.
	rootID, err := models.ValidateFamilyParent(ctx, h.dbH.db, source.ID, teamID, source.ResourceType, normalisedEnv)
	if err != nil {
		var linkErr *models.FamilyLinkError
		if errors.As(err, &linkErr) {
			switch linkErr.Reason {
			case "duplicate_twin":
				return respondError(c, fiber.StatusConflict, "twin_exists",
					"a "+source.ResourceType+" twin already exists for env="+normalisedEnv)
			case "cross_team":
				// Defensive — covered above, but keep the typed branch.
				return respondError(c, fiber.StatusForbidden, "forbidden_parent_resource",
					"source resource belongs to a different team")
			case "cross_type":
				// Cannot happen here — we always pass source.ResourceType.
				return respondError(c, fiber.StatusBadRequest, "type_mismatch", linkErr.Detail)
			case "deleted_parent":
				return respondError(c, fiber.StatusNotFound, "not_found", "Source resource not found")
			}
		}
		slog.Error("twin.validate_family_failed",
			"error", err, "source_id", source.ID, "env", normalisedEnv, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "family_validate_failed", "Failed to validate twin link")
	}

	// Carry forward source attributes that should mirror across env-twins:
	//   - tier: spec says "same limits / quotas / tier as the source"
	//   - fingerprint / cloud_vendor / country_code: lets quota + geo
	//     dashboards group siblings together
	// Name falls back to the source name if the caller didn't pass one —
	// it's only a label, so this saves agents one round-trip.
	twinName := body.Name
	if twinName == "" && source.Name.Valid {
		twinName = source.Name.String
	}

	fp := nullStr(source.Fingerprint)
	vendor := nullStr(source.CloudVendor)
	country := nullStr(source.CountryCode)

	// Hand off to the per-type handler. Each ProvisionForTwin runs the
	// same pipeline as the corresponding /new endpoint: CreateResource
	// (with parent_resource_id set), call the real provisioner, encrypt
	// + persist the connection URL, audit-log the event, return the same
	// JSON shape with status 201.
	switch source.ResourceType {
	case models.ResourceTypePostgres:
		return h.dbH.ProvisionForTwin(c, ProvisionForTwinInput{
			TeamID:       teamID,
			Name:         twinName,
			Tier:         source.Tier,
			Env:          normalisedEnv,
			ParentRootID: &rootID,
			Fingerprint:  fp,
			CloudVendor:  vendor,
			CountryCode:  country,
			RequestID:    requestID,
			Start:        start,
		})
	case models.ResourceTypeRedis:
		return h.cacheH.ProvisionForTwin(c, ProvisionForTwinInput{
			TeamID:       teamID,
			Name:         twinName,
			Tier:         source.Tier,
			Env:          normalisedEnv,
			ParentRootID: &rootID,
			Fingerprint:  fp,
			CloudVendor:  vendor,
			CountryCode:  country,
			RequestID:    requestID,
			Start:        start,
		})
	case models.ResourceTypeMongoDB:
		return h.nosqlH.ProvisionForTwin(c, ProvisionForTwinInput{
			TeamID:       teamID,
			Name:         twinName,
			Tier:         source.Tier,
			Env:          normalisedEnv,
			ParentRootID: &rootID,
			Fingerprint:  fp,
			CloudVendor:  vendor,
			CountryCode:  country,
			RequestID:    requestID,
			Start:        start,
		})
	}
	// Unreachable — isTwinSupportedType already covered every branch.
	return respondError(c, fiber.StatusInternalServerError, "internal_error",
		"unexpected resource_type: "+source.ResourceType)
}

// ProvisionForTwinInput is the common shape the three per-service handlers
// accept from the twin orchestrator. Keeping the fields in a single struct
// means adding a new field (e.g. cloud region for region-pinned twins) is
// one source-level change instead of three function-signature edits.
type ProvisionForTwinInput struct {
	TeamID       uuid.UUID
	Name         string
	Tier         string
	Env          string
	ParentRootID *uuid.UUID
	Fingerprint  string
	CloudVendor  string
	CountryCode  string
	RequestID    string
	Start        time.Time
}

// TwinResultLimits mirrors the per-tier limit response fields the single-
// twin handler returns. Held as a struct (rather than fiber.Map) so the
// fiber-free Core path stays decoupled from the web framework and the
// bulk handler can render it consistently for every row.
type TwinResultLimits struct {
	StorageMB   int
	Connections int
}

// TwinProvisionResult is what ProvisionForTwinCore returns on success. The
// single-twin handler (ProvisionForTwin) renders this as JSON; the bulk-twin
// handler aggregates many results into a Multi-Status response. Fields mirror
// the JSON shape one-for-one so the renderer stays trivial.
type TwinProvisionResult struct {
	ID              string
	Token           string
	Name            string
	ResourceType    string
	ConnectionURL   string
	InternalURL     string
	Tier            string
	Env             string
	FamilyRootID    string
	KeyPrefix       string // only set for redis twins
	Limits          TwinResultLimits
	StorageExceeded bool
}

// twinCoreErr wraps a message string as an error so ProvisionForTwinCore
// callers can render it via err.Error() without leaking the wrapper type.
// Kept package-private — every existing caller already maps the err to a
// 503 provision_failed response shape, so a typed error gives no win.
func twinCoreErr(msg string) error { return &twinProvisionError{Msg: msg} }

type twinProvisionError struct{ Msg string }

func (e *twinProvisionError) Error() string { return e.Msg }

// isTwinSupportedType returns true for the resource types the twin endpoint
// will provision. Out-of-scope types get a clean 400 instead of triggering
// the dispatch switch's default branch.
func isTwinSupportedType(resourceType string) bool {
	switch resourceType {
	case models.ResourceTypePostgres, models.ResourceTypeRedis, models.ResourceTypeMongoDB:
		return true
	default:
		return false
	}
}

// nullStr coerces a sql.NullString to a plain string (empty when not valid).
// Tiny helper — kept here so the twin file doesn't drag a generic util into
// the handlers package just for one use.
func nullStr(ns sql.NullString) string {
	if !ns.Valid {
		return ""
	}
	return ns.String
}

// derefUUID renders an optional uuid pointer as a string. Empty when nil so
// JSON consumers don't have to branch on null. Used by the response shape
// to surface family_root_id.
func derefUUID(p *uuid.UUID) string {
	if p == nil {
		return ""
	}
	return p.String()
}

// beginTwinApproval persists a pending row to promote_approvals and emits
// the audit_log event the Brevo forwarder picks up to send the approval
// email. Mirrors stack.beginPromoteApproval — the prompt deliberately
// kept the two helpers separate so kind-specific metadata (stack_slug
// vs resource_id + resource_type) stays close to its handler.
func (h *TwinHandler) beginTwinApproval(
	c *fiber.Ctx,
	team *models.Team,
	source *models.Resource,
	body provisionTwinRequest,
	toEnv string,
) (*models.PromoteApproval, error) {
	payload, mErr := json.Marshal(body)
	if mErr != nil {
		return nil, respondError(c, fiber.StatusBadRequest, "invalid_body",
			"Failed to marshal provision-twin payload")
	}

	requestedBy := middleware.GetEmail(c)
	if requestedBy == "" {
		return nil, respondError(c, fiber.StatusBadRequest, "missing_email",
			"Approval workflow needs an authenticated email on the session token")
	}

	srcName := ""
	if source.Name.Valid {
		srcName = source.Name.String
	}
	row, err := CreatePromoteApprovalAndEmit(c.Context(), h.dbH.db, PromoteApprovalRequest{
		TeamID:           team.ID,
		RequestedByEmail: requestedBy,
		PromoteKind:      models.PromoteApprovalKindResourceTwin,
		PromotePayload:   payload,
		FromEnv:          source.Env,
		ToEnv:            toEnv,
		Summary: "Twin approval requested: " + source.ResourceType + " " +
			source.Env + " → " + toEnv,
		EmailMetaExtras: map[string]any{
			"resource_id":   source.ID.String(),
			"resource_type": source.ResourceType,
			"resource_name": srcName,
		},
	})
	if err != nil {
		slog.Error("twin.approval_insert_failed",
			"error", err, "team_id", team.ID, "source_id", source.ID,
			"to", toEnv, "request_id", middleware.GetRequestID(c))
		return nil, respondError(c, fiber.StatusServiceUnavailable, "approval_failed",
			"Failed to persist twin approval request")
	}
	return row, nil
}

// consumeApprovedTwin is the twin counterpart of stack.consumeApprovedPromote.
// Verifies an explicit approval_id matches an approved-but-not-executed
// resource_twin row for THIS team with matching from/to, then atomically
// flips it to 'executed' before we proceed to call the per-type provisioner.
func (h *TwinHandler) consumeApprovedTwin(
	c *fiber.Ctx,
	team *models.Team,
	body provisionTwinRequest,
	from, to string,
) error {
	id, err := uuid.Parse(body.ApprovalID)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_approval_id",
			"approval_id must be a valid UUID")
	}
	row, err := models.GetPromoteApprovalByID(c.Context(), h.dbH.db, id)
	if errors.Is(err, models.ErrPromoteApprovalNotFound) {
		return respondError(c, fiber.StatusNotFound, "approval_not_found",
			"approval_id does not match any approval row")
	}
	if err != nil {
		slog.Error("twin.approval_lookup_failed",
			"error", err, "approval_id", id,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "lookup_failed",
			"Failed to look up approval")
	}
	if row.TeamID != team.ID {
		return respondError(c, fiber.StatusNotFound, "approval_not_found",
			"approval_id does not match any approval row for this team")
	}
	if row.Status != models.PromoteApprovalStatusApproved {
		return respondError(c, fiber.StatusConflict, "approval_not_approved",
			"approval row is in status="+row.Status+" — must be 'approved' to consume")
	}
	if row.PromoteKind != models.PromoteApprovalKindResourceTwin ||
		row.FromEnv != from || row.ToEnv != to {
		return respondError(c, fiber.StatusBadRequest, "approval_mismatch",
			"approval_id's recorded (kind,from,to) does not match this request")
	}
	if row.ExpiresAt.Before(time.Now().UTC()) {
		return respondError(c, fiber.StatusGone, "approval_expired",
			"approval window has fully expired")
	}
	ok, err := models.MarkPromoteApprovalExecuted(c.Context(), h.dbH.db, id)
	if err != nil {
		slog.Error("twin.approval_execute_failed",
			"error", err, "approval_id", id,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "execute_failed",
			"Failed to mark approval executed")
	}
	if !ok {
		return respondError(c, fiber.StatusConflict, "approval_already_executed",
			"approval row has already been executed")
	}
	executedBy := middleware.GetEmail(c) // capture before goroutine — c is recycled
	safego.Go("twin.promote_audit", func() {
		emitPromoteAuditEvent(context.Background(), h.dbH.db, row, models.AuditKindPromoteExecuted,
			"Twin executed via approval "+row.ID.String()+" ("+from+" → "+to+")",
			map[string]any{
				"approval_id": row.ID.String(),
				"executed_by": executedBy,
			})
	})
	return nil
}
