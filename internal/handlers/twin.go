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
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
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
	_ = c.BodyParser(&body)
	body.Name = sanitizeName(body.Name)

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
		// 403 not 404: caller passed an id they presumably know — the
		// meaningful failure mode is authz, not existence ambiguity.
		return respondError(c, fiber.StatusForbidden, "forbidden", "You do not own this resource")
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
