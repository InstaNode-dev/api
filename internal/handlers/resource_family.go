package handlers

// resource_family.go — slice 2 of env-aware deployments.
//
// Two endpoints:
//
//   GET /api/v1/resources/:id/family
//       Returns the env-twin family for the given resource — root + every
//       sibling in any env. Caller's id can be the root or any child; the
//       model layer walks parent_resource_id up to the root, then back
//       down. Cross-team callers get 403 (not 404) so an honest mistake
//       — passing the wrong UUID — is debuggable. Sensitive fields
//       (connection_url) are never returned here.
//
//   GET /api/v1/resources/families
//       Returns one entry per family root the caller's team owns. Each
//       entry groups members by env so the dashboard can render the
//       "Resources grouped by family" view without client-side bucketing.
//       Response carries Cache-Control: private, max-age=30 — narrow
//       freshness window because provisioning + soft-delete both shift
//       family membership and a 30s stale-while-deciding window is the
//       same one used by ListResourcesByTeam.
//
// Aggregation note. /families is a read aggregate over the team's full
// resource set. We do NOT use this surface for quota or billing
// decisions — those go through the model-layer Sum/Count queries which
// run uncached. The caching here is a UX-only optimisation.

import (
	"errors"
	"log/slog"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
)

const (
	// familyCacheControlHeader is the Cache-Control value returned by both
	// family endpoints. private = browser-only, never a shared edge cache
	// (the response is team-scoped). max-age=30 is the narrowest window
	// the dashboard can tolerate without re-fetching on every paint.
	familyCacheControlHeader = "private, max-age=30"
)

// Family handles GET /api/v1/resources/:id/family.
func (h *ResourceHandler) Family(c *fiber.Ctx) error {
	requestID := middleware.GetRequestID(c)

	teamID, err := parseTeamID(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session token required")
	}

	idStr := c.Params("id")
	id, parseErr := uuid.Parse(idStr)
	if parseErr != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_id", "Resource ID must be a valid UUID")
	}

	// Anchor: look up the requested resource so we can authorise ownership
	// before exposing any sibling metadata. Look up by token (the public
	// id used in all other resource routes); fall back to internal id
	// when token-lookup misses, since some clients have only the internal
	// id (e.g. from the families list endpoint below).
	var anchor *models.Resource
	if token, tokenErr := uuid.Parse(idStr); tokenErr == nil {
		r, lookupErr := models.GetResourceByToken(c.Context(), h.db, token)
		if lookupErr == nil {
			anchor = r
		} else {
			var notFound *models.ErrResourceNotFound
			if !errors.As(lookupErr, &notFound) {
				slog.Error("resource.family.token_lookup_failed",
					"error", lookupErr, "id", idStr, "request_id", requestID)
				return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch resource")
			}
		}
	}
	if anchor == nil {
		r, lookupErr := models.GetResourceByID(c.Context(), h.db, id)
		if lookupErr != nil {
			var notFound *models.ErrResourceNotFound
			if errors.As(lookupErr, &notFound) {
				return respondError(c, fiber.StatusNotFound, "not_found", "Resource not found")
			}
			slog.Error("resource.family.id_lookup_failed",
				"error", lookupErr, "id", idStr, "request_id", requestID)
			return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch resource")
		}
		anchor = r
	}

	// Ownership: 404 on cross-team. Returning 403 here would confirm
	// the resource exists in another tenant; 404 keeps the existence
	// of cross-team rows fully opaque (matches GetCredentials et al).
	if !anchor.TeamID.Valid || anchor.TeamID.UUID != teamID {
		return respondError(c, fiber.StatusNotFound, "not_found", "Resource not found")
	}

	family, err := models.GetResourceFamily(c.Context(), h.db, anchor.ID)
	if err != nil {
		slog.Error("resource.family.lookup_failed",
			"error", err, "resource_id", anchor.ID, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "lookup_failed", "Failed to look up resource family")
	}

	// Orphan resource (no parent, no children) — model returns single-
	// element slice already, but defensively handle the empty case so
	// the response always carries the anchor.
	if len(family) == 0 {
		family = []*models.Resource{anchor}
	}

	// Resolve the family root id for the response — it's the first row
	// (model orders the root first) when present, else the anchor.
	rootID := family[0].ID
	if family[0].ParentResourceID != nil {
		rootID = *family[0].ParentResourceID
	}

	members := make([]fiber.Map, 0, len(family))
	for _, r := range family {
		members = append(members, familyMemberToMap(r))
	}

	c.Set("Cache-Control", familyCacheControlHeader)

	return c.JSON(fiber.Map{
		"ok":             true,
		"family_root_id": rootID,
		"members":        members,
		"total":          len(members),
	})
}

// ListFamilies handles GET /api/v1/resources/families.
func (h *ResourceHandler) ListFamilies(c *fiber.Ctx) error {
	requestID := middleware.GetRequestID(c)

	teamID, err := parseTeamID(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session token required")
	}

	summaries, err := models.ListResourceFamiliesByTeam(c.Context(), h.db, teamID)
	if err != nil {
		slog.Error("resource.families.list_failed",
			"error", err, "team_id", teamID, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "list_failed", "Failed to list resource families")
	}

	items := make([]fiber.Map, 0, len(summaries))
	for _, s := range summaries {
		envMap := make(fiber.Map, len(s.MembersByEnv))
		for env, member := range s.MembersByEnv {
			envMap[env] = familyMemberSummaryToMap(member)
		}
		items = append(items, fiber.Map{
			"family_root_id":  s.FamilyRootID,
			"resource_type":   s.ResourceType,
			"members_per_env": envMap,
		})
	}

	c.Set("Cache-Control", familyCacheControlHeader)

	return c.JSON(fiber.Map{
		"ok":       true,
		"families": items,
		"total":    len(items),
	})
}

// familyMemberToMap is the per-member shape returned by GET /family. Mirrors
// resourceToMap minus the bits the family view doesn't need (cloud_vendor,
// country_code, etc.) plus is_root and parent_resource_id.
func familyMemberToMap(r *models.Resource) fiber.Map {
	m := fiber.Map{
		"id":            r.ID,
		"token":         r.Token,
		"env":           r.Env,
		"resource_type": r.ResourceType,
		"tier":          r.Tier,
		"status":        r.Status,
		"is_root":       r.ParentResourceID == nil,
		"created_at":    r.CreatedAt,
	}
	if r.Name.Valid {
		m["name"] = r.Name.String
	}
	if r.ParentResourceID != nil {
		m["parent_resource_id"] = r.ParentResourceID.String()
	} else {
		m["parent_resource_id"] = ""
	}
	return m
}

// familyMemberSummaryToMap returns the compact per-env entry shape used by
// the /families endpoint. Drops fields the env-grid renderer doesn't need
// (token, created_at) to keep the response small for teams with many envs.
func familyMemberSummaryToMap(m models.FamilyMember) fiber.Map {
	out := fiber.Map{
		"id":            m.ID,
		"token":         m.Token,
		"env":           m.Env,
		"resource_type": m.ResourceType,
		"tier":          m.Tier,
		"status":        m.Status,
		"is_root":       m.IsRoot,
	}
	if m.Name.Valid {
		out["name"] = m.Name.String
	}
	return out
}
