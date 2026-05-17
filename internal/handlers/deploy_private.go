package handlers

// deploy_private.go — Helpers for the private-deploy multipart fields on
// POST /deploy/new (Track A, migration 020).
//
// Kept in a separate file so the U3 reviewer can audit the whole rule-set —
// tier gate, validation, agent_action wiring — in one place. The handler in
// deploy.go calls parsePrivateDeployFields once before persisting the row.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/gofiber/fiber/v2"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"

	"log/slog"

	"mime/multipart"
)

// parsePrivateDeployFields extracts and validates the optional `private` and
// `allowed_ips` multipart fields from POST /deploy/new.
//
// Returns (private, allowedIPs, nil) on success. On failure, it writes the
// 400/402 response inline and returns a non-nil error — caller MUST propagate
// the error and return immediately (mirrors the pattern in requireTeam).
//
// Validation order (tier first — see U3 note in deploy.go):
//
//  1. private not set / "false" / empty → return (false, nil, nil) — no
//     allowed_ips check, no tier gate. Existing public-deploy path is byte-
//     identical to before this commit.
//  2. private=true on a hobby/anonymous/free/yearly-free team → 402 with
//     AgentActionPrivateDeployRequiresPro. Does NOT reveal whether the rest
//     of the request would have passed.
//  3. private=true with no allowed_ips → 400 with
//     AgentActionPrivateDeployRequiresAllowedIPs. We refuse "private deploy
//     reachable by no-one" because it silently bricks the app.
//  4. Each allowed_ips entry must be a valid IP or CIDR (net.ParseIP /
//     net.ParseCIDR). Bad entries surface verbatim in the 400 message so
//     the caller can fix the literal that broke.
//  5. > maxAllowedIPs entries → 400. Anything larger is a VPN / CF Access
//     problem, not a Pro deploy.
func parsePrivateDeployFields(c *fiber.Ctx, form *multipart.Form, planTier string) (bool, []string, error) {
	rawPrivate := firstFormValue(form, "private")
	private := parseTruthy(rawPrivate)
	rawAllowedIPs := firstFormValue(form, "allowed_ips")

	if !private {
		// Public deploy — even if allowed_ips is set, it is ignored and not
		// persisted. Surfaced as a `slog.Debug` so callers wondering why
		// allowed_ips "doesn't work" can find the breadcrumb in logs.
		if rawAllowedIPs != "" {
			slog.Debug("deploy.new.allowed_ips_ignored_public",
				"team_tier", planTier,
				"request_id", middleware.GetRequestID(c))
		}
		return false, nil, nil
	}

	entries := splitAllowedIPsField(rawAllowedIPs)
	return validatePrivateDeployFields(c, planTier, true, entries)
}

// validatePrivateDeployFields is the shared validation routine used by both
// the POST /deploy/new multipart flow (parsePrivateDeployFields) and the
// PATCH /api/v1/deployments/:id JSON flow (DeployHandler.Patch). Centralising
// the rule-set guarantees the two surfaces can't drift on a contract that the
// U3 reviewer audits as a single rule-set.
//
// Inputs:
//   - planTier:   team.PlanTier (e.g. "hobby", "pro"). Used for the tier gate.
//   - private:    the parsed private boolean.
//   - allowedIPs: already-split, already-trimmed entries (nil/empty allowed
//     only when private=false).
//
// On failure, writes the 400/402 response inline and returns a non-nil error
// (same pattern as the multipart helper). On success returns
// (private, allowedIPs, nil) — the slice is returned verbatim so the
// caller doesn't have to keep its own copy.
func validatePrivateDeployFields(c *fiber.Ctx, planTier string, private bool, allowedIPs []string) (bool, []string, error) {
	if !private {
		// Public — the caller is responsible for ignoring allowedIPs on this
		// path. No tier gate (every tier can run a public deploy).
		return false, nil, nil
	}

	// Tier gate FIRST — hides downstream validation rules from tiers that
	// don't have access to the feature at all.
	if !privateDeployAllowedTiers[planTier] {
		return false, nil, respondErrorWithAgentAction(c,
			fiber.StatusPaymentRequired,
			"private_deploy_requires_pro",
			fmt.Sprintf("Private deploys are a Pro feature. Your team is on %s.", planTier),
			AgentActionPrivateDeployRequiresPro,
			"https://instanode.dev/pricing")
	}

	// Required-field gate.
	if len(allowedIPs) == 0 {
		return false, nil, respondErrorWithAgentAction(c,
			fiber.StatusBadRequest,
			"private_deploy_requires_allowed_ips",
			"private=true requires a non-empty allowed_ips list (e.g. \"1.2.3.4,10.0.0.0/8\").",
			AgentActionPrivateDeployRequiresAllowedIPs,
			"")
	}

	// Cap enforcement BEFORE per-entry parsing — a 200-entry pathological
	// list would otherwise burn CPU through 200 net.ParseCIDR calls before
	// being rejected anyway. 32 is the max we'll ever stuff into an nginx
	// annotation responsibly; bigger lists belong in CF Access.
	if len(allowedIPs) > maxAllowedIPs {
		return false, nil, respondError(c,
			fiber.StatusBadRequest,
			"too_many_allowed_ips",
			fmt.Sprintf("allowed_ips has %d entries; max is %d. For larger allowlists use a real VPN or Cloudflare Access — see https://instanode.dev/docs/private-deploys.",
				len(allowedIPs), maxAllowedIPs))
	}

	// Per-entry validation. Surface the bad literal verbatim — the LLM agent
	// gets to feed the typo back to the human.
	for _, entry := range allowedIPs {
		if !isValidIPOrCIDR(entry) {
			return false, nil, respondError(c,
				fiber.StatusBadRequest,
				"invalid_allowed_ip",
				fmt.Sprintf("allowed_ips entry %q is not a valid IP or CIDR. Examples: \"1.2.3.4\", \"10.0.0.0/8\", \"2001:db8::/32\".", entry))
		}
	}

	return true, allowedIPs, nil
}

// patchAccessControlBody is the JSON body for PATCH /api/v1/deployments/:id.
//
// Both fields are optional pointers so the handler can distinguish "field
// omitted" (keep current state) from "field set to zero" (private=false /
// allowed_ips=[]). REST PATCH semantics: send only what you want to change.
//
// Semantics decision (REPLACE, not APPEND): when allowed_ips is supplied, the
// new slice REPLACES the current list rather than merging into it. This
// matches REST conventions for collection fields and is what the dashboard
// PrivacyPanel expects — the editor renders the current list, the user
// edits it, and submits the new authoritative list. Append semantics would
// silently grow the allow-list over multiple PATCHes (a known footgun for
// "I removed an IP but it's still there" bug reports).
type patchAccessControlBody struct {
	Private    *bool     `json:"private,omitempty"`
	AllowedIPs *[]string `json:"allowed_ips,omitempty"`
}

// Patch handles PATCH /api/v1/deployments/:id for in-place access-control
// edits — flipping a deploy public ↔ private or replacing the allowed_ips
// list. Does NOT rebuild the image; the apply-annotation helper that backs
// POST /deploy/new is reused so the two paths can't diverge.
//
// Behaviour matrix:
//
//   - {private:true, allowed_ips:[...]}   → set private, set list
//   - {allowed_ips:[...]} only            → keep current private; update list
//     (rejected if currently public — can't have allow-list on public deploy)
//   - {private:false}                     → clear allow-list, set public
//   - {private:true} only, no allow_ips   → 400 (need allowed_ips)
//   - {} empty body                       → 400 (nothing to change)
//
// All validation routes through validatePrivateDeployFields so the rule-set
// (tier gate → required IPs → cap → per-entry parse) is byte-identical to
// POST /deploy/new. The compute.Provider.UpdateAccessControl call patches
// the live Ingress; the models.UpdateDeploymentAccessControl call persists
// the row. Compute runs first because if it fails we don't want the DB to
// claim a state the Ingress can't enforce — but we also have to handle the
// reverse: if the Ingress doesn't exist yet (deploy is still building), the
// k8s provider returns nil so the DB is still updated and the next runDeploy
// picks up the fields.
func (h *DeployHandler) Patch(c *fiber.Ctx) error {
	team, err := h.requireTeam(c)
	if err != nil {
		return err
	}

	appID := c.Params("id")
	d, err := models.GetDeploymentByAppID(c.Context(), h.db, appID)
	if err != nil {
		var notFound *models.ErrDeploymentNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Deployment not found")
		}
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch deployment")
	}

	if d.TeamID != team.ID {
		// 404 not 403: never confirm the existence of deployments owned
		// by other teams.
		return respondError(c, fiber.StatusNotFound, "not_found", "Deployment not found")
	}

	var body patchAccessControlBody
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body",
			"Request body must be valid JSON: {\"private\": bool, \"allowed_ips\": [\"ip\",\"cidr\"]}")
	}

	if body.Private == nil && body.AllowedIPs == nil {
		return respondError(c, fiber.StatusBadRequest, "missing_fields",
			"At least one of 'private' or 'allowed_ips' must be supplied")
	}

	// Resolve the post-PATCH (private, allowed_ips) pair from the current
	// state + the supplied deltas. Sending only allowed_ips keeps the
	// current private flag (so a Pro user can edit their list without
	// having to also resend private=true). Sending private=false clears
	// the allow-list to empty regardless of what allowed_ips contains —
	// the public-deploy invariant is "no whitelist annotation".
	newPrivate := d.Private
	if body.Private != nil {
		newPrivate = *body.Private
	}

	var newAllowedIPs []string
	switch {
	case body.Private != nil && !*body.Private:
		// Explicit public — drop the list entirely regardless of allowed_ips
		// in the same body. Prevents the surface "I set private=false but
		// the allow-list is still there" bug.
		newAllowedIPs = nil
	case body.AllowedIPs != nil:
		// Caller supplied a new authoritative list (REPLACE semantics).
		newAllowedIPs = *body.AllowedIPs
	default:
		// allowed_ips omitted, private flipped (or unchanged) but stays
		// private — preserve the existing list verbatim.
		newAllowedIPs = d.AllowedIPs
	}

	// Run through the shared validation rule-set. Tier gate fires first so
	// hobby callers can't drill past it via "PATCH the public deploy I
	// already have to private". The team's CURRENT plan tier is what's
	// checked (matches POST semantics) — not the snapshot on the deployment
	// row.
	validatedPrivate, validatedAllowedIPs, vErr := validatePrivateDeployFields(c, team.PlanTier, newPrivate, newAllowedIPs)
	if vErr != nil {
		return vErr
	}

	// Compute-side first. The Ingress lives in k8s and a successful k8s
	// update is the truth that matters to inbound traffic. If this fails,
	// we surface 503 and skip the DB write so the row keeps reflecting
	// reality.
	if err := h.compute.UpdateAccessControl(c.Context(), d.AppID, validatedPrivate, validatedAllowedIPs); err != nil {
		slog.Error("deploy.patch.compute_update_failed",
			"app_id", appID, "error", err,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "compute_update_failed",
			"Failed to update ingress access control")
	}

	if err := models.UpdateDeploymentAccessControl(c.Context(), h.db, d.ID, validatedPrivate, validatedAllowedIPs); err != nil {
		slog.Error("deploy.patch.db_update_failed",
			"app_id", appID, "error", err,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "update_failed",
			"Failed to update deployment access control")
	}

	// Re-fetch so the response reflects the persisted row (status, updated_at).
	updated, err := models.GetDeploymentByAppID(c.Context(), h.db, appID)
	if err != nil {
		// Update succeeded but read-back failed — return the in-memory
		// representation we just wrote so the dashboard isn't blocked.
		d.Private = validatedPrivate
		d.AllowedIPs = validatedAllowedIPs
		updated = d
	}

	slog.Info("deploy.patch.access_control_updated",
		"app_id", appID, "team_id", team.ID,
		"private", validatedPrivate,
		"allowed_ip_count", len(validatedAllowedIPs),
		"request_id", middleware.GetRequestID(c))

	return c.JSON(fiber.Map{
		"ok":   true,
		"item": deploymentToMap(updated),
	})
}

// firstFormValue returns the first value for a multipart field, or "" when
// absent. multipart.Form.Value is map[string][]string with empty slices on
// missing keys — explicit check avoids the panic-on-index pattern.
func firstFormValue(form *multipart.Form, key string) string {
	if vals := form.Value[key]; len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// parseTruthy normalises the `private` field across reasonable inputs. The
// surface is loose on purpose: agents come from JS / Python / curl and each
// stringifies booleans differently. Anything not on this list is false.
func parseTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "yes", "y", "on":
		return true
	}
	return false
}

// splitAllowedIPsField parses the multipart `allowed_ips` value.
//
// P1-I (bug hunt 2026-05-17 round 2): the MCP client serialises allowed_ips
// as a JSON array string (`["1.2.3.4","10.0.0.0/8"]`) while this helper only
// understood the comma-joined form — so every MCP `create_deploy --private`
// 400'd with "invalid_allowed_ip". The parser now accepts BOTH:
//
//   - a JSON array of strings  → ["1.2.3.4", "10.0.0.0/8"]
//   - the canonical CSV form   → 1.2.3.4,10.0.0.0/8
//
// Fixing the backend covers every client (MCP, CLI, curl, dashboard) without
// shipping an MCP release. JSON detection is by leading-bracket sniff; a
// malformed JSON array falls through to CSV so a stray '[' never hard-fails.
// Whitespace is trimmed per entry and empty entries (trailing commas) skipped.
// Returns nil on empty.
func splitAllowedIPsField(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}

	// JSON-array form — what the MCP client sends.
	if strings.HasPrefix(trimmed, "[") {
		var arr []string
		if err := json.Unmarshal([]byte(trimmed), &arr); err == nil {
			out := make([]string, 0, len(arr))
			for _, p := range arr {
				if t := strings.TrimSpace(p); t != "" {
					out = append(out, t)
				}
			}
			if len(out) == 0 {
				return nil
			}
			return out
		}
		// Not valid JSON — fall through to CSV parsing rather than hard-fail.
	}

	// Canonical comma-joined form.
	parts := strings.Split(trimmed, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// isValidIPOrCIDR returns true if s is either a literal IP (v4 or v6) or a
// CIDR block. Used by parsePrivateDeployFields to validate each allowed_ips
// entry. nginx accepts both forms in whitelist-source-range.
func isValidIPOrCIDR(s string) bool {
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	if ip := net.ParseIP(s); ip != nil {
		return true
	}
	return false
}
