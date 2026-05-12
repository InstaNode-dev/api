package handlers

// deploy_private.go — Helpers for the private-deploy multipart fields on
// POST /deploy/new (Track A, migration 020).
//
// Kept in a separate file so the U3 reviewer can audit the whole rule-set —
// tier gate, validation, agent_action wiring — in one place. The handler in
// deploy.go calls parsePrivateDeployFields once before persisting the row.

import (
	"fmt"
	"net"
	"strings"

	"github.com/gofiber/fiber/v2"
	"instant.dev/internal/middleware"

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
	entries := splitAllowedIPsField(rawAllowedIPs)
	if len(entries) == 0 {
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
	if len(entries) > maxAllowedIPs {
		return false, nil, respondError(c,
			fiber.StatusBadRequest,
			"too_many_allowed_ips",
			fmt.Sprintf("allowed_ips has %d entries; max is %d. For larger allowlists use a real VPN or Cloudflare Access — see https://instanode.dev/docs/private-deploys.",
				len(entries), maxAllowedIPs))
	}

	// Per-entry validation. Surface the bad literal verbatim — the LLM agent
	// gets to feed the typo back to the human.
	for _, entry := range entries {
		if !isValidIPOrCIDR(entry) {
			return false, nil, respondError(c,
				fiber.StatusBadRequest,
				"invalid_allowed_ip",
				fmt.Sprintf("allowed_ips entry %q is not a valid IP or CIDR. Examples: \"1.2.3.4\", \"10.0.0.0/8\", \"2001:db8::/32\".", entry))
		}
	}

	return true, entries, nil
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

// splitAllowedIPsField parses the multipart `allowed_ips` value. Accepts the
// canonical comma-joined form ("1.2.3.4,10.0.0.0/8") and trims whitespace per
// entry. Empty entries (e.g. trailing commas) are skipped — they're a common
// concatenation typo and not worth a 400 on their own. Returns nil on empty.
func splitAllowedIPsField(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
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
