package handlers

// webhook_security_helpers.go — shared helpers for the audit-log emission
// path that fires from webhook handlers (Brevo URL-token compare,
// Razorpay HMAC verify) when authentication fails.
//
// Lives outside webhook.go / brevo_webhook.go / billing.go so the same
// helper is reachable from every webhook surface AND from the audit_log
// test that pins the "we never log a raw source IP" invariant.

import (
	"net"
	"strings"
)

// maskSourceIP returns a coarse-grained subnet representation of the
// supplied source IP so the audit_log row can record a per-network signal
// (useful for "X auth failures from this /24 over Y minutes" alerts)
// WITHOUT recording the exact caller IP. Mirrors the fingerprint masking
// the rate limiter already applies (api/internal/middleware/fingerprint.go)
// so an operator reading both surfaces sees the same network grouping.
//
// Behaviour:
//
//   - IPv4 → /24 ("198.51.100.7" → "198.51.100.0/24")
//   - IPv6 → /48 ("2001:db8:cafe::1" → "2001:db8:cafe::/48")
//   - unparseable / empty → "" (caller should omit the field from metadata)
//
// The function does NOT panic on garbage input. It tolerates IPv4-in-IPv6
// mapped addresses ("::ffff:198.51.100.7" → "198.51.100.0/24") so a Fiber
// proxy that promotes XFF values to mapped form still produces the canonical
// /24 result.
//
// SECURITY NOTE: this helper is the ONLY place the audit-log emission path
// touches a raw source IP. If you find yourself reaching into c.IP() at a
// webhook-emit site, route it through maskSourceIP first.
func maskSourceIP(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// Fiber returns "ip:port" on some surfaces (proxy-extracted XFF on
	// older versions) — strip the trailing :port if it parses cleanly.
	// Skip the strip when the input is an IPv6 literal (which contains
	// many colons but no trailing port unless wrapped in brackets); a
	// raw IPv6 like "2001:db8::1" has multiple colons and net.ParseIP
	// would handle it directly, so only apply SplitHostPort when there
	// is exactly one colon (the IPv4:port case) or when the input is
	// bracket-wrapped ("[::1]:8080").
	if strings.Count(raw, ":") == 1 || strings.HasPrefix(raw, "[") {
		if host, _, err := net.SplitHostPort(raw); err == nil && host != "" {
			raw = host
		}
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return ""
	}
	// Prefer the v4 form when the address parses as v4 OR is a v4-in-v6
	// mapped address. To4() returns non-nil in both cases.
	if v4 := ip.To4(); v4 != nil {
		// Mask to /24.
		mask := net.CIDRMask(24, 32)
		return (&net.IPNet{IP: v4.Mask(mask), Mask: mask}).String()
	}
	// Pure IPv6 — mask to /48. This is the same mask the dashboard
	// fingerprint uses for v6 callers; an operator cross-referencing
	// the two surfaces sees the same group.
	mask := net.CIDRMask(48, 128)
	return (&net.IPNet{IP: ip.Mask(mask), Mask: mask}).String()
}
