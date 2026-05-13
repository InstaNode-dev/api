package handlers

// deploy_webhook_notify.go — Optional notify_webhook field on POST /deploy/new.
//
// Today a caller has no async signal that a deploy has reached a terminal
// state (healthy / failed) — they poll GET /deploy/:id. The notify_webhook
// field lets the caller subscribe instead: when the deploy hits 'healthy'
// or 'failed' the worker will POST a payload to the supplied URL (with an
// optional HMAC-SHA256 signature header when notify_webhook_secret is set).
//
// This file owns the *write* path: parsing the multipart fields, validating
// the URL, encrypting the secret. The *dispatch* path (worker scans
// notify_state='pending' rows and POSTs to the URL) is a follow-up PR that
// lives in the worker repo — see the PR description for the contract.
//
// Validation rules (kept loud and explicit because they are the SSRF gate):
//
//   1. Scheme MUST be https.   No http://, no file://, no gopher://. An
//      agent supplying http:// for "convenience" gets a 400 with a
//      copy-pastable agent_action sentence pointing at the docs.
//
//   2. Hostname MUST resolve and MUST NOT resolve to a private / loopback /
//      link-local / multicast / unspecified / CGNAT range. This is the
//      SSRF safety net: a malicious agent could try
//      https://169.254.169.254 (cloud metadata) or
//      https://10.0.0.5:8080/admin (internal service). Every resolved IP
//      is checked — if ANY resolved IP is in a blocked range we reject the
//      whole URL. We deliberately do NOT try to "warn and proceed" — the
//      worker dispatches with the platform's egress identity and that
//      authority must not point inward.
//
//   3. Hostname literal forms are rejected even before DNS:
//      "localhost" (regardless of /etc/hosts), and any IP literal that
//      itself parses into a blocked range. This stops an attacker from
//      passing 127.0.0.1 as a string literal in the URL.
//
// The SSRF check is intentionally synchronous in the request path. The
// 400 is the right place — the worker shouldn't have to redo the check
// on every retry, and an "accepted, later silently dropped" path is the
// hardest-to-debug failure mode.

import (
	"fmt"
	"mime/multipart"
	"net"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v2"

	"instant.dev/internal/crypto"
)

// notifyWebhookResolver is overridable so tests can inject a deterministic
// resolver without doing real DNS. Production code uses net.LookupIP.
//
// The signature returns []net.IP so the SSRF check can iterate every
// resolved A/AAAA record — a hostname pointing at one public and one
// private IP must still be rejected (mixed-record SSRF dodge).
var notifyWebhookResolver = func(host string) ([]net.IP, error) {
	return net.LookupIP(host)
}

// SetNotifyWebhookResolverForTest swaps the package-level DNS resolver used
// by validateNotifyWebhookURL. Test-only escape hatch — handler_test (a
// black-box package) can't reach the unexported var directly. The returned
// function restores the previous resolver; tests should `defer` it.
//
// Production code never calls this. The behaviour is identical to writing
// `notifyWebhookResolver = ...` inline, but the explicit name makes it
// easy to grep for test-only mutation in this file.
func SetNotifyWebhookResolverForTest(replacement func(host string) ([]net.IP, error)) func() {
	prev := notifyWebhookResolver
	notifyWebhookResolver = replacement
	return func() { notifyWebhookResolver = prev }
}

// parseNotifyWebhookFields extracts and validates the optional `notify_webhook`
// and `notify_webhook_secret` multipart fields from POST /deploy/new.
//
// Returns (rawURL, encryptedSecret, nil) on success. On failure, writes the
// 400 response inline and returns a non-nil error — caller MUST propagate
// it and return immediately (mirrors parsePrivateDeployFields).
//
// Behaviour:
//   - field absent / empty                  → ("", "", nil)
//   - URL fails SSRF / scheme / parse gate  → 400 + agent_action
//   - URL ok, secret absent                 → (url, "", nil)
//   - URL ok, secret present, AES key bad   → 503 (server-side; not user fault)
//   - URL ok, secret present, encrypts fine → (url, ciphertext, nil)
//
// The plaintext secret is never returned to the caller and never persisted
// in plaintext — Encrypt's output is what lands in the deployments row.
func parseNotifyWebhookFields(c *fiber.Ctx, form *multipart.Form, aesKeyHex string) (string, string, error) {
	rawURL := strings.TrimSpace(firstFormValue(form, "notify_webhook"))
	if rawURL == "" {
		// Field absent — nothing to validate, nothing to store. notify_state
		// stays at the column default ('unset'). Backward-compatible: any
		// existing caller that doesn't know about this field sees no change.
		return "", "", nil
	}

	if err := validateNotifyWebhookURL(rawURL); err != nil {
		return "", "", respondErrorWithAgentAction(c,
			fiber.StatusBadRequest,
			"invalid_notify_webhook",
			err.Error(),
			AgentActionNotifyWebhookInvalid,
			"")
	}

	rawSecret := firstFormValue(form, "notify_webhook_secret")
	if rawSecret == "" {
		return rawURL, "", nil
	}

	// Secret is supplied — encrypt with the platform AES key. Same path as
	// resources.connection_url, vault entries, webhook receive URLs.
	aesKey, keyErr := crypto.ParseAESKey(aesKeyHex)
	if keyErr != nil {
		// Operator error — AES_KEY is misconfigured. Surface as 503 because
		// the user can't fix it; the platform must.
		return "", "", respondError(c,
			fiber.StatusServiceUnavailable,
			"encryption_unavailable",
			"Webhook secret encryption is misconfigured on the server")
	}
	ciphertext, encErr := crypto.Encrypt(aesKey, rawSecret)
	if encErr != nil {
		return "", "", respondError(c,
			fiber.StatusServiceUnavailable,
			"encryption_failed",
			"Failed to encrypt webhook secret")
	}
	return rawURL, ciphertext, nil
}

// validateNotifyWebhookURL is the SSRF + scheme gate. Pure function — no IO
// other than the DNS lookup via notifyWebhookResolver. Returns an error whose
// message is safe to surface in the 400 body (no internal IPs leaked).
func validateNotifyWebhookURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("notify_webhook is not a valid URL")
	}
	if u.Scheme != "https" {
		return fmt.Errorf("notify_webhook must use https:// (got %q)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("notify_webhook is missing a hostname")
	}
	// Reject "localhost" by literal name before any DNS — /etc/hosts can
	// remap it but we never want an inbound URL claiming localhost.
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return fmt.Errorf("notify_webhook hostname is not publicly routable")
	}

	// If the host parses as an IP literal, check it directly — no need to
	// hit DNS for an IP, and DNS would just resolve to itself.
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(ip) {
			return fmt.Errorf("notify_webhook IP is in a blocked range (private / loopback / link-local)")
		}
		return nil
	}

	// Hostname — resolve and check every resulting IP. A hostname that
	// resolves to BOTH a public and a private IP is rejected (the mixed-
	// record SSRF dodge: attacker controls DNS, returns 8.8.8.8 + 10.0.0.5).
	ips, err := notifyWebhookResolver(host)
	if err != nil {
		return fmt.Errorf("notify_webhook hostname does not resolve")
	}
	if len(ips) == 0 {
		return fmt.Errorf("notify_webhook hostname has no A/AAAA records")
	}
	for _, ip := range ips {
		if isBlockedIP(ip) {
			return fmt.Errorf("notify_webhook hostname resolves to a private / loopback / link-local IP")
		}
	}
	return nil
}

// isBlockedIP returns true if ip is in any range we refuse to dispatch to.
//
// The set is deliberately broad — anything that isn't unambiguously a public
// internet IP is blocked. This is the SSRF safety net so we err on the side
// of false positives (rejecting weird-but-legal URLs) over false negatives
// (letting the worker POST to cloud metadata).
//
// Blocked:
//   - IPv4 loopback        127.0.0.0/8
//   - IPv4 private         10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
//   - IPv4 link-local      169.254.0.0/16  (covers AWS/GCP metadata 169.254.169.254)
//   - IPv4 CGNAT           100.64.0.0/10
//   - IPv4 multicast       224.0.0.0/4
//   - IPv4 broadcast       255.255.255.255
//   - IPv6 loopback        ::1
//   - IPv6 unspecified     ::
//   - IPv6 link-local      fe80::/10
//   - IPv6 unique-local    fc00::/7
//   - IPv6 multicast       ff00::/8
//   - IPv6 IPv4-mapped     ::ffff:0:0/96 (re-checked as v4 to catch e.g. ::ffff:127.0.0.1)
//   - any unspecified      0.0.0.0
func isBlockedIP(ip net.IP) bool {
	// Standard-library predicates cover most of the surface. We do them
	// first because they're the cheapest checks and they hit the common
	// SSRF targets (loopback, link-local, multicast, private).
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsUnspecified() || ip.IsPrivate() {
		return true
	}
	// IPv4-mapped IPv6 — re-check as v4 so ::ffff:10.0.0.1 doesn't slip past.
	if v4 := ip.To4(); v4 != nil {
		// CGNAT 100.64.0.0/10 — not covered by IsPrivate(). Catches the
		// shared address space carriers use behind NAT.
		_, cgnat, _ := net.ParseCIDR("100.64.0.0/10")
		if cgnat.Contains(v4) {
			return true
		}
		// Broadcast 255.255.255.255 — limited-broadcast literal.
		if v4.Equal(net.IPv4bcast) {
			return true
		}
	}
	return false
}

// AgentActionNotifyWebhookInvalid is the agent_action copy returned on every
// 400 from the notify_webhook validation gate (bad scheme, private/loopback
// IP, unresolvable hostname). Single sentence, names the rejection reason
// (private / loopback / not https), names the exact next action (supply a
// public https URL or omit the field), contains the full docs URL.
const AgentActionNotifyWebhookInvalid = "Tell the user the notify_webhook URL must be a public https:// endpoint — private/loopback IPs and http:// are rejected. Have them omit the field or use a public webhook URL — see https://instanode.dev/docs/deploy-webhooks."
