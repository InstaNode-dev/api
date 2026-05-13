package handlers

// deploy_webhook_notify_test.go — Unit tests for the SSRF / scheme gate in
// validateNotifyWebhookURL. These live in package handlers (white-box) so
// they can swap out notifyWebhookResolver — production code does real DNS,
// tests inject a deterministic resolver per-table-case.
//
// The black-box end-to-end tests (handler accepts/rejects, persisted state)
// live in deploy_webhook_notify_handler_test.go (package handlers_test).

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubResolver returns the supplied IPs for any hostname. Used to bypass
// real DNS in tests so we can exercise the IP-classification branches
// without depending on the world.
func stubResolver(ips ...string) func(string) ([]net.IP, error) {
	parsed := make([]net.IP, 0, len(ips))
	for _, s := range ips {
		parsed = append(parsed, net.ParseIP(s))
	}
	return func(host string) ([]net.IP, error) {
		return parsed, nil
	}
}

// errResolver simulates DNS failure for the unresolvable-hostname branch.
func errResolver() func(string) ([]net.IP, error) {
	return func(host string) ([]net.IP, error) {
		return nil, errors.New("no such host")
	}
}

// restoreResolver swaps the package-level resolver back at the end of a
// test. Tests run in parallel within a package so a leaky resolver would
// poison later cases — Cleanup keeps the swap scoped.
func restoreResolver(t *testing.T, replacement func(string) ([]net.IP, error)) {
	t.Helper()
	prev := notifyWebhookResolver
	notifyWebhookResolver = replacement
	t.Cleanup(func() { notifyWebhookResolver = prev })
}

// TestValidateNotifyWebhookURL_HTTPSPublic accepts the happy path: an
// https URL whose hostname resolves to a public IP.
func TestValidateNotifyWebhookURL_HTTPSPublic(t *testing.T) {
	restoreResolver(t, stubResolver("8.8.8.8"))

	err := validateNotifyWebhookURL("https://hooks.example.com/webhook")
	assert.NoError(t, err, "https URL with public-IP resolution must be accepted")
}

// TestValidateNotifyWebhookURL_RejectsHTTP guards the scheme gate.
// Plain http is rejected so the worker never POSTs over cleartext.
func TestValidateNotifyWebhookURL_RejectsHTTP(t *testing.T) {
	restoreResolver(t, stubResolver("8.8.8.8"))

	err := validateNotifyWebhookURL("http://hooks.example.com/webhook")
	require.Error(t, err, "http:// must be rejected")
	assert.Contains(t, err.Error(), "https",
		"error must name https as the required scheme so the user knows the fix")
}

// TestValidateNotifyWebhookURL_RejectsLocalhost guards the literal-hostname
// shortcut. "localhost" is rejected before any DNS lookup so /etc/hosts
// tricks can't sneak past.
func TestValidateNotifyWebhookURL_RejectsLocalhost(t *testing.T) {
	// Resolver wouldn't even be called for "localhost" because the literal
	// check fires first — but install a stub anyway so an accidental
	// resolver call wouldn't trigger real DNS.
	restoreResolver(t, stubResolver("8.8.8.8"))

	cases := []string{
		"https://localhost/webhook",
		"https://localhost:8080/webhook",
		"https://LOCALHOST/webhook", // case-insensitive
		"https://app.localhost/webhook",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			err := validateNotifyWebhookURL(raw)
			require.Error(t, err, "localhost variants must be rejected")
		})
	}
}

// TestValidateNotifyWebhookURL_RejectsPrivateIPLiteral guards the case
// where the URL embeds a private IP literal directly. No DNS needed.
func TestValidateNotifyWebhookURL_RejectsPrivateIPLiteral(t *testing.T) {
	restoreResolver(t, stubResolver("8.8.8.8"))

	cases := []string{
		"https://127.0.0.1/webhook",        // loopback
		"https://10.0.0.5/webhook",         // RFC1918 10/8
		"https://172.16.0.1/webhook",       // RFC1918 172.16/12
		"https://192.168.1.1/webhook",      // RFC1918 192.168/16
		"https://169.254.169.254/metadata", // cloud metadata (link-local)
		"https://100.64.0.1/webhook",       // CGNAT
		"https://0.0.0.0/webhook",          // unspecified
		"https://[::1]/webhook",            // IPv6 loopback
		"https://[fe80::1]/webhook",        // IPv6 link-local
		"https://[fc00::1]/webhook",        // IPv6 unique-local
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			err := validateNotifyWebhookURL(raw)
			assert.Error(t, err,
				"%s must be rejected as a blocked IP literal", raw)
			if err != nil {
				assert.True(t, strings.Contains(err.Error(), "blocked") ||
					strings.Contains(err.Error(), "private") ||
					strings.Contains(err.Error(), "loopback") ||
					strings.Contains(err.Error(), "publicly routable"),
					"error must explain the rejection class: %v", err)
			}
		})
	}
}

// TestValidateNotifyWebhookURL_RejectsHostnameResolvingPrivate guards the
// mixed-record SSRF dodge: an attacker controls DNS and points
// hooks.evil.com → [8.8.8.8, 10.0.0.5]. We must reject if ANY resolved
// IP is in a blocked range.
func TestValidateNotifyWebhookURL_RejectsHostnameResolvingPrivate(t *testing.T) {
	restoreResolver(t, stubResolver("8.8.8.8", "10.0.0.5"))

	err := validateNotifyWebhookURL("https://hooks.evil.com/webhook")
	require.Error(t, err,
		"hostname resolving to mix of public+private IPs must be rejected")
}

// TestValidateNotifyWebhookURL_RejectsUnresolvable guards the DNS-failure
// branch — a typo or non-existent hostname surfaces as a 400 (don't pretend
// the URL is fine if we can't even resolve it).
func TestValidateNotifyWebhookURL_RejectsUnresolvable(t *testing.T) {
	restoreResolver(t, errResolver())

	err := validateNotifyWebhookURL("https://does-not-exist.invalid./webhook")
	require.Error(t, err, "unresolvable hostname must be rejected")
}

// TestIsBlockedIP_CoversFullCIDRSet exercises isBlockedIP directly with the
// canonical representatives of each blocked range. This is the granular
// safety net under validateNotifyWebhookURL.
func TestIsBlockedIP_CoversFullCIDRSet(t *testing.T) {
	cases := map[string]bool{
		// Blocked
		"127.0.0.1":            true,
		"127.255.255.254":      true,
		"10.0.0.1":             true,
		"172.16.0.1":           true,
		"172.31.255.254":       true,
		"192.168.0.1":          true,
		"169.254.169.254":      true, // AWS/GCP metadata
		"100.64.0.1":           true, // CGNAT
		"100.127.255.254":      true, // CGNAT upper
		"224.0.0.1":            true, // multicast
		"255.255.255.255":      true, // limited broadcast
		"0.0.0.0":              true, // unspecified
		"::1":                  true,
		"fe80::1":              true,
		"fc00::1":              true,
		"::":                   true,

		// Public — must NOT be blocked
		"8.8.8.8":              false,
		"1.1.1.1":              false,
		"172.15.0.1":           false, // just below RFC1918
		"172.32.0.1":           false, // just above RFC1918
		"100.63.255.254":       false, // just below CGNAT
		"100.128.0.1":          false, // just above CGNAT
		"2001:4860:4860::8888": false, // Google IPv6 DNS
	}
	for ipStr, expected := range cases {
		t.Run(ipStr, func(t *testing.T) {
			ip := net.ParseIP(ipStr)
			require.NotNil(t, ip, "test fixture %q must parse as IP", ipStr)
			got := isBlockedIP(ip)
			assert.Equal(t, expected, got,
				"isBlockedIP(%q): want %v, got %v", ipStr, expected, got)
		})
	}
}

// TestValidateNotifyWebhookURL_RejectsMalformed guards the url.Parse failure
// branch. An obviously malformed URL surfaces as a clear 400.
func TestValidateNotifyWebhookURL_RejectsMalformed(t *testing.T) {
	restoreResolver(t, stubResolver("8.8.8.8"))
	cases := []string{
		"not a url",
		"://no-scheme",
		"https://",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			err := validateNotifyWebhookURL(raw)
			require.Error(t, err, "malformed URL %q must be rejected", raw)
		})
	}
}
