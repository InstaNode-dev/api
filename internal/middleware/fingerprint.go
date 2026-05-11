package middleware

import (
	"crypto/subtle"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"instant.dev/internal/crypto"
)

// FingerprintConfig controls how the fingerprint middleware extracts the client IP.
type FingerprintConfig struct {
	// Production, when true, uses the rightmost (last-hop) IP from X-Forwarded-For
	// to prevent header spoofing by clients. In development mode the leftmost entry
	// (i.e. c.IP() which Fiber resolves) is used.
	Production bool
}

// e2eTestTokenEnv is the env var holding a shared secret that, when matched
// in an X-E2E-Test-Token request header, lets the request override the
// fingerprint's source IP. This is the ONLY production-mode escape hatch and
// is intended exclusively for E2E suites running against the live cluster
// from a single dev workstation — every request from that workstation
// otherwise shares a fingerprint and hits the per-day provision cap.
//
// Operationally: set E2E_TEST_TOKEN to a 32-char hex secret in the cluster
// config; export the same value as E2E_TEST_TOKEN in the test runner. When
// both match, the LEFTMOST X-Forwarded-For entry (the one the test set)
// is used as the source IP, restoring per-test isolation.
const e2eTestTokenEnv = "E2E_TEST_TOKEN"

// e2eTrustHeader is the request header carrying the shared secret.
const e2eTrustHeader = "X-E2E-Test-Token"

// e2eSourceIPHeader carries the override source IP. Used instead of
// X-Forwarded-For because some reverse proxies (notably ingress-nginx with
// default use-forwarded-headers=false) overwrite XFF with the real client IP,
// dropping any test-supplied value. A custom header is passed through verbatim.
const e2eSourceIPHeader = "X-E2E-Source-IP"

// FingerprintMiddleware computes a stable per-subnet+ASN fingerprint and stores it
// in Fiber locals under the key "fingerprint". It accepts a FingerprintConfig so
// callers can control spoofing-prevention behaviour.
func FingerprintMiddleware(cfg FingerprintConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var ipStr string

		// E2E bypass: independent of cfg.Production. When the request bears a
		// valid X-E2E-Test-Token matching the cluster's shared secret, the
		// override source IP from X-E2E-Source-IP is used instead of the
		// reverse-proxy-resolved IP. ingress-nginx defaults to overwriting
		// X-Forwarded-For with the real client IP, which collapses every
		// test request from one workstation onto the same fingerprint and
		// trips the per-day provision cap. The dedicated header is passed
		// through verbatim by every reverse proxy, sidestepping the issue.
		if e2eTokenAccepted(c) {
			if v := strings.TrimSpace(c.Get(e2eSourceIPHeader)); v != "" {
				ipStr = v
			}
		}
		if cfg.Production && ipStr == "" {
			// Use the rightmost (last-hop) XFF entry — the trusted edge hop.
			xff := c.Get("X-Forwarded-For")
			if xff != "" {
				parts := strings.Split(xff, ",")
				ipStr = strings.TrimSpace(parts[len(parts)-1])
			}
		}
		if ipStr == "" {
			ipStr = c.IP()
		}

		asn := GetGeoASN(c)

		ip := net.ParseIP(ipStr)
		if ip == nil {
			ip = net.IPv4(0, 0, 0, 0)
		}

		fp := crypto.Fingerprint(ip, asn)
		c.Locals("fingerprint", fp)

		return c.Next()
	}
}

// Fingerprint is the default fingerprint middleware with development-mode config.
// Use FingerprintMiddleware(FingerprintConfig{Production: true}) in production deployments.
func Fingerprint() fiber.Handler {
	return FingerprintMiddleware(FingerprintConfig{})
}

// GetFingerprint retrieves the computed fingerprint from Fiber locals.
func GetFingerprint(c *fiber.Ctx) string {
	if fp, ok := c.Locals("fingerprint").(string); ok {
		return fp
	}
	return ""
}

// e2eTokenAccepted reports whether the request carries a valid E2E trust
// token matching the cluster's shared secret. Returns false if the env var
// is unset (default — no bypass available).
func e2eTokenAccepted(c *fiber.Ctx) bool {
	expected := os.Getenv(e2eTestTokenEnv)
	if expected == "" {
		return false
	}
	got := c.Get(e2eTrustHeader)
	if got == "" {
		// Debug: log headers we DO have — helps detect proxy stripping.
		// Triggers only when bypass is enabled but header missing.
		hdrs := []string{}
		c.Request().Header.VisitAll(func(k, v []byte) {
			hdrs = append(hdrs, string(k))
		})
		slog.Info("e2e_bypass.token_missing",
			"have_headers", strings.Join(hdrs, ","))
		return false
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1 {
		return true
	}
	slog.Warn("e2e_bypass.token_mismatch",
		"got_len", len(got), "expected_len", len(expected),
		"got_prefix", got[:min(8, len(got))])
	return false
}

