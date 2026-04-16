package middleware

import (
	"net"
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

// FingerprintMiddleware computes a stable per-subnet+ASN fingerprint and stores it
// in Fiber locals under the key "fingerprint". It accepts a FingerprintConfig so
// callers can control spoofing-prevention behaviour.
func FingerprintMiddleware(cfg FingerprintConfig) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var ipStr string
		if cfg.Production {
			// Use the rightmost entry in X-Forwarded-For — the last trusted edge hop.
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
