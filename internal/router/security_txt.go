package router

// security_txt.go — RFC 9116 /.well-known/security.txt handler builder.
//
// Extracted from router.go's inline closure so the handler stays
// directly addressable from package_test.go (the New(...) wiring path
// is heavyweight to bring up in a test — needs Postgres + Redis + gRPC
// — and the 100%-of-changed-lines patch coverage gate trips on lines
// only reachable through that path). Keeping the body builder + the
// handler closure here makes the unit test cover both via a direct
// call.
//
// The handler is deliberately stateless. It captures `now` at builder
// time so the Expires field round-trips through `time.Time` (and tests
// can inject a known time without relying on time.Now() drift).

import (
	"time"

	"github.com/gofiber/fiber/v2"
)

// makeSecurityTxtHandler returns a fiber handler that serves the RFC
// 9116 security.txt body. The body's Expires field is set to 1 year
// after `now` (RFC 9116 §2.5.5 SHOULD-NOT exceed 1 year), so each
// fresh deploy pushes the window forward — the file stays valid as
// long as the binary is redeployed regularly.
//
// Body content is constant across handler instances except for the
// Expires field, which is the only time-varying line.
func makeSecurityTxtHandler(now time.Time) fiber.Handler {
	expiresAt := now.UTC().AddDate(1, 0, 0).Format("2006-01-02T15:04:05Z")
	body := buildSecurityTxtBody(expiresAt)
	return func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, "text/plain; charset=utf-8")
		return c.SendString(body)
	}
}

// buildSecurityTxtBody assembles the RFC 9116 body. Split from
// makeSecurityTxtHandler so the body shape is testable without
// instantiating a fiber.Handler closure.
//
// Field order matches the RFC's example: Contact (mandatory, ×2 for
// channel redundancy), Expires (mandatory), then the recommended
// fields. Trailing newline on the final field per §2.3 line-format
// (every field MUST be CRLF-terminated; LF-only is widely accepted
// and is what every other instanode file uses).
func buildSecurityTxtBody(expiresAt string) string {
	return "Contact: mailto:security@instanode.dev\n" +
		"Contact: https://instanode.dev/security\n" +
		"Expires: " + expiresAt + "\n" +
		"Preferred-Languages: en\n" +
		"Canonical: https://api.instanode.dev/.well-known/security.txt\n" +
		"Policy: https://instanode.dev/security\n"
}
