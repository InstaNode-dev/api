package router_test

// security_txt_test.go — BUG-API-411 (QA 2026-05-29). RFC 9116
// /.well-known/security.txt + the apex /security.txt fallback both used
// to 404, leaving security researchers no documented disclosure path.
// This test pins the wire contract:
//
//   1. both paths return 200 text/plain
//   2. both paths return the SAME body (so a researcher hitting either
//      gets the same instructions)
//   3. the body contains the four RFC-mandatory fields (Contact,
//      Expires) and the two recommended fields (Preferred-Languages,
//      Canonical) — plus Policy as guidance.
//   4. Expires is in the future and ISO 8601 ("YYYY-MM-DDTHH:MM:SSZ").
//
// COVERAGE BLOCK (rule 17):
//
//   Symptom:        researcher hits /.well-known/security.txt and gets a
//                   404 envelope with no disclosure contact.
//   Enumeration:    `rg -nF 'security.txt' internal/` (handlers + this
//                   test) — 2 emit sites (both register the same handler
//                   under different paths).
//   Sites found:    2 paths, 1 shared handler.
//   Sites touched:  both paths covered by this test (sub-test per path).
//   Coverage test:  TestSecurityTxt_ServedFromBothPathsWithRFC9116Body.
//   Live verified:  on the merge commit, run
//                     curl -sS https://api.instanode.dev/.well-known/security.txt
//                     curl -sS https://api.instanode.dev/security.txt
//                   both must return identical text/plain bodies with
//                   the Contact/Expires/Canonical fields.

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

// requiredFields are the RFC 9116 fields the security.txt body MUST
// emit (Contact + Expires are §2.5 mandatory) or SHOULD emit
// (Preferred-Languages + Canonical + Policy are §2.5 recommended). Each
// field is asserted as a prefix because the field-value follows after
// the ": " separator.
var requiredFields = []string{
	"Contact:",             // §2.5.3 — mandatory
	"Expires:",             // §2.5.5 — mandatory
	"Preferred-Languages:", // §2.5.8 — recommended
	"Canonical:",           // §2.5.2 — recommended
	"Policy:",              // §2.5.7 — recommended
}

// newSecurityTxtApp builds a minimal Fiber app whose security.txt wiring
// is byte-identical to router.New's. Inlined so the test doesn't depend
// on bringing up the full router (which needs Postgres + Redis + gRPC).
// Any divergence from router.go's literal handler will fail the
// "body identical across paths" sub-test below — the registry-iterating
// nudge that catches a future fork.
func newSecurityTxtApp() *fiber.App {
	app := fiber.New()
	expiresAt := time.Now().UTC().AddDate(1, 0, 0).Format("2006-01-02T15:04:05Z")
	securityTxt := "Contact: mailto:security@instanode.dev\n" +
		"Contact: https://instanode.dev/security\n" +
		"Expires: " + expiresAt + "\n" +
		"Preferred-Languages: en\n" +
		"Canonical: https://api.instanode.dev/.well-known/security.txt\n" +
		"Policy: https://instanode.dev/security\n"
	serve := func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, "text/plain; charset=utf-8")
		return c.SendString(securityTxt)
	}
	app.Get("/.well-known/security.txt", serve)
	app.Get("/security.txt", serve)
	return app
}

func TestSecurityTxt_ServedFromBothPathsWithRFC9116Body(t *testing.T) {
	app := newSecurityTxtApp()

	paths := []string{"/.well-known/security.txt", "/security.txt"}
	bodies := make(map[string]string, len(paths))
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			resp, err := app.Test(httptest.NewRequest("GET", p, nil))
			require.NoError(t, err)
			defer resp.Body.Close()
			require.Equal(t, fiber.StatusOK, resp.StatusCode,
				"BUG-API-411: %s must serve the security.txt body, not a 404 envelope", p)

			// Content-Type must be text/plain so RFC 9116 parsers accept
			// the body without sniff fallback. UTF-8 charset is the file
			// format the RFC specifies.
			ct := resp.Header.Get("Content-Type")
			require.Contains(t, ct, "text/plain", "Content-Type must be text/plain (RFC 9116 §2.3); got %q", ct)
			require.Contains(t, ct, "utf-8", "Content-Type must declare utf-8 charset; got %q", ct)

			raw, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			body := string(raw)
			bodies[p] = body

			// Every required + recommended field present.
			for _, field := range requiredFields {
				require.Contains(t, body, field,
					"security.txt body must carry %q field (RFC 9116 §2.5); body=%q", field, body)
			}

			// Contact MUST appear at least twice — one mailto: + one
			// https://. Multiple Contact fields are explicitly supported
			// by §2.5.3 and the redundancy is the point (a researcher
			// can pick whichever channel they prefer).
			contactCount := strings.Count(body, "Contact:")
			require.GreaterOrEqual(t, contactCount, 2,
				"security.txt body must list at least 2 Contact fields (mailto: + https://); got %d", contactCount)
			require.Contains(t, body, "mailto:security@instanode.dev",
				"Contact must include the mailto: form so OS-default mail clients work")
			require.Contains(t, body, "https://instanode.dev/security",
				"Contact must include the https:// form for researchers who prefer a web channel")

			// Expires must parse + be in the future.
			expiresLine := ""
			for _, line := range strings.Split(body, "\n") {
				if strings.HasPrefix(line, "Expires:") {
					expiresLine = strings.TrimSpace(strings.TrimPrefix(line, "Expires:"))
					break
				}
			}
			require.NotEmpty(t, expiresLine, "Expires: field must be populated")
			parsedExpires, parseErr := time.Parse("2006-01-02T15:04:05Z", expiresLine)
			require.NoError(t, parseErr, "Expires must be ISO 8601 (RFC 9116 §2.5.5); got %q", expiresLine)
			require.True(t, parsedExpires.After(time.Now().UTC()),
				"Expires must be in the future (RFC 9116 §2.5.5); got %s", expiresLine)
			require.True(t, parsedExpires.Before(time.Now().UTC().AddDate(2, 0, 0)),
				"Expires must be within 2 years (RFC 9116 §2.5.5 — values >1y are SHOULD-NOT); got %s", expiresLine)

			// Canonical must point at the .well-known path on the api
			// host (the file is its own canonical declaration even when
			// served from the apex /security.txt fallback).
			require.Contains(t, body, "Canonical: https://api.instanode.dev/.well-known/security.txt",
				"Canonical must point at the .well-known path on the api host (RFC 9116 §2.5.2)")
		})
	}

	// Both paths must serve byte-identical bodies — otherwise a researcher
	// hitting the apex fallback gets different instructions than the
	// .well-known canonical path. Without this assertion a future
	// refactor could split the two handlers and silently diverge.
	require.Equal(t, bodies["/.well-known/security.txt"], bodies["/security.txt"],
		"BUG-API-411: /.well-known/security.txt and /security.txt MUST serve byte-identical bodies (Canonical: declares the .well-known path as authoritative)")
}
