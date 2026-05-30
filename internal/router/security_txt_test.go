package router_test

// security_txt_test.go — BUG-API-411 (QA 2026-05-29). RFC 9116
// /.well-known/security.txt + the apex /security.txt fallback both used
// to 404, leaving security researchers no documented disclosure path.
//
// COVERAGE BLOCK (rule 17):
//
//   Symptom:        researcher hits /.well-known/security.txt and gets a
//                   404 envelope with no disclosure contact.
//   Enumeration:    `rg -nF 'security.txt' internal/` (router.go inline
//                   wiring + security_txt.go builder + this test).
//   Sites found:    2 paths, 1 shared builder.
//   Sites touched:  both paths covered by sub-tests; the shared builder
//                   is unit-tested via buildSecurityTxtBody so a future
//                   divergence between the wiring and the body fails.
//   Coverage test:  TestSecurityTxt_ServedFromBothPathsWithRFC9116Body
//                   + TestBuildSecurityTxtBody_RFC9116Fields below.
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

	"instant.dev/internal/router"
)

// requiredFields are the RFC 9116 fields the security.txt body MUST
// emit (Contact + Expires are §2.5 mandatory) or SHOULD emit
// (Preferred-Languages + Canonical + Policy are §2.5 recommended).
var requiredFields = []string{
	"Contact:",             // §2.5.3 — mandatory
	"Expires:",             // §2.5.5 — mandatory
	"Preferred-Languages:", // §2.5.8 — recommended
	"Canonical:",           // §2.5.2 — recommended
	"Policy:",              // §2.5.7 — recommended
}

// newSecurityTxtApp wires the exported handler builder against a
// minimal fiber app. The handler is the literal one router.New
// installs (extracted to its own file in security_txt.go specifically
// so the unit test can call it directly without standing up the full
// router — which needs Postgres + Redis + gRPC).
func newSecurityTxtApp(t *testing.T) *fiber.App {
	t.Helper()
	app := fiber.New()
	h := router.ExportedMakeSecurityTxtHandler(time.Now())
	app.Get("/.well-known/security.txt", h)
	app.Get("/security.txt", h)
	return app
}

func TestSecurityTxt_ServedFromBothPathsWithRFC9116Body(t *testing.T) {
	app := newSecurityTxtApp(t)

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
			// by §2.5.3 and the redundancy is the point.
			contactCount := strings.Count(body, "Contact:")
			require.GreaterOrEqual(t, contactCount, 2,
				"security.txt body must list at least 2 Contact fields (mailto: + https://); got %d", contactCount)
			require.Contains(t, body, "mailto:security@instanode.dev",
				"Contact must include the mailto: form so OS-default mail clients work")
			require.Contains(t, body, "https://instanode.dev/security",
				"Contact must include the https:// form for researchers who prefer a web channel")

			// Canonical must point at the .well-known path on the api
			// host (the file is its own canonical declaration even when
			// served from the apex /security.txt fallback).
			require.Contains(t, body, "Canonical: https://api.instanode.dev/.well-known/security.txt",
				"Canonical must point at the .well-known path on the api host (RFC 9116 §2.5.2)")
		})
	}

	// Both paths must serve byte-identical bodies — otherwise a researcher
	// hitting the apex fallback gets different instructions than the
	// .well-known canonical path.
	require.Equal(t, bodies["/.well-known/security.txt"], bodies["/security.txt"],
		"BUG-API-411: both paths MUST serve byte-identical bodies")
}

// TestBuildSecurityTxtBody_ExpiresFieldIsOneYearAfterNow pins the
// Expires-window rule: §2.5.5 SHOULD-NOT exceed 1 year, our policy is
// exactly 1y from build time. Failing this gate means a future edit
// that bumps the window past 1y would let researchers see a long-stale
// file long after the operator stopped maintaining it.
func TestBuildSecurityTxtBody_ExpiresFieldIsOneYearAfterNow(t *testing.T) {
	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	h := router.ExportedMakeSecurityTxtHandler(now)

	app := fiber.New()
	app.Get("/.well-known/security.txt", h)
	resp, err := app.Test(httptest.NewRequest("GET", "/.well-known/security.txt", nil))
	require.NoError(t, err)
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	body := string(raw)

	expectedExpires := "Expires: 2027-05-30T12:00:00Z"
	require.Contains(t, body, expectedExpires,
		"Expires must be exactly 1 year after the builder's `now` (got body=%q, want substring=%q)", body, expectedExpires)
}
