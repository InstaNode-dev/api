package handlers_test

// auth_cli_domain_test.go — guards B13-P0-F1 (2026-05-20).
//
// POST /auth/cli returns auth_url that the user MUST visit to complete
// OAuth. It was previously hardcoded to https://instant.dev/login in
// production — instant.dev is the dead-brand marketing host (returns 404).
// An agent following the auth_url landed on a parking page and gave up.
//
// Two regression guards here:
//
//  1. TestAuth_CLI_ReturnsInstanodeDomain — wire-level test that asserts
//     the literal returned by POST /auth/cli starts with the canonical
//     instanode.dev base (when DASHBOARD_BASE_URL is set explicitly).
//
//  2. TestAuth_CLI_NoLegacyInstantDevInResponses — coverage test that
//     enumerates every URL string surfaced by the handler layer and
//     fails if any handler-emitted string mentions instant.dev/login,
//     instant.dev/start, instant.dev/docs, instant.dev/billing, etc.
//     This is the rule-17 coverage block: adding a new handler that
//     emits a dead-brand URL fails this test, not a production browser.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// TestAuth_CLI_ReturnsInstanodeDomain — POST /auth/cli must return an
// auth_url rooted at cfg.DashboardBaseURL (the prod value is
// https://instanode.dev). instant.dev is the dead-brand host and must never
// appear in this response.
func TestAuth_CLI_ReturnsInstanodeDomain(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	cases := []struct {
		name             string
		dashboardBaseURL string
		environment      string
		wantPrefix       string
		// wantNoSubstr is the dead-brand fragment that MUST NOT appear
		// in any field of the response — catches a regression where
		// some unrelated field accidentally interpolates the host.
		wantNoSubstr string
	}{
		{
			name:             "production-with-explicit-base",
			dashboardBaseURL: "https://instanode.dev",
			environment:      "production",
			wantPrefix:       "https://instanode.dev/login?cli_session=",
			wantNoSubstr:     "instant.dev",
		},
		{
			name:             "production-fallback-when-base-empty",
			dashboardBaseURL: "",
			environment:      "production",
			wantPrefix:       "https://instanode.dev/login?cli_session=",
			wantNoSubstr:     "instant.dev/login",
		},
		{
			name:             "local-dev-default",
			dashboardBaseURL: "http://localhost:5173",
			environment:      "development",
			wantPrefix:       "http://localhost:5173/login?cli_session=",
			wantNoSubstr:     "instant.dev",
		},
		{
			name:             "trailing-slash-stripped",
			dashboardBaseURL: "https://instanode.dev/",
			environment:      "production",
			wantPrefix:       "https://instanode.dev/login?cli_session=",
			wantNoSubstr:     "//login",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{
				Port:             "8080",
				JWTSecret:        testhelpers.TestJWTSecret,
				AESKey:           testhelpers.TestAESKeyHex,
				EnabledServices:  "redis",
				Environment:      tc.environment,
				DashboardBaseURL: tc.dashboardBaseURL,
			}
			planReg := plans.Default()
			cliAuthH := handlers.NewCLIAuthHandler(db, rdb, cfg, planReg)

			app := fiber.New()
			app.Use(middleware.RequestID())
			app.Post("/auth/cli", cliAuthH.CreateCLISession)

			req := httptest.NewRequest(http.MethodPost, "/auth/cli", nil)
			resp, err := app.Test(req, 5000)
			require.NoError(t, err)
			defer resp.Body.Close()

			require.Equal(t, http.StatusCreated, resp.StatusCode,
				"POST /auth/cli must return 201 with an auth_url")

			var body map[string]any
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

			authURL, _ := body["auth_url"].(string)
			require.NotEmpty(t, authURL, "auth_url must be present in response")

			assert.True(t, strings.HasPrefix(authURL, tc.wantPrefix),
				"auth_url %q must start with %q (DASHBOARD_BASE_URL drives this)",
				authURL, tc.wantPrefix)

			// Catch any field in the response that mentions the dead-brand host.
			// JSON-encode the whole response so we cover fields we may add later.
			raw, _ := json.Marshal(body)
			if tc.wantNoSubstr != "" {
				assert.NotContains(t, string(raw), tc.wantNoSubstr,
					"response must not mention the dead-brand host %q anywhere",
					tc.wantNoSubstr)
			}
		})
	}
}

// TestAuth_CLI_NoLegacyInstantDevInResponses is the rule-17 coverage test
// (CLAUDE.md). It walks every .go source file under internal/handlers/ and
// fails if any non-comment, non-test string literal contains a known
// dead-brand URL fragment (instant.dev/login, instant.dev/start,
// instant.dev/docs, r2.instant.dev, etc.).
//
// Two carve-outs documented inline:
//
//   - Go import paths and OTel tracer names like "instant.dev/handlers",
//     "instant.dev/internal/...", and "instant.dev/proto" — those are
//     module identifiers, NOT URLs an agent or user will follow.
//   - Kubernetes label prefixes like "instant.dev/owner-team",
//     "instant.dev/role", "instant.dev/tier", "instant.dev/tenant",
//     "instant.dev/stack", "instant.dev/component", "instant.dev/redeploy-at",
//     "instant.dev/custom-domain" — those are label keys (kubernetes naming
//     convention), NOT user-visible URLs.
//
// Any OTHER use of instant.dev/<segment> in a non-test, non-comment string
// literal under internal/handlers/ is treated as a dead-brand leak.
//
// Why scan source rather than runtime responses: an agent that adds a new
// 5xx error message containing "see https://instant.dev/foo" would never
// be hit by an integration test until a customer reports the dead link.
// Scanning the source lights up at gate time.
func TestAuth_CLI_NoLegacyInstantDevInResponses(t *testing.T) {
	// Resolve the handlers/ directory relative to this test file's package.
	// The test runs from the package dir, so "." is internal/handlers.
	root, err := filepath.Abs(".")
	require.NoError(t, err)

	// Carve-outs: substrings that, when found, mean the match is NOT a
	// user-facing URL. The match is judged against the full instant.dev/<x>
	// fragment after stripping these prefixes.
	knownLabelKeys := []string{
		"instant.dev/owner-team",
		"instant.dev/role",
		"instant.dev/tier",
		"instant.dev/tenant",
		"instant.dev/stack",
		"instant.dev/component",
		"instant.dev/redeploy-at",
		"instant.dev/custom-domain",
		"instant.dev/handlers", // OTel tracer name
	}
	// Import-path carve-out. Any line that looks like a Go import literal
	// "instant.dev/<go-package>" is a module path, not a URL.
	importPathRe := regexp.MustCompile(`"instant\.dev/(internal|common|proto|worker|provisioner)`)

	// What we hunt for: any instant.dev/<segment> mention in source.
	instantDevRe := regexp.MustCompile(`instant\.dev/[A-Za-z][A-Za-z0-9._\-]*`)

	var leaks []string
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		// Skip tests (this file included). Coverage policy applies to
		// production handler code, not the regression scaffolding around it.
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		lines := strings.Split(string(raw), "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			// Skip pure-comment lines — author intent matters; a comment
			// describing the old domain isn't a leak we surface to users.
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			matches := instantDevRe.FindAllString(line, -1)
			if len(matches) == 0 {
				continue
			}
			// Filter import paths (Go module identifiers, not URLs).
			if importPathRe.MatchString(line) {
				continue
			}
			for _, m := range matches {
				isLabel := false
				for _, k := range knownLabelKeys {
					if strings.HasPrefix(m, k) {
						isLabel = true
						break
					}
				}
				if isLabel {
					continue
				}
				rel, _ := filepath.Rel(root, path)
				leaks = append(leaks, rel+":"+authCLIItoa(i+1)+": "+m+"  (line: "+strings.TrimSpace(line)+")")
			}
		}
		return nil
	})
	require.NoError(t, err)

	if len(leaks) > 0 {
		t.Errorf("dead-brand instant.dev/<x> URL fragments found in handler source — these reach agents/users.\nUse instanode.dev or cfg.DashboardBaseURL instead.\n\nLeaks:\n  %s",
			strings.Join(leaks, "\n  "))
	}
}

// authCLIItoa is a tiny strconv-free integer formatter so this test file
// doesn't import strconv just for line numbers. Named with the test
// prefix to avoid colliding with another `itoa` helper in this package.
func authCLIItoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
