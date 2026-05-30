package handlers

// deletion_confirm_helpers_coverage_test.go — white-box coverage for the pure
// helpers + the email-link redirect handler in deletion_confirm.go. These were
// 0%/low under CI because the full request flow (requestEmailConfirmedDeletion)
// is reached only through the deploy/stack delete-confirm endpoints, which the
// happy-path tests skip when provisioning is unavailable. The helpers below are
// pure (string/URL composition) or a no-side-effect redirect, so a focused
// white-box test exercises every branch deterministically.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"

	"instant.dev/internal/models"
)

func TestConfirmationLinkBase(t *testing.T) {
	// API_PUBLIC_URL wins when set (trailing slash trimmed).
	if got := confirmationLinkBase("https://api.instanode.dev/", "https://dash.local"); got != "https://api.instanode.dev" {
		t.Errorf("apiPublicURL path = %q", got)
	}
	// Falls back to dashboard when API_PUBLIC_URL empty.
	if got := confirmationLinkBase("  ", "https://dash.local/"); got != "https://dash.local" {
		t.Errorf("dashboard fallback = %q", got)
	}
}

func TestBuildConfirmationLink(t *testing.T) {
	prod := buildConfirmationLink("https://api.instanode.dev", "https://dash.local", "tok123")
	if !strings.HasPrefix(prod, "https://api.instanode.dev/auth/email/confirm-deletion?t=tok123") {
		t.Errorf("prod link = %q", prod)
	}
	dev := buildConfirmationLink("", "https://dash.local", "tok123")
	if !strings.HasPrefix(dev, "https://dash.local/app/confirm-deletion?t=tok123") {
		t.Errorf("dev link = %q", dev)
	}
}

func TestTeamIsPaid(t *testing.T) {
	if teamIsPaid(nil) {
		t.Error("nil team must be unpaid")
	}
	for _, tier := range []string{"hobby", "pro", "team", "growth"} {
		if !teamIsPaid(&models.Team{PlanTier: tier}) {
			t.Errorf("tier %q must be paid", tier)
		}
	}
	for _, tier := range []string{"anonymous", "free", ""} {
		if teamIsPaid(&models.Team{PlanTier: tier}) {
			t.Errorf("tier %q must be unpaid", tier)
		}
	}
}

func TestDeletionAuditKindHelpers(t *testing.T) {
	cases := []struct {
		rt              string
		wantReqStack    bool
	}{
		{models.PendingDeletionResourceStack, true},
		{models.PendingDeletionResourceDeploy, false},
		{"something_else", false},
	}
	for _, tc := range cases {
		req := deletionAuditKindRequested(tc.rt)
		conf := deletionAuditKindConfirmed(tc.rt)
		canc := deletionAuditKindCancelled(tc.rt)
		if tc.wantReqStack {
			if req != models.AuditKindStackDeletionRequested ||
				conf != models.AuditKindStackDeletionConfirmed ||
				canc != models.AuditKindStackDeletionCancelled {
				t.Errorf("rt=%q stack kinds wrong: %s/%s/%s", tc.rt, req, conf, canc)
			}
		} else {
			if req != models.AuditKindDeployDeletionRequested ||
				conf != models.AuditKindDeployDeletionConfirmed ||
				canc != models.AuditKindDeployDeletionCancelled {
				t.Errorf("rt=%q deploy kinds wrong: %s/%s/%s", tc.rt, req, conf, canc)
			}
		}
	}
}

func TestDeletionAuditResourceType(t *testing.T) {
	if got := deletionAuditResourceType(models.AuditKindStackDeletionRequested); got != "stack" {
		t.Errorf("stack kind => %q", got)
	}
	if got := deletionAuditResourceType(models.AuditKindDeployDeletionRequested); got != "deploy" {
		t.Errorf("deploy kind => %q", got)
	}
}

func TestShouldSkipEmailConfirmation_bvwave(t *testing.T) {
	app := fiber.New()
	defer app.Shutdown()
	app.Get("/h", func(c *fiber.Ctx) error {
		return c.SendString(map[bool]string{true: "skip", false: "noskip"}[shouldSkipEmailConfirmation(c)])
	})
	read := func(hdr string) string {
		req := httptest.NewRequest("GET", "/h", nil)
		if hdr != "" {
			req.Header.Set(SkipEmailConfirmationHeader, hdr)
		}
		resp, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		buf := make([]byte, 16)
		n, _ := resp.Body.Read(buf)
		return string(buf[:n])
	}
	// "yes" / "YES" / " Yes " (case-insensitive, trimmed) → skip.
	for _, v := range []string{"yes", "YES", " Yes "} {
		if read(v) != "skip" {
			t.Errorf("header %q should skip", v)
		}
	}
	// Empty / other values → no skip.
	for _, v := range []string{"", "no", "true", "1"} {
		if read(v) != "noskip" {
			t.Errorf("header %q should NOT skip", v)
		}
	}
}

func TestEmailConfirmDeletionRedirectHandler(t *testing.T) {
	h := EmailConfirmDeletionRedirectHandler("https://dash.local/")
	// BUG-API-047/204/273: respondError returns ErrResponseWritten as a
	// sentinel — fiber's default ErrorHandler would otherwise overwrite
	// the JSON body with the sentinel string. Mirror the production
	// router's swallow-sentinel handler so the assertions read the body
	// the handler actually wrote.
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, ErrResponseWritten) {
				return nil
			}
			return fiber.DefaultErrorHandler(c, err)
		},
	})
	app.Get("/auth/email/confirm-deletion", h)

	// BUG-API-047 / BUG-API-204 / BUG-API-273 (QA 2026-05-29):
	// missing-token branch must return the canonical {ok,error,message,
	// request_id,agent_action} envelope on Content-Type application/json,
	// NOT text/plain "Missing token" which broke agents grepping on
	// `error: missing_token`. Pin both the wire format and the canonical
	// error code so a future revert to SendString fails this test.
	resp, err := app.Test(httptest.NewRequest("GET", "/auth/email/confirm-deletion", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Errorf("missing token status = %d; want 400", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("BUG-API-204/273: missing-token Content-Type = %q; want application/json (envelope, not text/plain)", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var env struct {
		OK          bool   `json:"ok"`
		Error       string `json:"error"`
		Message     string `json:"message"`
		RequestID   string `json:"request_id"`
		AgentAction string `json:"agent_action"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("BUG-API-204/273: missing-token body not JSON: %v (body=%q)", err, string(body))
	}
	if env.OK {
		t.Errorf("BUG-API-204/273: envelope.ok = true; want false on 400")
	}
	if env.Error != "missing_token" {
		t.Errorf("BUG-API-047: envelope.error = %q; want %q (canonical code used across onboarding.go/magic_link.go/deletion_confirm.go)", env.Error, "missing_token")
	}
	if env.Message == "" {
		t.Errorf("BUG-API-204/273: envelope.message empty")
	}
	// codeToAgentAction has a `missing_token` entry, so the envelope
	// MUST carry a non-empty agent_action through respondError.
	if env.AgentAction == "" {
		t.Errorf("BUG-API-204/273: envelope.agent_action empty — codeToAgentAction[missing_token] should populate this")
	}

	// With token → 302 to the dashboard confirm page.
	resp, err = app.Test(httptest.NewRequest("GET", "/auth/email/confirm-deletion?t=abc", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 302 {
		t.Errorf("with token status = %d; want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc != "https://dash.local/app/confirm-deletion?t=abc" {
		t.Errorf("redirect Location = %q", loc)
	}
	resp.Body.Close()
}
