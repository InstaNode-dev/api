package handlers

// deletion_confirm_helpers_coverage_test.go — white-box coverage for the pure
// helpers + the email-link redirect handler in deletion_confirm.go. These were
// 0%/low under CI because the full request flow (requestEmailConfirmedDeletion)
// is reached only through the deploy/stack delete-confirm endpoints, which the
// happy-path tests skip when provisioning is unavailable. The helpers below are
// pure (string/URL composition) or a no-side-effect redirect, so a focused
// white-box test exercises every branch deterministically.

import (
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

func TestEmailConfirmDeletionRedirectHandler(t *testing.T) {
	h := EmailConfirmDeletionRedirectHandler("https://dash.local/")
	app := fiber.New()
	app.Get("/auth/email/confirm-deletion", h)

	// Missing token → 400.
	resp, err := app.Test(httptest.NewRequest("GET", "/auth/email/confirm-deletion", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Errorf("missing token status = %d; want 400", resp.StatusCode)
	}
	resp.Body.Close()

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
