package email_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"instant.dev/internal/email"
)

// noopClient returns a noop email client (no backend keys).
func noopClient() *email.Client {
	return email.NewNoop()
}

// TestSendPaymentFailed_NoopClient_ReturnsNil verifies the noop client returns nil without error.
func TestSendPaymentFailed_NoopClient_ReturnsNil(t *testing.T) {
	c := noopClient()
	err := c.SendPaymentFailed(context.Background(), "user@example.com", 1, nil)
	if err != nil {
		t.Fatalf("expected nil error from noop client, got: %v", err)
	}
}

// TestSendPaymentFailed_AttemptCount1_NotUrgent verifies attempt 1 sends without error.
func TestSendPaymentFailed_AttemptCount1_NotUrgent(t *testing.T) {
	c := noopClient()
	next := time.Now().Add(72 * time.Hour)
	err := c.SendPaymentFailed(context.Background(), "user@example.com", 1, &next)
	if err != nil {
		t.Fatalf("attempt 1: expected nil, got: %v", err)
	}
}

// TestSendPaymentFailed_AttemptCount3_FinalAttempt verifies the final attempt (3) sends without error.
func TestSendPaymentFailed_AttemptCount3_FinalAttempt(t *testing.T) {
	c := noopClient()
	err := c.SendPaymentFailed(context.Background(), "user@example.com", 3, nil)
	if err != nil {
		t.Fatalf("attempt 3 (final): expected nil, got: %v", err)
	}
}

// TestSendPaymentFailed_NilNextAttemptDate verifies nil nextAttemptDate does not panic.
func TestSendPaymentFailed_NilNextAttemptDate(t *testing.T) {
	c := noopClient()
	// Must not panic.
	err := c.SendPaymentFailed(context.Background(), "user@example.com", 2, nil)
	if err != nil {
		t.Fatalf("nil nextAttemptDate: expected nil, got: %v", err)
	}
}

// TestSendPaymentFailed_WithNextAttemptDate verifies a non-nil nextAttemptDate sends without error.
func TestSendPaymentFailed_WithNextAttemptDate(t *testing.T) {
	c := noopClient()
	next := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	err := c.SendPaymentFailed(context.Background(), "user@example.com", 2, &next)
	if err != nil {
		t.Fatalf("with nextAttemptDate: expected nil, got: %v", err)
	}
}

// Trial email tests removed on 2026-05-14 per policy memory
// project_no_trial_pay_day_one.md — the SendTrialStarted, SendTrialWarning,
// and SendTrialExpired functions no longer exist.

// ---------------------------------------------------------------------------
// Provider-selection tests (added 2026-05-14 with the Brevo backend).
// ---------------------------------------------------------------------------

// TestProvider_NoopByDefault — empty config + both keys absent → noop.
// This pins the historical "no key = no send, no panic" contract that lets
// `make test` run without leaking real outbound emails.
func TestProvider_NoopByDefault(t *testing.T) {
	c := email.New(email.Config{})
	if got := c.ProviderName(); got != email.ProviderNoop {
		t.Fatalf("expected noop provider, got %q", got)
	}
}

// TestProvider_PicksBrevoWhenKeyPresent — BREVO_API_KEY trumps RESEND_API_KEY
// even when both are set. This matches the env-precedence rule in the commit
// message: Brevo > Resend > Noop.
func TestProvider_PicksBrevoWhenKeyPresent(t *testing.T) {
	c := email.New(email.Config{
		BrevoAPIKey:  "xkeysib-test",
		ResendAPIKey: "re_live_real_key_value",
	})
	if got := c.ProviderName(); got != email.ProviderBrevo {
		t.Fatalf("expected brevo provider when BREVO_API_KEY set, got %q", got)
	}
}

// TestProvider_PicksResendWhenBrevoMissing — fallback path. No Brevo key,
// Resend key present and non-sentinel → Resend wins. Also asserts the
// "CHANGE_ME" sentinel does NOT count as configured (the live-prod bug
// from 2026-05-14 that motivated this whole refactor).
func TestProvider_PicksResendWhenBrevoMissing(t *testing.T) {
	c := email.New(email.Config{ResendAPIKey: "re_test_real_value"})
	if got := c.ProviderName(); got != email.ProviderResend {
		t.Fatalf("expected resend provider, got %q", got)
	}

	// Sentinel "CHANGE_ME" must NOT activate Resend.
	c2 := email.New(email.Config{ResendAPIKey: "CHANGE_ME"})
	if got := c2.ProviderName(); got != email.ProviderNoop {
		t.Fatalf("CHANGE_ME sentinel: expected noop, got %q", got)
	}
}

// TestBrevoProvider_FormatsBody drives a fake Brevo server and asserts the
// exact JSON shape + headers the live API expects. This is the regression
// guard for the magic-link flow: if the body shape drifts, this test fails
// instead of production.
func TestBrevoProvider_FormatsBody(t *testing.T) {
	var (
		gotAPIKey      string
		gotContentType string
		gotMethod      string
		gotPath        string
		gotBody        map[string]any
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAPIKey = r.Header.Get("api-key")
		gotContentType = r.Header.Get("Content-Type")
		gotMethod = r.Method
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"messageId":"<test@brevo>"}`))
	}))
	defer srv.Close()

	// Build a client that POSTs to srv.URL instead of api.brevo.com by
	// swapping the HTTP transport. We do this with a custom http.Client
	// whose Transport rewrites the request URL.
	rewrite := &urlRewriter{base: srv.URL, inner: http.DefaultTransport}
	c := email.New(email.Config{
		Provider:    "brevo",
		BrevoAPIKey: "xkeysib-test-key",
		FromName:    "InstaNode",
		FromAddress: "noreply@instanode.dev",
		HTTPClient:  &http.Client{Transport: rewrite},
	})

	if err := c.SendMagicLink(context.Background(), "user@example.com", "https://app.example/magic?t=abc"); err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method: want POST, got %q", gotMethod)
	}
	if gotPath != "/v3/smtp/email" {
		t.Errorf("path: want /v3/smtp/email, got %q", gotPath)
	}
	if gotAPIKey != "xkeysib-test-key" {
		t.Errorf("api-key header: want xkeysib-test-key, got %q", gotAPIKey)
	}
	if !strings.HasPrefix(gotContentType, "application/json") {
		t.Errorf("Content-Type: want application/json*, got %q", gotContentType)
	}

	sender, ok := gotBody["sender"].(map[string]any)
	if !ok {
		t.Fatalf("sender: want object, got %T (%v)", gotBody["sender"], gotBody["sender"])
	}
	if sender["email"] != "noreply@instanode.dev" {
		t.Errorf("sender.email: want noreply@instanode.dev, got %v", sender["email"])
	}
	if sender["name"] != "InstaNode" {
		t.Errorf("sender.name: want InstaNode, got %v", sender["name"])
	}

	toList, ok := gotBody["to"].([]any)
	if !ok || len(toList) != 1 {
		t.Fatalf("to: want one recipient, got %v", gotBody["to"])
	}
	recip, _ := toList[0].(map[string]any)
	if recip["email"] != "user@example.com" {
		t.Errorf("to[0].email: want user@example.com, got %v", recip["email"])
	}

	if subj, _ := gotBody["subject"].(string); !strings.Contains(subj, "Sign in") {
		t.Errorf("subject: want contains 'Sign in', got %q", subj)
	}
	if txt, _ := gotBody["textContent"].(string); !strings.Contains(txt, "https://app.example/magic?t=abc") {
		t.Errorf("textContent missing magic link, got %q", txt)
	}
	if html, _ := gotBody["htmlContent"].(string); !strings.Contains(html, "Sign in") {
		t.Errorf("htmlContent missing 'Sign in', got %q", html)
	}
}

// TestBrevoProvider_HandlesUnauthorized — Brevo returns 401 on bad api-key;
// the provider must surface a non-nil error so callers (magic_link.go etc.)
// can log + retry instead of silently dropping the email.
func TestBrevoProvider_HandlesUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"unauthorized","message":"Key not found"}`))
	}))
	defer srv.Close()

	rewrite := &urlRewriter{base: srv.URL, inner: http.DefaultTransport}
	c := email.New(email.Config{
		Provider:    "brevo",
		BrevoAPIKey: "xkeysib-bogus",
		HTTPClient:  &http.Client{Transport: rewrite},
	})

	err := c.SendMagicLink(context.Background(), "user@example.com", "https://app.example/m?t=x")
	if err == nil {
		t.Fatal("expected non-nil error on 401, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should mention status 401, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "unauthorized") && !strings.Contains(err.Error(), "Key not found") {
		t.Errorf("error should include Brevo response body, got %q", err.Error())
	}
}

// urlRewriter is a tiny http.RoundTripper that swaps the scheme+host of
// every outbound request with the test server's. We use it so the Brevo
// provider keeps targeting api.brevo.com in production while tests redirect
// to httptest.Server.URL without monkey-patching the package constant.
type urlRewriter struct {
	base  string // e.g. "http://127.0.0.1:54321"
	inner http.RoundTripper
}

func (u *urlRewriter) RoundTrip(req *http.Request) (*http.Response, error) {
	// Replace scheme + host with the test server's. Path stays the same so
	// the assertion on "/v3/smtp/email" still works.
	idx := strings.Index(u.base, "://")
	if idx > 0 {
		req.URL.Scheme = u.base[:idx]
		req.URL.Host = strings.TrimPrefix(u.base[idx+3:], "")
	}
	return u.inner.RoundTrip(req)
}
