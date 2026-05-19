package email_test

import (
	"context"
	"encoding/json"
	"errors"
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

// TestSendDeletionConfirmation_FormatsBody drives a fake Brevo server
// and asserts the deletion-confirm email carries the resource label, the
// TTL in minutes, and the full confirmation link. Wave FIX-I.
func TestSendDeletionConfirmation_FormatsBody(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	rewrite := &urlRewriter{base: srv.URL, inner: http.DefaultTransport}
	c := email.New(email.Config{
		Provider:    "brevo",
		BrevoAPIKey: "xkeysib-test",
		HTTPClient:  &http.Client{Transport: rewrite},
	})

	link := "https://api.instanode.dev/auth/email/confirm-deletion?t=del_abc123"
	if err := c.SendDeletionConfirmation(
		context.Background(),
		"owner@example.com",
		"deployment my-app",
		link,
		15,
	); err != nil {
		t.Fatalf("SendDeletionConfirmation: %v", err)
	}

	subj, _ := gotBody["subject"].(string)
	if !strings.Contains(subj, "Confirm deletion") {
		t.Errorf("subject: want 'Confirm deletion', got %q", subj)
	}
	if !strings.Contains(subj, "deployment my-app") {
		t.Errorf("subject: must name the resource, got %q", subj)
	}
	if !strings.Contains(subj, "15") {
		t.Errorf("subject: must surface the TTL minutes, got %q", subj)
	}
	txt, _ := gotBody["textContent"].(string)
	if !strings.Contains(txt, link) {
		t.Errorf("textContent: must embed the confirmation link, got %q", txt)
	}
	html, _ := gotBody["htmlContent"].(string)
	if !strings.Contains(html, link) {
		t.Errorf("htmlContent: must embed the confirmation link, got %q", html)
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

// ---------------------------------------------------------------------------
// EMAIL-BUGBASH 2026-05-19 regression tests.
// ---------------------------------------------------------------------------

// captureBrevo builds a Brevo-backed client wired to a test server and
// returns the client plus a pointer to the last captured request body. Used
// by the domain-drift / amount / suppression tests below.
func captureBrevo(t *testing.T) (*email.Client, *map[string]any) {
	t.Helper()
	captured := &map[string]any{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		*captured = body
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(srv.Close)
	rewrite := &urlRewriter{base: srv.URL, inner: http.DefaultTransport}
	c := email.New(email.Config{
		Provider:    "brevo",
		BrevoAPIKey: "xkeysib-test",
		HTTPClient:  &http.Client{Transport: rewrite},
	})
	return c, captured
}

// TestNoEmailBodyContainsInstantDev is the EMAIL-BUGBASH C2/F1/F11 domain-drift
// regression guard. It drives every customer-facing api email through a fake
// Brevo server and asserts the subject + textContent + htmlContent never
// contain the bare wrong domain "instant.dev". Fails before the fix because
// SendPaymentFailed and SendTeamInvite hardcoded "instant.dev".
//
// "instanode.dev" legitimately contains "instant.dev" as a substring is NOT
// true ("instanode" != "instant"), so a plain Contains check is safe; but to
// be unambiguous the assertion strips the correct domain first.
func TestNoEmailBodyContainsInstantDev(t *testing.T) {
	next := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	sends := []struct {
		name string
		fn   func(c *email.Client) error
	}{
		{"SendPaymentFailed", func(c *email.Client) error {
			return c.SendPaymentFailed(context.Background(), "u@example.com", 2, &next)
		}},
		{"SendPaymentFailedFinal", func(c *email.Client) error {
			return c.SendPaymentFailed(context.Background(), "u@example.com", 3, nil)
		}},
		{"SendTeamInvite", func(c *email.Client) error {
			return c.SendTeamInvite(context.Background(), "u@example.com", "Acme", "https://api.instanode.dev/i/abc")
		}},
		{"SendPaymentSucceeded", func(c *email.Client) error {
			return c.SendPaymentSucceeded(context.Background(), "u@example.com", email.PaymentReceipt{
				Plan: "Pro", AmountDisplay: "$49.00", Period: "monthly", AmountKnown: true,
			})
		}},
		{"SendMagicLink", func(c *email.Client) error {
			return c.SendMagicLink(context.Background(), "u@example.com", "https://api.instanode.dev/m?t=x")
		}},
		{"SendDeletionConfirmation", func(c *email.Client) error {
			return c.SendDeletionConfirmation(context.Background(), "u@example.com", "deployment x", "https://api.instanode.dev/d?t=x", 15)
		}},
	}
	for _, s := range sends {
		t.Run(s.name, func(t *testing.T) {
			c, captured := captureBrevo(t)
			if err := s.fn(c); err != nil {
				t.Fatalf("%s: %v", s.name, err)
			}
			for _, field := range []string{"subject", "textContent", "htmlContent"} {
				v, _ := (*captured)[field].(string)
				// Strip the correct domain so any remaining "instant.dev"
				// substring is unambiguously the wrong domain.
				stripped := strings.ReplaceAll(v, "instanode.dev", "")
				if strings.Contains(stripped, "instant.dev") {
					t.Errorf("%s.%s contains wrong domain instant.dev:\n%s", s.name, field, v)
				}
			}
		})
	}
}

// TestSendPaymentFailed_UsesCorrectBillingURL pins the C2/F1 CTA fix: the
// payment-failed email must link to instanode.dev/app/billing, never the dead
// instant.dev/billing/checkout path.
func TestSendPaymentFailed_UsesCorrectBillingURL(t *testing.T) {
	c, captured := captureBrevo(t)
	if err := c.SendPaymentFailed(context.Background(), "u@example.com", 1, nil); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"textContent", "htmlContent"} {
		v, _ := (*captured)[field].(string)
		if !strings.Contains(v, "https://instanode.dev/app/billing") {
			t.Errorf("%s missing correct billing URL, got:\n%s", field, v)
		}
		if strings.Contains(v, "/billing/checkout") {
			t.Errorf("%s still references dead /billing/checkout path:\n%s", field, v)
		}
	}
}

// TestSendPaymentFailed_AttemptCountClamped is the C6 regression guard:
// out-of-range attempt counts must never render "attempt 4 of 3" /
// "attempt 0 of 3". The clamp bounds the count into [1, 3].
func TestSendPaymentFailed_AttemptCountClamped(t *testing.T) {
	cases := []struct{ in int }{{-1}, {0}, {4}, {99}}
	for _, tc := range cases {
		c, captured := captureBrevo(t)
		if err := c.SendPaymentFailed(context.Background(), "u@example.com", tc.in, nil); err != nil {
			t.Fatalf("attempt=%d: %v", tc.in, err)
		}
		for _, field := range []string{"textContent", "htmlContent"} {
			v, _ := (*captured)[field].(string)
			for _, bad := range []string{"attempt 0 of", "attempt 4 of", "attempt 99 of", "attempt -1 of", "0 of 3", "4 of 3"} {
				if strings.Contains(v, bad) {
					t.Errorf("attempt=%d: %s renders unclamped %q:\n%s", tc.in, field, bad, v)
				}
			}
		}
	}
}

// TestSendPaymentFailed_NoBlankLinesInPlainText is the C7 guard: when no
// retry date and not final, the text/plain body must not contain a run of
// blank lines from empty interpolated %s.
func TestSendPaymentFailed_NoBlankLinesInPlainText(t *testing.T) {
	c, captured := captureBrevo(t)
	// attempt 2, no nextAttemptDate, not final → both retryLine and
	// urgencyLine are empty.
	if err := c.SendPaymentFailed(context.Background(), "u@example.com", 2, nil); err != nil {
		t.Fatal(err)
	}
	txt, _ := (*captured)["textContent"].(string)
	if strings.Contains(txt, "\n\n\n") {
		t.Errorf("plain text has a run of blank lines (C7):\n%q", txt)
	}
}

// TestSendPaymentSucceeded_UnknownAmount is the C8 guard: when AmountKnown is
// false the receipt must NOT print a definite "Amount: <value>" — it renders
// the parenthetical pointer instead.
func TestSendPaymentSucceeded_UnknownAmount(t *testing.T) {
	c, captured := captureBrevo(t)
	err := c.SendPaymentSucceeded(context.Background(), "u@example.com", email.PaymentReceipt{
		Plan: "Pro", AmountDisplay: "see your billing dashboard", Period: "monthly", AmountKnown: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	txt, _ := (*captured)["textContent"].(string)
	if !strings.Contains(txt, "(see your billing dashboard for the exact amount)") {
		t.Errorf("unknown-amount receipt missing parenthetical pointer:\n%s", txt)
	}
	// Known-amount path still prints the figure.
	c2, captured2 := captureBrevo(t)
	if err := c2.SendPaymentSucceeded(context.Background(), "u@example.com", email.PaymentReceipt{
		Plan: "Pro", AmountDisplay: "$49.00", Period: "monthly", AmountKnown: true,
	}); err != nil {
		t.Fatal(err)
	}
	txt2, _ := (*captured2)["textContent"].(string)
	if !strings.Contains(txt2, "$49.00") {
		t.Errorf("known-amount receipt missing the amount:\n%s", txt2)
	}
}

// fakeSuppression is a test SuppressionChecker. suppressed addresses return
// true; errFor addresses return an error (to exercise the fail-open path).
type fakeSuppression struct {
	suppressed map[string]bool
	errFor     map[string]bool
}

func (f *fakeSuppression) IsSuppressed(_ context.Context, addr string) (bool, error) {
	if f.errFor[addr] {
		return false, errors.New("fake db error")
	}
	return f.suppressed[addr], nil
}

// TestSuppressedAddressIsNotSent is the C3 regression guard: a client with a
// SuppressionChecker must NOT POST to Brevo for a suppressed recipient. The
// fake Brevo server records whether it was hit; for a suppressed address it
// must stay untouched, and send() must still return nil (a skip is success).
func TestSuppressedAddressIsNotSent(t *testing.T) {
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	rewrite := &urlRewriter{base: srv.URL, inner: http.DefaultTransport}
	c := email.New(email.Config{
		Provider: "brevo", BrevoAPIKey: "xkeysib-test",
		HTTPClient: &http.Client{Transport: rewrite},
	}).WithSuppressionChecker(&fakeSuppression{
		suppressed: map[string]bool{"bounced@example.com": true},
	})

	// Suppressed recipient — must NOT hit Brevo, must return nil.
	if err := c.SendMagicLink(context.Background(), "bounced@example.com", "https://x/m?t=1"); err != nil {
		t.Fatalf("send to suppressed address should return nil, got %v", err)
	}
	if hit {
		t.Fatal("C3: a suppressed address was still POSTed to Brevo")
	}

	// Non-suppressed recipient — must hit Brevo.
	if err := c.SendMagicLink(context.Background(), "ok@example.com", "https://x/m?t=2"); err != nil {
		t.Fatalf("send to ok address: %v", err)
	}
	if !hit {
		t.Fatal("non-suppressed address should have been sent")
	}
}

// TestSuppressionCheck_FailsOpen verifies that a SuppressionChecker error
// does NOT block the send — a Postgres blip must never swallow a sign-in
// link (C3 fail-open contract).
func TestSuppressionCheck_FailsOpen(t *testing.T) {
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	rewrite := &urlRewriter{base: srv.URL, inner: http.DefaultTransport}
	c := email.New(email.Config{
		Provider: "brevo", BrevoAPIKey: "xkeysib-test",
		HTTPClient: &http.Client{Transport: rewrite},
	}).WithSuppressionChecker(&fakeSuppression{
		errFor: map[string]bool{"u@example.com": true},
	})
	if err := c.SendMagicLink(context.Background(), "u@example.com", "https://x/m?t=1"); err != nil {
		t.Fatalf("fail-open: send should still succeed on suppression error, got %v", err)
	}
	if !hit {
		t.Fatal("fail-open: send should have proceeded to Brevo despite the suppression error")
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
