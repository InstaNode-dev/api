package email

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/resend/resend-go/v2"
)

// ProviderName identifies a backend implementation. Stable strings; safe to use
// as metric/log labels.
type ProviderName string

const (
	ProviderBrevo  ProviderName = "brevo"
	ProviderResend ProviderName = "resend"
	ProviderNoop   ProviderName = "noop"
)

// resendSentinelUnset is the placeholder value live deployments use to indicate
// "Resend is not configured". Treating it as "unset" prevents the magic-link
// flow from breaking when an operator forgets to fill in the secret.
const resendSentinelUnset = "CHANGE_ME"

// brevoEndpoint is the Brevo Transactional Email API. It accepts a JSON body
// and returns 201 on success.
const brevoEndpoint = "https://api.brevo.com/v3/smtp/email"

// defaultFromName / defaultFromAddress are the fallbacks used when the
// EMAIL_FROM_NAME / EMAIL_FROM_ADDRESS env vars are not configured. They match
// the verified sender currently registered with Brevo for instanode.dev.
const (
	defaultFromName    = "InstaNode"
	defaultFromAddress = "noreply@instanode.dev"
)

// Config carries the email-backend configuration. All fields are optional;
// New() resolves sensible defaults so calling New(Config{}) yields a noop
// client that never blocks development.
type Config struct {
	// Provider, when non-empty, forces a specific backend regardless of which
	// API keys are present. Accepted values: "brevo", "resend", "noop".
	// Anything else falls back to auto-detection (Brevo > Resend > Noop).
	Provider string

	// BrevoAPIKey is the value of BREVO_API_KEY. When non-empty and Provider
	// is unset or "brevo", the Brevo backend is used.
	BrevoAPIKey string

	// ResendAPIKey is the value of RESEND_API_KEY. Treated as unset when empty
	// or equal to "CHANGE_ME" (the placeholder in infra/k8s/secrets.yaml that
	// caused the live magic-link outage on 2026-05-14).
	ResendAPIKey string

	// FromName / FromAddress override the verified-sender pair. Empty values
	// fall back to "InstaNode" / "noreply@instanode.dev".
	FromName    string
	FromAddress string

	// HTTPClient, when non-nil, replaces the default net/http.Client used by
	// the Brevo backend. Set in tests to swap in a httptest.Server.
	HTTPClient *http.Client
}

// provider is the internal seam: one method, no provider-specific types leak
// out. All public Send* helpers on Client funnel through provider.Send.
type provider interface {
	Send(ctx context.Context, to, subject, plainText, htmlBody string) error
	Name() ProviderName
}

// Client is the public façade. Handlers depend on *Client; they never see the
// provider type, so swapping backends does not ripple into call sites.
type Client struct {
	provider provider
	fromName string
	fromAddr string
}

// New constructs an email Client. Provider selection precedence:
//
//  1. Config.Provider, if explicitly set to "brevo" | "resend" | "noop".
//  2. BREVO_API_KEY set and non-empty → brevo.
//  3. RESEND_API_KEY set, non-empty, and not equal to "CHANGE_ME" → resend.
//  4. Otherwise → noop (logs, never sends).
//
// The chosen provider is logged once at construction via slog.Info under the
// "email.client.init" event so operators can confirm which backend the api
// pod boots with.
func New(cfg Config) *Client {
	fromName := cfg.FromName
	if fromName == "" {
		fromName = defaultFromName
	}
	fromAddr := cfg.FromAddress
	if fromAddr == "" {
		fromAddr = defaultFromAddress
	}

	c := &Client{fromName: fromName, fromAddr: fromAddr}

	chosen := resolveProvider(cfg)
	switch chosen {
	case ProviderBrevo:
		httpClient := cfg.HTTPClient
		if httpClient == nil {
			httpClient = &http.Client{Timeout: 10 * time.Second}
		}
		c.provider = &brevoProvider{
			apiKey:   cfg.BrevoAPIKey,
			http:     httpClient,
			fromName: fromName,
			fromAddr: fromAddr,
		}
	case ProviderResend:
		c.provider = &resendProvider{
			client: resend.NewClient(cfg.ResendAPIKey),
			from:   fmt.Sprintf("%s <%s>", fromName, fromAddr),
		}
	default:
		c.provider = &noopProvider{}
	}

	slog.Info("email.client.init",
		"provider", string(chosen),
		"from_name", fromName,
		"from_address", fromAddr,
	)
	return c
}

// NewNoop returns a Client backed by the noop provider. Convenience helper
// for tests and bootstrap paths where outbound email is undesired.
func NewNoop() *Client {
	return New(Config{Provider: string(ProviderNoop)})
}

// resolveProvider implements the precedence rules documented on New.
func resolveProvider(cfg Config) ProviderName {
	switch strings.ToLower(strings.TrimSpace(cfg.Provider)) {
	case string(ProviderBrevo):
		return ProviderBrevo
	case string(ProviderResend):
		return ProviderResend
	case string(ProviderNoop):
		return ProviderNoop
	}
	if strings.TrimSpace(cfg.BrevoAPIKey) != "" {
		return ProviderBrevo
	}
	if rk := strings.TrimSpace(cfg.ResendAPIKey); rk != "" && rk != resendSentinelUnset {
		return ProviderResend
	}
	return ProviderNoop
}

// send is the internal dispatch wrapper. Every public Send* method funnels
// through here so logging + provider routing stay in one place.
func (c *Client) send(ctx context.Context, to, subject, plainText, htmlBody string) error {
	if c.provider == nil {
		// Defensive: a zero-value Client (never returned by New) would
		// otherwise panic. Treat it as noop.
		slog.Warn("email.client.no_provider", "to", to, "subject", subject)
		return nil
	}
	return c.provider.Send(ctx, to, subject, plainText, htmlBody)
}

// ProviderName returns the active backend identifier. Useful for /healthz
// payloads or operator-facing diagnostics that confirm which backend the
// running pod chose.
func (c *Client) ProviderName() ProviderName {
	if c.provider == nil {
		return ProviderNoop
	}
	return c.provider.Name()
}

// ---------------------------------------------------------------------------
// resendProvider — wraps github.com/resend/resend-go/v2 (existing behaviour).
// ---------------------------------------------------------------------------

type resendProvider struct {
	client *resend.Client
	from   string
}

func (p *resendProvider) Name() ProviderName { return ProviderResend }

func (p *resendProvider) Send(ctx context.Context, to, subject, plainText, htmlBody string) error {
	params := &resend.SendEmailRequest{
		From:    p.from,
		To:      []string{to},
		Subject: subject,
		Text:    plainText,
		Html:    htmlBody,
	}
	if _, err := p.client.Emails.SendWithContext(ctx, params); err != nil {
		slog.Error("email.send_failed",
			"provider", string(ProviderResend),
			"to", to,
			"subject", subject,
			"error", err,
		)
		return fmt.Errorf("email.send: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// brevoProvider — POSTs Transactional Email API; no SDK dependency added.
// ---------------------------------------------------------------------------

type brevoProvider struct {
	apiKey   string
	http     *http.Client
	fromName string
	fromAddr string
}

func (p *brevoProvider) Name() ProviderName { return ProviderBrevo }

// brevoSender / brevoRecipient match the JSON shape documented at
// https://developers.brevo.com/reference/sendtransacemail. Both are
// internal — they never leak past Send.
type brevoSender struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email"`
}

type brevoRecipient struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

type brevoSendRequest struct {
	Sender      brevoSender      `json:"sender"`
	To          []brevoRecipient `json:"to"`
	Subject     string           `json:"subject"`
	TextContent string           `json:"textContent,omitempty"`
	HTMLContent string           `json:"htmlContent,omitempty"`
}

func (p *brevoProvider) Send(ctx context.Context, to, subject, plainText, htmlBody string) error {
	if strings.TrimSpace(to) == "" {
		return fmt.Errorf("email.brevo: empty recipient")
	}

	body := brevoSendRequest{
		Sender:      brevoSender{Name: p.fromName, Email: p.fromAddr},
		To:          []brevoRecipient{{Email: to}},
		Subject:     subject,
		TextContent: plainText,
		HTMLContent: htmlBody,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("email.brevo.marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, brevoEndpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("email.brevo.new_request: %w", err)
	}
	req.Header.Set("api-key", p.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := p.http.Do(req)
	if err != nil {
		slog.Error("email.send_failed",
			"provider", string(ProviderBrevo),
			"to", to,
			"subject", subject,
			"error", err,
		)
		return fmt.Errorf("email.brevo.do: %w", err)
	}
	defer resp.Body.Close()

	// Brevo: 201 Created on success. 400 surfaces sender-not-verified, 401
	// is bad api-key, 4xx generally are payload problems. Surface the
	// response body so operators see the exact reason.
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusAccepted {
		return nil
	}

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	slog.Error("email.send_failed",
		"provider", string(ProviderBrevo),
		"to", to,
		"subject", subject,
		"status", resp.StatusCode,
		"body", string(respBody),
	)
	return fmt.Errorf("email.brevo: unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
}

// ---------------------------------------------------------------------------
// noopProvider — logs and returns nil. Matches the historical empty-key path.
// ---------------------------------------------------------------------------

type noopProvider struct{}

func (p *noopProvider) Name() ProviderName { return ProviderNoop }

func (p *noopProvider) Send(_ context.Context, to, subject, _, _ string) error {
	slog.Info("email.skipped",
		"provider", string(ProviderNoop),
		"to", to,
		"subject", subject,
	)
	return nil
}

// SendTrialStarted / SendTrialWarning / SendTrialExpired were removed on
// 2026-05-14 per policy memory project_no_trial_pay_day_one.md. The platform
// has no trial period; hobby/pro/team are paid from day one. Anonymous (24h
// TTL) is the only free tier and is not eligible for these emails.

// SendWeeklyDigest sends the Monday morning digest email.
func (c *Client) SendWeeklyDigest(ctx context.Context, to string) error {
	subject := "Your instant.dev weekly summary"

	plain := `Your instant.dev weekly summary

Here is a quick snapshot of your account activity this week.

View your dashboard: https://instant.dev/dashboard

`
	plain += fmt.Sprintf("Unsubscribe: https://instant.dev/unsubscribe?token=%s\n", to)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:24px;color:#111;">
  <h2>Your instant.dev weekly summary</h2>
  <p>Here is a quick snapshot of your account activity this week.</p>
  <p style="margin-top:32px;">
    <a href="https://instant.dev/dashboard"
       style="background:#111;color:#fff;padding:12px 24px;text-decoration:none;border-radius:6px;font-weight:bold;">
      View dashboard &rarr;
    </a>
  </p>
  <p style="margin-top:40px;color:#888;font-size:12px;">
    <a href="https://instant.dev/unsubscribe?token=%s" style="color:#888;">Unsubscribe</a>
  </p>
</body>
</html>`, to)

	return c.send(ctx, to, subject, plain, html)
}

// SendPaymentFailed sends a payment failure notification email.
// attemptCount is the number of attempts Razorpay has made (1–3).
// nextAttemptDate is when Razorpay will retry; nil means no further retry is scheduled.
func (c *Client) SendPaymentFailed(ctx context.Context, to string, attemptCount int, nextAttemptDate *time.Time) error {
	subject := "Payment failed for your instant.dev subscription"

	isFinal := attemptCount >= 3

	retryLine := ""
	retryHTML := ""
	if nextAttemptDate != nil {
		retryDate := nextAttemptDate.UTC().Format("January 2, 2006")
		retryLine = fmt.Sprintf("Razorpay will automatically retry your payment on %s.", retryDate)
		retryHTML = fmt.Sprintf("<p>Razorpay will automatically retry your payment on <strong>%s</strong>.</p>", retryDate)
	}

	urgencyLine := ""
	urgencyHTML := ""
	if isFinal {
		urgencyLine = "This is the final retry. Your subscription will be cancelled if payment fails again."
		urgencyHTML = `<p style="color:#c0392b;font-weight:bold;">This is the final retry. Your subscription will be cancelled if payment fails again.</p>`
	}

	plain := fmt.Sprintf(`Your payment for instant.dev failed (attempt %d of 3).

%s
%s
Update your payment method to keep your subscription active:
https://instant.dev/billing/checkout

— The instant.dev team
`, attemptCount, retryLine, urgencyLine)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:24px;color:#111;">
  <h2>Payment failed for your instant.dev subscription</h2>
  <p>Your payment failed (attempt <strong>%d of 3</strong>).</p>
  %s
  %s
  <p>Update your payment method to keep your subscription active.</p>
  <p style="margin-top:32px;">
    <a href="https://instant.dev/billing/checkout"
       style="background:#111;color:#fff;padding:12px 24px;text-decoration:none;border-radius:6px;font-weight:bold;">
      Update payment method &rarr;
    </a>
  </p>
  <p style="margin-top:40px;color:#666;font-size:13px;">— The instant.dev team</p>
</body>
</html>`, attemptCount, retryHTML, urgencyHTML)

	return c.send(ctx, to, subject, plain, html)
}

// PaymentReceipt carries the fields rendered into the payment-success
// (receipt) email. All amounts are display-ready strings — the caller
// formats currency + minor units so this package stays currency-agnostic.
//
// Plan is the canonical tier label shown to the customer ("Pro", "Hobby").
// AmountDisplay is the charged amount already formatted with its currency
// symbol/code (e.g. "₹4,900.00" or "$49.00"). Period is a human-readable
// billing cycle ("monthly" / "yearly"). IsRenewal toggles the copy between
// a first-charge "thanks for upgrading" receipt and a recurring
// "your subscription renewed" receipt — both are still a receipt and both
// always send (renewals are NOT silent: F4).
type PaymentReceipt struct {
	Plan          string
	AmountDisplay string
	Period        string
	IsRenewal     bool
}

// SendPaymentSucceeded sends the customer's payment receipt — fired on every
// successful Razorpay subscription charge (first upgrade AND every monthly
// renewal). This is the artifact that confirms money left the customer's
// account; before it existed (audit finding F4) a paying customer could get
// zero communication that they were charged.
//
// Go-rendered in full (CLAUDE.md rule 70 — all email kinds Go-rendered, no
// Brevo template dependency) so the receipt copy can never silently break
// on a template-id drift.
func (c *Client) SendPaymentSucceeded(ctx context.Context, to string, receipt PaymentReceipt) error {
	headline := "Payment received — your instanode.dev plan is active"
	leadPlain := fmt.Sprintf("Thank you for upgrading to %s. Your payment was successful and your plan is now active.", receipt.Plan)
	leadHTML := fmt.Sprintf("Thank you for upgrading to <strong>%s</strong>. Your payment was successful and your plan is now active.", htmlEscape(receipt.Plan))
	if receipt.IsRenewal {
		headline = "Payment received — your instanode.dev subscription renewed"
		leadPlain = fmt.Sprintf("Your %s subscription renewed successfully. Thanks for staying with instanode.dev.", receipt.Plan)
		leadHTML = fmt.Sprintf("Your <strong>%s</strong> subscription renewed successfully. Thanks for staying with instanode.dev.", htmlEscape(receipt.Plan))
	}
	subject := headline

	plain := fmt.Sprintf(`%s

%s

Receipt
  Plan:    %s
  Amount:  %s
  Billing: %s

View your billing details: https://instanode.dev/app/billing

Need help? Reply to this email or contact support@instanode.dev.

— The instanode.dev team
`, headline, leadPlain, receipt.Plan, receipt.AmountDisplay, receipt.Period)

	htmlBody := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:24px;color:#111;">
  <h2>%s</h2>
  <p>%s</p>
  <table style="margin-top:16px;border-collapse:collapse;background:#f5f5f5;border-radius:6px;width:100%%;">
    <tr><td style="padding:10px 16px;color:#666;">Plan</td><td style="padding:10px 16px;font-weight:bold;">%s</td></tr>
    <tr><td style="padding:10px 16px;color:#666;">Amount</td><td style="padding:10px 16px;font-weight:bold;">%s</td></tr>
    <tr><td style="padding:10px 16px;color:#666;">Billing</td><td style="padding:10px 16px;font-weight:bold;">%s</td></tr>
  </table>
  <p style="margin-top:32px;">
    <a href="https://instanode.dev/app/billing"
       style="background:#111;color:#fff;padding:12px 24px;text-decoration:none;border-radius:6px;font-weight:bold;">
      View billing details &rarr;
    </a>
  </p>
  <p style="margin-top:24px;color:#666;font-size:13px;">
    Need help? Reply to this email or contact
    <a href="mailto:support@instanode.dev" style="color:#444;">support@instanode.dev</a>.
  </p>
  <p style="margin-top:40px;color:#666;font-size:13px;">— The instanode.dev team</p>
</body>
</html>`, headline, leadHTML, htmlEscape(receipt.Plan), htmlEscape(receipt.AmountDisplay), htmlEscape(receipt.Period))

	return c.send(ctx, to, subject, plain, htmlBody)
}

// SendMagicLink emails a one-click sign-in link to the user. The link MUST
// already point at the API's /auth/email/callback endpoint — this function
// does not construct it.
//
// The 15-minute expiry and single-use semantics are enforced by the
// magic_links table; this email body just communicates them to the user.
func (c *Client) SendMagicLink(ctx context.Context, toEmail, link string) error {
	subject := "Sign in to instanode (expires in 15 min)"

	plain := fmt.Sprintf(`Sign in to instanode.dev:

%s

This link expires in 15 minutes and can only be used once. If you didn't
request this email, you can safely ignore it.

— The instanode.dev team
`, link)

	safeLink := htmlEscape(link)
	htmlBody := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:24px;color:#111;">
  <h2>Sign in to instanode.dev</h2>
  <p>Click the button below to sign in. This link expires in <strong>15 minutes</strong> and can only be used once.</p>
  <p style="margin-top:32px;">
    <a href="%s"
       style="background:#111;color:#fff;padding:12px 24px;text-decoration:none;border-radius:6px;font-weight:bold;">
      Sign in &rarr;
    </a>
  </p>
  <p style="margin-top:24px;color:#666;font-size:13px;">
    If the button doesn't work, copy this URL into your browser:<br>
    <span style="color:#444;word-break:break-all;">%s</span>
  </p>
  <p style="margin-top:24px;color:#666;font-size:13px;">
    If you didn't request this email, you can safely ignore it.
  </p>
  <p style="margin-top:40px;color:#666;font-size:13px;">— The instanode.dev team</p>
</body>
</html>`, safeLink, safeLink)

	return c.send(ctx, toEmail, subject, plain, htmlBody)
}

// SendTeamInvite emails an invitation to join a team on instant.dev.
func (c *Client) SendTeamInvite(ctx context.Context, toEmail, teamName, acceptURL string) error {
	subject := "You've been invited to an instant.dev team"
	plain := fmt.Sprintf(`Hi,

You've been invited to join the team %q on instant.dev.

Open this link while signed in with %s to accept:
%s

— The instant.dev team
`, teamName, toEmail, acceptURL)

	safeTeam := htmlEscape(teamName)
	safeURL := htmlEscape(acceptURL)
	htmlBody := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:24px;color:#111;">
  <h2>Team invitation</h2>
  <p>You've been invited to join <strong>%s</strong> on instant.dev.</p>
  <p>Sign in with <strong>%s</strong>, then open:</p>
  <p style="margin-top:16px;"><a href="%s">Accept invitation</a></p>
  <p style="margin-top:40px;color:#666;font-size:13px;">— The instant.dev team</p>
</body>
</html>`, safeTeam, htmlEscape(toEmail), safeURL)

	return c.send(ctx, toEmail, subject, plain, htmlBody)
}

// SendDeletionConfirmation emails the user a one-click link to confirm
// the destruction of a deploy or stack. The link MUST already be a
// fully-formed URL pointing at /auth/email/confirm-deletion?t=<token>
// (the API redirects through to the dashboard's /app/confirm-deletion
// surface). This function does not construct the URL — that's the
// caller's job so a Brevo template change can't accidentally rewrite
// the path.
//
// resourceLabel is what the user sees ("deployment my-app",
// "stack my-stack/production"). ttlMinutes is the expiry window the
// email surfaces ("expires in 15 minutes"). Both are formatted into the
// subject + body so a user with multiple pending deletes can tell which
// resource the email refers to without opening the link.
//
// Wave FIX-I — two-step deletion. The flow is intentionally human-only:
// the agent can request deletion but cannot confirm it.
func (c *Client) SendDeletionConfirmation(
	ctx context.Context,
	toEmail, resourceLabel, link string,
	ttlMinutes int,
) error {
	subject := fmt.Sprintf("Confirm deletion of %s on instanode.dev (expires in %d min)", resourceLabel, ttlMinutes)

	plain := fmt.Sprintf(`You (or your AI agent) requested deletion of:

  %s

This link expires in %d minutes and can only be used once. Click to
permanently destroy the resource and free its slot on your plan:

%s

If you did NOT request this, you can safely ignore the email — the
resource stays active and the request expires automatically. Or cancel
it from your dashboard at https://instanode.dev/app.

— The instanode.dev team
`, resourceLabel, ttlMinutes, link)

	safeLink := htmlEscape(link)
	safeLabel := htmlEscape(resourceLabel)
	htmlBody := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:24px;color:#111;">
  <h2>Confirm deletion on instanode.dev</h2>
  <p>You (or your AI agent) requested deletion of:</p>
  <p style="background:#f5f5f5;padding:12px 16px;border-radius:6px;font-family:monospace;"><strong>%s</strong></p>
  <p>This link expires in <strong>%d minutes</strong> and can only be used once. Click to permanently destroy the resource and free its slot on your plan.</p>
  <p style="margin-top:32px;">
    <a href="%s"
       style="background:#c0392b;color:#fff;padding:12px 24px;text-decoration:none;border-radius:6px;font-weight:bold;">
      Confirm deletion &rarr;
    </a>
  </p>
  <p style="margin-top:24px;color:#666;font-size:13px;">
    If the button doesn't work, copy this URL into your browser:<br>
    <span style="color:#444;word-break:break-all;">%s</span>
  </p>
  <p style="margin-top:24px;color:#666;font-size:13px;">
    If you did NOT request this, you can safely ignore the email — the
    resource stays active and the request expires automatically. Or
    cancel from <a href="https://instanode.dev/app" style="color:#444;">your dashboard</a>.
  </p>
  <p style="margin-top:40px;color:#666;font-size:13px;">— The instanode.dev team</p>
</body>
</html>`, safeLabel, ttlMinutes, safeLink, safeLink)

	return c.send(ctx, toEmail, subject, plain, htmlBody)
}

// htmlEscape replaces HTML-unsafe characters with their entity equivalents.
func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	return s
}
