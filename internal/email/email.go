package email

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/resend/resend-go/v2"
)

// Client wraps the Resend API client.
type Client struct {
	client *resend.Client
	from   string // e.g. "Instant Dev <noreply@instant.dev>"
	noop   bool   // true when apiKey is empty (dev mode)
}

// New creates an email client. Returns a no-op client if apiKey is empty (dev mode).
func New(apiKey string) *Client {
	if apiKey == "" {
		slog.Info("email.client.noop", "reason", "no RESEND_API_KEY set — emails will be logged only")
		return &Client{noop: true, from: "Instant Dev <noreply@instant.dev>"}
	}
	return &Client{
		client: resend.NewClient(apiKey),
		from:   "Instant Dev <noreply@instant.dev>",
	}
}

// send is the internal dispatcher. If noop, it logs and returns nil.
func (c *Client) send(ctx context.Context, to, subject, plainText, htmlBody string) error {
	if c.noop {
		slog.Info("email.skipped",
			"to", to,
			"subject", subject,
		)
		return nil
	}

	params := &resend.SendEmailRequest{
		From:    c.from,
		To:      []string{to},
		Subject: subject,
		Text:    plainText,
		Html:    htmlBody,
	}

	_, err := c.client.Emails.SendWithContext(ctx, params)
	if err != nil {
		slog.Error("email.send_failed",
			"to", to,
			"subject", subject,
			"error", err,
		)
		return fmt.Errorf("email.send: %w", err)
	}
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

// htmlEscape replaces HTML-unsafe characters with their entity equivalents.
func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	return s
}
