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
//
// idempotencyKey, when non-empty, is forwarded to the upstream provider so a
// network-glitch retry collapses to one delivered email (P0-1
// CIRCUIT-RETRY-AUDIT-2026-05-20). Brevo: `X-Mailin-Custom` header. Resend:
// `idempotency_key` field on SendWithOptions. The empty-string default
// preserves the historical no-key behaviour for backwards-compatible call
// sites that don't yet pass a key.
type provider interface {
	Send(ctx context.Context, to, subject, plainText, htmlBody, idempotencyKey string) error
	Name() ProviderName
}

// SuppressionChecker reports whether an address has a recorded suppression
// (hard bounce / unsubscribe / spam complaint). The api's synchronous email
// sends (magic link, receipt, dunning, invite, deletion-confirm) consult it
// before every send so api-originated mail respects the email_events
// suppression table that migration 025 exists to serve (EMAIL-BUGBASH C3).
//
// Implementations MUST fail open: a (false, err) return on a DB error means
// "could not determine — send anyway", because a Postgres blip must never
// silently swallow a transactional email like a sign-in link.
//
// models.NewSuppressionChecker provides the production DB-backed
// implementation; tests pass a fake or leave it nil (nil = no check).
type SuppressionChecker interface {
	IsSuppressed(ctx context.Context, emailAddr string) (bool, error)
}

// SendLedger is the idempotency ledger consulted by every keyed
// transactional send (P0-1 CIRCUIT-RETRY-AUDIT-2026-05-20). For an
// idempotency-keyed send, the email Client probes Sent BEFORE invoking the
// upstream provider; if Sent returns true, the call is skipped (treated as a
// success — the previous attempt got through). After a successful provider
// 2xx, MarkSent records the key so a subsequent retry with the SAME key is
// a no-op.
//
// The shape is intentionally narrow — just probe + mark — so the only
// production implementation (models.EmailDedupLedger, backed by the
// `email_send_dedup` table from migration 056) is a thin SQL wrapper. The
// ledger is OPTIONAL; a Client without one falls back to the historical
// always-send behaviour, which is the right default for callers that
// haven't yet adopted idempotency keys.
//
// Implementations MUST fail open on DB errors: (false, err) from Sent means
// "could not determine, send anyway" and a MarkSent error is logged-and-
// swallowed by the caller. Better one rare duplicate during a Postgres blip
// than a missed receipt or deletion-confirm.
type SendLedger interface {
	// Sent reports whether key has already been recorded as sent. fail-open
	// contract: (false, err) on DB trouble.
	Sent(ctx context.Context, key string) (bool, error)
	// MarkSent records key as sent for emailKind. Returning a non-nil err
	// is allowed; the caller logs and swallows it — the upstream provider
	// already 2xx'd, the email is in the customer's inbox, a missing
	// ledger row is at most one duplicate on the next retry.
	MarkSent(ctx context.Context, key, emailKind string) error
}

// Client is the public façade. Handlers depend on *Client; they never see the
// provider type, so swapping backends does not ripple into call sites.
type Client struct {
	provider    provider
	fromName    string
	fromAddr    string
	suppression SuppressionChecker
	ledger      SendLedger // P0-1 idempotency ledger; nil = no ledger.
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

// WithSuppressionChecker attaches a SuppressionChecker so every subsequent
// send consults the email_events suppression table first (EMAIL-BUGBASH C3).
// Returns the same *Client for fluent wiring in main.go. Passing nil clears
// the checker (the no-check default). Tests that want suppression coverage
// inject a fake here.
func (c *Client) WithSuppressionChecker(s SuppressionChecker) *Client {
	c.suppression = s
	return c
}

// WithSendLedger attaches a SendLedger so any keyed Send* call (the
// *WithKey variants) is gated by a ledger probe and recorded after a
// successful provider 2xx (P0-1 CIRCUIT-RETRY-AUDIT-2026-05-20). nil
// clears the ledger (the historical always-send default). Calls that
// pass an empty idempotency key bypass the ledger entirely — only keyed
// calls are gated, so the change is backwards-compatible.
func (c *Client) WithSendLedger(l SendLedger) *Client {
	c.ledger = l
	return c
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
// through here so logging, suppression checks, and provider routing stay in
// one place.
//
// EMAIL-BUGBASH C3: before dispatching, the recipient is checked against the
// suppression table. A suppressed address (hard bounce / unsubscribe / spam
// complaint) is skipped and the send returns nil — a skipped send is a
// success from the caller's view, not an error to retry. The check is
// fail-open: a DB error during the lookup logs and proceeds with the send,
// because a Postgres blip must never swallow a transactional email.
func (c *Client) send(ctx context.Context, to, subject, plainText, htmlBody string) error {
	return c.sendWithKey(ctx, to, subject, plainText, htmlBody, "", "")
}

// sendWithKey is the keyed variant of send. When idempotencyKey is non-empty
// the call is gated by the SendLedger (P0-1 CIRCUIT-RETRY-AUDIT-2026-05-20):
//
//  1. Probe ledger.Sent(idempotencyKey) — if true, skip (return nil).
//  2. Forward idempotencyKey to the upstream provider (Brevo
//     `X-Mailin-Custom`, Resend `idempotency_key`) so the provider's own
//     dedup can collapse the request.
//  3. On a successful provider call, ledger.MarkSent(idempotencyKey, kind).
//
// An empty idempotencyKey OR a nil ledger preserves the historical
// always-send behaviour — callers that don't pass a key are unaffected by
// this code path.
//
// Fail-open contract: ledger.Sent errors are logged and the send proceeds
// (better one rare duplicate than a missed deletion-confirm during a
// Postgres blip). MarkSent errors are logged and swallowed (the provider
// already 2xx'd, the email is in the inbox).
func (c *Client) sendWithKey(ctx context.Context, to, subject, plainText, htmlBody, idempotencyKey, emailKind string) error {
	if c.provider == nil {
		// Defensive: a zero-value Client (never returned by New) would
		// otherwise panic. Treat it as noop.
		slog.Warn("email.client.no_provider", "to", maskEmail(to), "subject", subject)
		return nil
	}

	if c.suppression != nil && strings.TrimSpace(to) != "" {
		suppressed, err := c.suppression.IsSuppressed(ctx, to)
		if err != nil {
			// Fail open — log and send anyway. A suppression-lookup failure
			// must never block a sign-in link or a payment receipt.
			//
			// P2 (CIRCUIT-RETRY-AUDIT-2026-05-20): emit the fail-open
			// metric so a DB outage that disables suppression for the
			// duration of the brownout is alertable. Sender-reputation
			// cost is uncapped without this signal.
			recordSuppressionFailOpen()
			slog.Warn("email.suppression.check_failed",
				"to", maskEmail(to), "subject", subject, "error", err)
		} else if suppressed {
			slog.Info("email.suppressed",
				"to", maskEmail(to), "subject", subject,
				"reason", "recipient has a hard-bounce/unsubscribe/spam-complaint suppression row")
			return nil
		}
	}

	// P0-1 idempotency-ledger probe. Only consulted when a key is present
	// AND a ledger was configured — keyless calls preserve historical
	// always-send behaviour.
	if idempotencyKey != "" && c.ledger != nil {
		sent, err := c.ledger.Sent(ctx, idempotencyKey)
		if err != nil {
			// P2: ledger-probe fail-open metric (same observability
			// rationale as suppression — make a Postgres brownout
			// alertable instead of silent).
			recordLedgerProbeFailOpen()
			slog.Warn("email.ledger.probe_failed_open",
				"to", maskEmail(to), "subject", subject,
				"key", idempotencyKey, "error", err)
		} else if sent {
			slog.Info("email.ledger.deduped",
				"to", maskEmail(to), "subject", subject,
				"key", idempotencyKey,
				"reason", "previous send already 2xx'd and recorded in email_send_dedup")
			return nil
		}
	}

	if err := c.provider.Send(ctx, to, subject, plainText, htmlBody, idempotencyKey); err != nil {
		return err
	}

	// P0-1 post-send mark. Best-effort: a MarkSent error here is logged
	// and swallowed (the email already delivered; a missing ledger row
	// is at most one duplicate on the next retry).
	if idempotencyKey != "" && c.ledger != nil {
		if err := c.ledger.MarkSent(ctx, idempotencyKey, emailKind); err != nil {
			slog.Warn("email.ledger.mark_sent_failed",
				"to", maskEmail(to), "subject", subject,
				"key", idempotencyKey, "kind", emailKind, "error", err)
		}
	}
	return nil
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

func (p *resendProvider) Send(ctx context.Context, to, subject, plainText, htmlBody, idempotencyKey string) error {
	params := &resend.SendEmailRequest{
		From:    p.from,
		To:      []string{to},
		Subject: subject,
		Text:    plainText,
		Html:    htmlBody,
	}
	// P0-1: Resend SDK exposes idempotency on SendWithOptions; route
	// keyed sends there so a network-glitch retry collapses to one
	// delivered email. Keyless sends keep the existing SendWithContext
	// path — no behaviour change for callers that don't pass a key.
	var err error
	if idempotencyKey != "" {
		_, err = p.client.Emails.SendWithOptions(ctx, params, &resend.SendEmailOptions{
			IdempotencyKey: idempotencyKey,
		})
	} else {
		_, err = p.client.Emails.SendWithContext(ctx, params)
	}
	if err != nil {
		slog.Error("email.send_failed",
			"provider", string(ProviderResend),
			"to", maskEmail(to),
			"subject", subject,
			"idempotency_key_present", idempotencyKey != "",
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

func (p *brevoProvider) Send(ctx context.Context, to, subject, plainText, htmlBody, idempotencyKey string) error {
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
	// P0-1: Brevo supports `X-Mailin-Custom` as an arbitrary per-send tag
	// surfaced on every webhook event for that send. Used by the worker
	// forwarder for dedup; the api uses it here so a network-glitch
	// retry (caller perceives 5xx, retries with the same key) reaches
	// Brevo's own dedup. Keyless sends omit the header.
	if idempotencyKey != "" {
		req.Header.Set("X-Mailin-Custom", idempotencyKey)
		// Brevo also accepts a stricter `Idempotency-Key` header on some
		// preview endpoints — we set both so a future Brevo policy change
		// that prefers the stricter header is still honoured.
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}

	resp, err := p.http.Do(req)
	if err != nil {
		slog.Error("email.send_failed",
			"provider", string(ProviderBrevo),
			"to", maskEmail(to),
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
		"to", maskEmail(to),
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

func (p *noopProvider) Send(_ context.Context, to, subject, _, _, idempotencyKey string) error {
	// EMAIL-BUGBASH L1: DEBUG, not INFO — the noop provider runs on every
	// non-prod env and a per-send INFO line is log spam. The recipient is
	// masked regardless of level so a plaintext address never reaches logs.
	slog.Debug("email.skipped",
		"provider", string(ProviderNoop),
		"to", maskEmail(to),
		"subject", subject,
		"idempotency_key_present", idempotencyKey != "",
	)
	return nil
}

// SendTrialStarted / SendTrialWarning / SendTrialExpired were removed on
// 2026-05-14 per policy memory project_no_trial_pay_day_one.md. The platform
// has no trial period; hobby/pro/team are paid from day one. Anonymous (24h
// TTL) is the only free tier and is not eligible for these emails.
//
// SendWeeklyDigest was removed on 2026-05-19 (EMAIL-BUGBASH C1/F6). It was
// dead code (zero production callers) AND broken: it hardcoded the wrong
// domain (instant.dev) and its "Unsubscribe" link was `?token=<recipient
// email>` — leaking the plaintext address into the URL with no working
// unsubscribe semantics. The live weekly digest is the worker-side
// `digest.weekly` audit kind → renderDigestWeekly. Do NOT re-add a digest
// sender here; the digest belongs to the suppression-checked worker path.

// maxPaymentAttempts is the documented Razorpay charge-retry ceiling. The
// payment-failed copy says "attempt N of <maxPaymentAttempts>" and the
// attempt counter is clamped into [1, maxPaymentAttempts] so a Razorpay
// payload reporting 0 or 4+ can never render a nonsensical "attempt 4 of 3"
// (EMAIL-BUGBASH C6).
const maxPaymentAttempts = 3

// clampAttemptCount bounds a raw Razorpay attempt count into the
// [1, maxPaymentAttempts] range used by the payment-failed email copy.
func clampAttemptCount(n int) int {
	if n < 1 {
		return 1
	}
	if n > maxPaymentAttempts {
		return maxPaymentAttempts
	}
	return n
}

// EmailSendKindPaymentFailed / Receipt / TeamInvite / DeletionConfirm / MagicLink
// are the kind labels stamped into email_send_dedup.email_kind for every
// keyed send through *WithKey variants (P0-1
// CIRCUIT-RETRY-AUDIT-2026-05-20). The labels match models.EmailSendKind*
// where a sibling already existed; the new labels (TeamInvite,
// DeletionConfirm, MagicLink) are introduced here. Stored as a free-form
// TEXT column on the table, so adding a new kind never needs a migration —
// the only invariant is "operators can filter by kind in the dashboard".
const (
	EmailSendKindPaymentFailed    = "payment_failed"
	EmailSendKindPaymentReceipt   = "receipt"
	EmailSendKindTeamInvite       = "team_invite"
	EmailSendKindDeletionConfirm  = "deletion_confirm"
	EmailSendKindMagicLink        = "magic_link"
)

// SendPaymentFailed sends a payment failure notification email.
// attemptCount is the number of attempts Razorpay has made (1–3); values
// outside that range are clamped (EMAIL-BUGBASH C6).
// nextAttemptDate is when Razorpay will retry; nil means no further retry is scheduled.
//
// This is the keyless variant — preserved verbatim for backwards
// compatibility. New call sites that have a stable per-cycle key should
// use SendPaymentFailedWithKey instead so the inner ledger (P0-1) can
// collapse network-glitch retries.
func (c *Client) SendPaymentFailed(ctx context.Context, to string, attemptCount int, nextAttemptDate *time.Time) error {
	return c.SendPaymentFailedWithKey(ctx, to, "", attemptCount, nextAttemptDate)
}

// SendPaymentFailedWithKey is the P0-1 idempotent variant. idempotencyKey
// (typically the dunning cycle key built by dunningDedupKey in
// handlers/billing.go) is plumbed through to:
//
//  1. The ledger probe — if a previous attempt already 2xx'd with this
//     key the call is a no-op.
//  2. The upstream provider — `X-Mailin-Custom` (Brevo) /
//     `idempotency_key` (Resend) so the provider's own dedup catches a
//     truly-in-flight retry the local ledger hasn't yet recorded.
//
// An empty key falls back to the historical always-send path.
func (c *Client) SendPaymentFailedWithKey(ctx context.Context, to, idempotencyKey string, attemptCount int, nextAttemptDate *time.Time) error {
	subject := "Payment failed for your instanode.dev subscription"

	attemptCount = clampAttemptCount(attemptCount)
	isFinal := attemptCount >= maxPaymentAttempts

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

	// C7: build the plain-text body from only the non-empty lines so an
	// absent retryLine / urgencyLine does not interpolate blank lines into
	// the text/plain part (the HTML branch collapses empty %s on its own).
	plainLines := []string{
		fmt.Sprintf("Your payment for instanode.dev failed (attempt %d of %d).", attemptCount, maxPaymentAttempts),
		"",
	}
	if retryLine != "" {
		plainLines = append(plainLines, retryLine)
	}
	if urgencyLine != "" {
		plainLines = append(plainLines, urgencyLine)
	}
	plainLines = append(plainLines,
		"Update your payment method to keep your subscription active:",
		"https://instanode.dev/app/billing",
		"",
		"— The instanode.dev team",
	)
	plain := strings.Join(plainLines, "\n") + "\n"

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:24px;color:#111;">
  <h2>Payment failed for your instanode.dev subscription</h2>
  <p>Your payment failed (attempt <strong>%d of %d</strong>).</p>
  %s
  %s
  <p>Update your payment method to keep your subscription active.</p>
  <p style="margin-top:32px;">
    <a href="https://instanode.dev/app/billing"
       style="background:#111;color:#fff;padding:12px 24px;text-decoration:none;border-radius:6px;font-weight:bold;">
      Update payment method &rarr;
    </a>
  </p>
  <p style="margin-top:40px;color:#666;font-size:13px;">— The instanode.dev team</p>
</body>
</html>`, attemptCount, maxPaymentAttempts, retryHTML, urgencyHTML)

	return c.sendWithKey(ctx, to, subject, plain, html, idempotencyKey, EmailSendKindPaymentFailed)
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
//
// AmountKnown is false when the Razorpay payment entity was absent on the
// charge event so no real amount could be resolved (EMAIL-BUGBASH C8). When
// false, SendPaymentSucceeded does NOT print AmountDisplay as a definite
// "Amount" value — it instead renders a clearly-parenthetical "(see your
// billing dashboard for the exact amount)" so a receipt never states a
// fabricated or misleading charge figure.
type PaymentReceipt struct {
	Plan          string
	AmountDisplay string
	Period        string
	IsRenewal     bool
	AmountKnown   bool
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
//
// This is the keyless variant — preserved for backwards compatibility.
// New call sites that have a stable per-cycle key (the existing
// receiptDedupKey in handlers/billing.go is the canonical example) should
// use SendPaymentSucceededWithKey instead so the inner ledger (P0-1) can
// collapse network-glitch retries.
func (c *Client) SendPaymentSucceeded(ctx context.Context, to string, receipt PaymentReceipt) error {
	return c.SendPaymentSucceededWithKey(ctx, to, "", receipt)
}

// SendPaymentSucceededWithKey is the P0-1 idempotent variant. See
// SendPaymentFailedWithKey for the ledger + provider-header semantics.
func (c *Client) SendPaymentSucceededWithKey(ctx context.Context, to, idempotencyKey string, receipt PaymentReceipt) error {
	headline := "Payment received — your instanode.dev plan is active"
	leadPlain := fmt.Sprintf("Thank you for upgrading to %s. Your payment was successful and your plan is now active.", receipt.Plan)
	leadHTML := fmt.Sprintf("Thank you for upgrading to <strong>%s</strong>. Your payment was successful and your plan is now active.", htmlEscape(receipt.Plan))
	if receipt.IsRenewal {
		headline = "Payment received — your instanode.dev subscription renewed"
		leadPlain = fmt.Sprintf("Your %s subscription renewed successfully. Thanks for staying with instanode.dev.", receipt.Plan)
		leadHTML = fmt.Sprintf("Your <strong>%s</strong> subscription renewed successfully. Thanks for staying with instanode.dev.", htmlEscape(receipt.Plan))
	}
	subject := headline

	// C8: when the amount is not known (no payment entity on the event),
	// render the row as a clearly-parenthetical pointer rather than as a
	// definite "Amount" value, so the receipt never asserts a fabricated
	// or misleading charge figure.
	amountPlain := receipt.AmountDisplay
	amountHTMLValue := htmlEscape(receipt.AmountDisplay)
	if !receipt.AmountKnown {
		amountPlain = "(see your billing dashboard for the exact amount)"
		amountHTMLValue = `<span style="font-weight:normal;color:#666;">(see your billing dashboard for the exact amount)</span>`
	}

	plain := fmt.Sprintf(`%s

%s

Receipt
  Plan:    %s
  Amount:  %s
  Billing: %s

View your billing details: https://instanode.dev/app/billing

Need help? Reply to this email or contact support@instanode.dev.

— The instanode.dev team
`, headline, leadPlain, receipt.Plan, amountPlain, receipt.Period)

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
</html>`, headline, leadHTML, htmlEscape(receipt.Plan), amountHTMLValue, htmlEscape(receipt.Period))

	return c.sendWithKey(ctx, to, subject, plain, htmlBody, idempotencyKey, EmailSendKindPaymentReceipt)
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

// SendTeamInvite emails an invitation to join a team on instanode.dev.
// Keyless variant — preserved for backwards compatibility. New call sites
// should pass the invite id (or token) via SendTeamInviteWithKey so a
// network-glitch retry doesn't double-send the invitation.
func (c *Client) SendTeamInvite(ctx context.Context, toEmail, teamName, acceptURL string) error {
	return c.SendTeamInviteWithKey(ctx, toEmail, "", teamName, acceptURL)
}

// SendTeamInviteWithKey is the P0-1 idempotent variant. Pass the stable
// invitation id (or accept-URL token) as idempotencyKey so a webhook
// redelivery or in-process retry collapses to one delivered email.
func (c *Client) SendTeamInviteWithKey(ctx context.Context, toEmail, idempotencyKey, teamName, acceptURL string) error {
	subject := "You've been invited to an instanode.dev team"
	plain := fmt.Sprintf(`Hi,

You've been invited to join the team %q on instanode.dev.

Open this link while signed in with %s to accept:
%s

— The instanode.dev team
`, teamName, toEmail, acceptURL)

	safeTeam := htmlEscape(teamName)
	safeURL := htmlEscape(acceptURL)
	htmlBody := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:24px;color:#111;">
  <h2>Team invitation</h2>
  <p>You've been invited to join <strong>%s</strong> on instanode.dev.</p>
  <p>Sign in with <strong>%s</strong>, then open:</p>
  <p style="margin-top:16px;"><a href="%s">Accept invitation</a></p>
  <p style="margin-top:40px;color:#666;font-size:13px;">— The instanode.dev team</p>
</body>
</html>`, safeTeam, htmlEscape(toEmail), safeURL)

	return c.sendWithKey(ctx, toEmail, subject, plain, htmlBody, idempotencyKey, EmailSendKindTeamInvite)
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
//
// Keyless variant — preserved for backwards compatibility. New call sites
// should pass the pending-deletion id or token via
// SendDeletionConfirmationWithKey: the deletion confirm has NO redelivery
// safety net (no webhook redelivery, no worker retry), so a network glitch
// double-sending the email is the worst-case audit finding the P0-1 fix
// closes.
func (c *Client) SendDeletionConfirmation(
	ctx context.Context,
	toEmail, resourceLabel, link string,
	ttlMinutes int,
) error {
	return c.SendDeletionConfirmationWithKey(ctx, toEmail, "", resourceLabel, link, ttlMinutes)
}

// SendDeletionConfirmationWithKey is the P0-1 idempotent variant. Pass the
// pending-deletion row id as idempotencyKey so a retry triggered by a
// network glitch between provider 2xx and our handler reading the
// response is a no-op.
func (c *Client) SendDeletionConfirmationWithKey(
	ctx context.Context,
	toEmail, idempotencyKey, resourceLabel, link string,
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

	return c.sendWithKey(ctx, toEmail, subject, plain, htmlBody, idempotencyKey, EmailSendKindDeletionConfirm)
}

// htmlEscape replaces HTML-unsafe characters with their entity equivalents.
func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	return s
}

// maskEmail returns a privacy-preserving rendering of a recipient address
// for slog lines (EMAIL-BUGBASH L1). "alice@example.com" → "a***@example.com";
// a one-char local part is kept as-is to avoid emitting a bare "@domain".
// An address with no "@" is returned unchanged. This mirrors
// models.MaskEmail — duplicated here rather than imported because the email
// package sits below models in the dependency graph and must not import it.
func maskEmail(addr string) string {
	at := strings.LastIndex(addr, "@")
	if at <= 0 {
		return addr
	}
	local := addr[:at]
	domain := addr[at:]
	if len(local) == 1 {
		return local + domain
	}
	return local[:1] + "***" + domain
}
