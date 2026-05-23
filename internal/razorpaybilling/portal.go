package razorpaybilling

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	razorpay "github.com/razorpay/razorpay-go"
	"instant.dev/internal/circuit"
	"instant.dev/internal/config"
	"instant.dev/internal/models"
)

// Circuit-breaker tuning for the api → Razorpay HTTP boundary.
//
// Razorpay's outbound API is slower than the provisioner (p99 1-2s) and
// the failure mode is a 5xx burst when their infra hiccups. 5 consecutive
// failures opens the breaker; 60s cooldown matches the observed Razorpay
// recovery window (too-short floods them with retries that re-trip).
//
// One process-wide breaker shared by ALL Razorpay calls — the failure
// mode is "Razorpay is down", not "Subscription endpoint is down".
const (
	razorpayCircuitName      = "razorpay"
	razorpayCircuitThreshold = 5
	razorpayCircuitCooldown  = 60 * time.Second
)

// RazorpayHTTPTimeoutSeconds is the per-HTTP-call deadline imposed on every
// outbound Razorpay request by api-side code (P0-2 in
// CIRCUIT-RETRY-AUDIT-2026-05-20). 30 seconds matches the worker's billing
// reconciler and is the documented ceiling we treat a hung Razorpay
// endpoint as "definitely a fault" — past this we record the failure
// against the breaker and 503 the caller instead of holding a request
// handler open for minutes.
//
// Why explicit and not "rely on the SDK default": the SDK default is 10s,
// which is BELOW Razorpay's documented p99 for subscription create. A
// brownout that pushes p99 to 12-25s would silently 10s-fail every
// checkout without ever flipping the breaker, because the SDK
// converted the slow response into a generic "context deadline" error
// every time. 30s lets normal slow-but-healthy responses through,
// while still bounding the worst-case handler stall.
//
// int16 because the SDK's SetTimeout signature uses int16; values >32767
// seconds would overflow but we're well clear at 30.
const RazorpayHTTPTimeoutSeconds int16 = 30

// ApplyHTTPTimeout installs the audit-mandated 30-second HTTP timeout on a
// freshly-constructed razorpay.Client. Every razorpay.NewClient call in
// the api MUST be funneled through this helper so a future refactor
// cannot silently regress to the 10s SDK default (or worse, no timeout).
//
// Returns the same *razorpay.Client for fluent construction.
//
// The SDK's SetTimeout replaces the underlying *http.Client with a fresh
// one carrying the requested timeout — that's how we override the 10s
// default. We rely on the SDK guarantee that this is safe to call
// immediately after NewClient and before any RPC.
func ApplyHTTPTimeout(c *razorpay.Client) *razorpay.Client {
	if c == nil {
		return nil
	}
	c.Request.SetTimeout(RazorpayHTTPTimeoutSeconds)
	return c
}

// NewTimeoutClient constructs a razorpay.Client with the audit-mandated
// HTTP timeout already applied. Use this everywhere instead of
// razorpay.NewClient — it is a one-line drop-in.
func NewTimeoutClient(keyID, keySecret string) *razorpay.Client {
	return ApplyHTTPTimeout(razorpay.NewClient(keyID, keySecret))
}

// sharedBreaker is the package-level Razorpay breaker. Lazy-init so
// the package can be imported without registering Prometheus metrics
// in tests that never reach a Razorpay call.
var (
	sharedBreakerOnce sync.Once
	sharedBreaker     *circuit.Breaker
)

func breaker() *circuit.Breaker {
	sharedBreakerOnce.Do(func() {
		sharedBreaker = circuit.NewBreaker(
			razorpayCircuitName,
			razorpayCircuitThreshold,
			razorpayCircuitCooldown,
		).WithOnOpen(func() {
			slog.Error("razorpay.circuit.opened",
				"name", razorpayCircuitName,
				"threshold", razorpayCircuitThreshold,
				"cooldown_seconds", int(razorpayCircuitCooldown.Seconds()),
				"impact", "/billing/checkout and /billing/change-plan will 503 until Razorpay recovers",
				"runbook", "https://instanode.dev/status",
			)
		})
	})
	return sharedBreaker
}

// Breaker exposes the package singleton breaker for /healthz consumers
// and tests. Read-only — do NOT call Allow / Record on it directly.
func Breaker() *circuit.Breaker { return breaker() }

// callWithBreaker is the package-level wrapper for outbound Razorpay
// calls. Returns circuit.ErrOpen when the breaker rejects.
func callWithBreaker[T any](fn func() (T, error)) (T, error) {
	b := breaker()
	var zero T
	if !b.Allow() {
		return zero, circuit.ErrOpen
	}
	out, err := fn()
	b.Record(err)
	return out, err
}

// CallWithBreaker is the exported sibling of callWithBreaker, used by
// the billing handler (which constructs its Razorpay client inline via
// razorpay.NewClient instead of going through Portal). Same semantics.
func CallWithBreaker[T any](fn func() (T, error)) (T, error) {
	return callWithBreaker(fn)
}

// Portal exposes Razorpay subscription operations for dashboard billing.
type Portal struct {
	DB  *sql.DB
	Cfg *config.Config
}

// newClientForPortal is the factory used by Portal.client(). It is a
// package-level variable so unit tests in this package can install a
// version that points its BaseURL at an httptest.Server mock of the
// Razorpay API. Production code path is unchanged — the default is
// NewTimeoutClient verbatim.
var newClientForPortal = NewTimeoutClient

func (p *Portal) client() (*razorpay.Client, error) {
	if p.Cfg.RazorpayKeyID == "" || p.Cfg.RazorpayKeySecret == "" {
		return nil, fmt.Errorf("billing not configured")
	}
	// P0-2: 30s HTTP timeout via ApplyHTTPTimeout — never the bare SDK
	// default (10s) which is below Razorpay's documented p99 for
	// subscription create.
	return newClientForPortal(p.Cfg.RazorpayKeyID, p.Cfg.RazorpayKeySecret), nil
}

// SubscriptionID returns the Razorpay subscription id stored on the team (stripe_customer_id column).
func (p *Portal) SubscriptionID(ctx context.Context, teamID uuid.UUID) (string, error) {
	var sid sql.NullString
	err := p.DB.QueryRowContext(ctx, `
		SELECT stripe_customer_id FROM teams WHERE id = $1
	`, teamID).Scan(&sid)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("team not found")
	}
	if err != nil {
		return "", err
	}
	if !sid.Valid || strings.TrimSpace(sid.String) == "" {
		return "", fmt.Errorf("no subscription")
	}
	return strings.TrimSpace(sid.String), nil
}

// CancelAtCycleEnd calls POST /subscriptions/{id}/cancel with cancel_at_cycle_end.
// Wrapped by the package-level circuit breaker.
func (p *Portal) CancelAtCycleEnd(subscriptionID string) error {
	c, err := p.client()
	if err != nil {
		return err
	}
	_, err = callWithBreaker(func() (map[string]any, error) {
		return c.Subscription.Cancel(subscriptionID, map[string]interface{}{
			"cancel_at_cycle_end": true,
		}, nil)
	})
	return err
}

// CancelImmediately calls POST /subscriptions/{id}/cancel with
// cancel_at_cycle_end=false, terminating the subscription right away
// (no further charges, MRR drops in the same billing cycle).
//
// Used by the admin demote flow — when an operator pushes a paying
// customer down a tier, the customer should not continue to be charged
// for the higher tier they no longer have. Picking the "immediate"
// variant (rather than the at-cycle-end variant the customer's own
// self-serve cancel uses) keeps the MRR math clean: the cancellation
// shows up in the same period the tier change happened, with no
// ambiguous "still billing the old tier through end of cycle" tail.
func (p *Portal) CancelImmediately(subscriptionID string) error {
	c, err := p.client()
	if err != nil {
		return err
	}
	_, err = callWithBreaker(func() (map[string]any, error) {
		return c.Subscription.Cancel(subscriptionID, map[string]interface{}{
			"cancel_at_cycle_end": false,
		}, nil)
	})
	return err
}

// Invoice is a normalized subscription invoice row for the dashboard.
type Invoice struct {
	ID       string
	Amount   int64
	Currency string
	Status   string
	Date     time.Time
	PDFURL   string
}

// ListSubscriptionInvoices lists invoices for a subscription.
// Wrapped by the package-level circuit breaker.
func (p *Portal) ListSubscriptionInvoices(subscriptionID string) ([]Invoice, error) {
	c, err := p.client()
	if err != nil {
		return nil, err
	}
	raw, err := callWithBreaker(func() (map[string]any, error) {
		return c.Invoice.All(map[string]interface{}{
			"subscription_id": subscriptionID,
			"count":           100,
		}, nil)
	})
	if err != nil {
		return nil, err
	}
	items, ok := raw["items"].([]interface{})
	if !ok {
		return nil, nil
	}
	out := make([]Invoice, 0, len(items))
	for _, it := range items {
		m, ok := it.(map[string]interface{})
		if !ok {
			continue
		}
		id, _ := m["id"].(string)
		status, _ := m["status"].(string)
		cur, _ := m["currency"].(string)
		amt := toInt64(m["amount"])
		ts := pickInvoiceTimestamp(m)
		pdf := ""
		if u, ok := m["short_url"].(string); ok && u != "" {
			pdf = u
		}
		out = append(out, Invoice{
			ID: id, Amount: amt, Currency: strings.ToUpper(cur),
			Status: status, Date: ts, PDFURL: pdf,
		})
	}
	return out, nil
}

func pickInvoiceTimestamp(m map[string]interface{}) time.Time {
	for _, key := range []string{"paid_at", "issued_at", "date", "created_at"} {
		if v, ok := m[key]; ok {
			if sec := toInt64(v); sec > 0 {
				return time.Unix(sec, 0).UTC()
			}
		}
	}
	return time.Time{}
}

func toInt64(v interface{}) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case int64:
		return t
	case int:
		return int64(t)
	case json.Number:
		n, _ := t.Int64()
		return n
	case string:
		n, _ := strconv.ParseInt(t, 10, 64)
		return n
	default:
		return 0
	}
}

// PaymentUpdateURL returns a hosted URL the customer can use to authenticate or update payment.
// Wrapped by the package-level circuit breaker.
func (p *Portal) PaymentUpdateURL(subscriptionID string) (string, error) {
	c, err := p.client()
	if err != nil {
		return "", err
	}
	sub, err := callWithBreaker(func() (map[string]any, error) {
		return c.Subscription.Fetch(subscriptionID, nil, nil)
	})
	if err != nil {
		return "", err
	}
	if u, ok := sub["short_url"].(string); ok && strings.TrimSpace(u) != "" {
		return u, nil
	}
	return "", fmt.Errorf("no payment update URL available from Razorpay for this subscription")
}

// ChangePlanResult is returned after scheduling cancel and creating a replacement subscription.
type ChangePlanResult struct {
	NewPlan        string
	EffectiveDate  time.Time
	CheckoutShort  string
	NewSubID       string
}

// ChangePlan cancels the current subscription at cycle end and creates a new subscription for targetPlan (hobby|pro|team).
func (p *Portal) ChangePlan(ctx context.Context, teamID uuid.UUID, targetPlan string, planIDs map[string]string) (*ChangePlanResult, error) {
	c, err := p.client()
	if err != nil {
		return nil, err
	}
	subID, err := p.SubscriptionID(ctx, teamID)
	if err != nil {
		return nil, err
	}
	if err := p.CancelAtCycleEnd(subID); err != nil {
		return nil, fmt.Errorf("cancel current subscription: %w", err)
	}
	planID, ok := planIDs[strings.ToLower(strings.TrimSpace(targetPlan))]
	if !ok {
		return nil, fmt.Errorf("invalid target plan")
	}
	subBody := map[string]interface{}{
		"plan_id":         planID,
		"total_count":     120,
		"quantity":        1,
		"customer_notify": 1,
		"notes": map[string]interface{}{
			"team_id": teamID.String(),
			"plan":    strings.ToLower(strings.TrimSpace(targetPlan)),
		},
	}
	sub, err := callWithBreaker(func() (map[string]any, error) {
		return c.Subscription.Create(subBody, nil)
	})
	if err != nil {
		return nil, fmt.Errorf("create subscription: %w", err)
	}
	newSubID, _ := sub["id"].(string)
	shortURL, _ := sub["short_url"].(string)
	if newSubID != "" {
		if updateErr := models.UpdateRazorpaySubscriptionID(ctx, p.DB, teamID, newSubID); updateErr != nil {
			return nil, fmt.Errorf("persist subscription id: %w", updateErr)
		}
	}
	cur, err := callWithBreaker(func() (map[string]any, error) {
		return c.Subscription.Fetch(subID, nil, nil)
	})
	effective := time.Now().UTC()
	if err == nil {
		if end := toInt64(cur["current_end"]); end > 0 {
			effective = time.Unix(end, 0).UTC()
		}
	}
	return &ChangePlanResult{
		NewPlan:       strings.ToLower(strings.TrimSpace(targetPlan)),
		EffectiveDate: effective,
		CheckoutShort: shortURL,
		NewSubID:      newSubID,
	}, nil
}

// SubscriptionDetails holds a subset of Razorpay subscription fields for billing UI.
type SubscriptionDetails struct {
	Status            string
	CurrentPeriodEnd  time.Time
	CancelAtPeriodEnd bool
	ShortURL          string
	PaymentLast4      string
	PaymentNetwork    string
	PaymentExpMonth   int32
	PaymentExpYear    int32

	// PaymentMethod is the Razorpay payment method type ("card" | "upi" |
	// "netbanking" | "wallet" | "emi" | ""). Empty when no successful payment
	// has been observed for the subscription yet (e.g. just-created subs
	// awaiting the first charge).
	PaymentMethod string
	// PaymentVPA is the UPI VPA used (e.g. "name@hdfc") when PaymentMethod == "upi".
	PaymentVPA string
	// LatestPaidAmount is the most recent successful invoice amount, in the
	// subscription currency's smallest unit (paise for INR). Zero when no
	// paid invoice exists yet — callers should fall back to the plan price.
	LatestPaidAmount int64
	// LatestPaidCurrency is the ISO-4217 currency code of LatestPaidAmount
	// ("INR", "USD", ...). Empty when LatestPaidAmount is zero.
	LatestPaidCurrency string
}

// FetchSubscriptionDetails loads subscription from Razorpay and enriches payment method from latest paid invoice.
// Wrapped by the package-level circuit breaker.
func (p *Portal) FetchSubscriptionDetails(subscriptionID string) (*SubscriptionDetails, error) {
	c, err := p.client()
	if err != nil {
		return nil, err
	}
	sub, err := callWithBreaker(func() (map[string]any, error) {
		return c.Subscription.Fetch(subscriptionID, nil, nil)
	})
	if err != nil {
		return nil, err
	}
	d := &SubscriptionDetails{}
	if s, ok := sub["status"].(string); ok {
		d.Status = s
	}
	if u, ok := sub["short_url"].(string); ok {
		d.ShortURL = u
	}
	if end := toInt64(sub["current_end"]); end > 0 {
		d.CurrentPeriodEnd = time.Unix(end, 0).UTC()
	}
	if v, ok := sub["cancel_at_cycle_end"].(bool); ok && v {
		d.CancelAtPeriodEnd = true
	} else if v, ok := sub["cancel_at_cycle_end"].(float64); ok && v != 0 {
		d.CancelAtPeriodEnd = true
	}
	raw, err := callWithBreaker(func() (map[string]any, error) {
		return c.Invoice.All(map[string]interface{}{
			"subscription_id": subscriptionID,
			"count":           50,
		}, nil)
	})
	if err != nil {
		return d, nil
	}
	items, ok := raw["items"].([]interface{})
	if !ok {
		return d, nil
	}
	var paymentID string
	var bestTS int64
	for _, it := range items {
		m, ok := it.(map[string]interface{})
		if !ok {
			continue
		}
		if st, _ := m["status"].(string); !strings.EqualFold(st, "paid") {
			continue
		}
		pid, _ := m["payment_id"].(string)
		if pid == "" {
			continue
		}
		ts := toInt64(m["paid_at"])
		if ts == 0 {
			ts = toInt64(m["created_at"])
		}
		if ts >= bestTS {
			bestTS = ts
			paymentID = pid
			// Capture amount + currency from this invoice; the payment
			// object's amount field is also available but invoice amount
			// is what was actually charged for the cycle.
			d.LatestPaidAmount = toInt64(m["amount"])
			if cur, _ := m["currency"].(string); cur != "" {
				d.LatestPaidCurrency = strings.ToUpper(cur)
			}
		}
	}
	if paymentID == "" {
		return d, nil
	}
	pay, err := callWithBreaker(func() (map[string]any, error) {
		return c.Payment.Fetch(paymentID, nil, nil)
	})
	if err != nil {
		return d, nil
	}
	if method, ok := pay["method"].(string); ok {
		d.PaymentMethod = strings.ToLower(method)
	}
	// Card payment — last4 + network.
	if card, ok := pay["card"].(map[string]interface{}); ok {
		if last, ok := card["last4"].(string); ok {
			d.PaymentLast4 = last
		}
		if net, ok := card["network"].(string); ok {
			d.PaymentNetwork = strings.ToLower(net)
		}
		d.PaymentExpMonth = int32(toInt64(card["exp_month"]))
		d.PaymentExpYear = int32(toInt64(card["exp_year"]))
	}
	// UPI payment — VPA lives at top-level `vpa` (or inside an `upi` block on
	// some webhook variants — handle both).
	if vpa, ok := pay["vpa"].(string); ok && vpa != "" {
		d.PaymentVPA = vpa
	} else if upi, ok := pay["upi"].(map[string]interface{}); ok {
		if v, ok := upi["vpa"].(string); ok {
			d.PaymentVPA = v
		}
	}
	// If LatestPaidAmount wasn't picked up from the invoice (rare — some
	// Razorpay invoice records omit `amount` for non-INR or partially refunded
	// cycles), fall back to the payment record's amount.
	if d.LatestPaidAmount == 0 {
		d.LatestPaidAmount = toInt64(pay["amount"])
		if cur, _ := pay["currency"].(string); cur != "" && d.LatestPaidCurrency == "" {
			d.LatestPaidCurrency = strings.ToUpper(cur)
		}
	}
	return d, nil
}
