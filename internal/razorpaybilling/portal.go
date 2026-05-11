package razorpaybilling

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	razorpay "github.com/razorpay/razorpay-go"
	"instant.dev/internal/config"
	"instant.dev/internal/models"
)

// Portal exposes Razorpay subscription operations for dashboard billing.
type Portal struct {
	DB  *sql.DB
	Cfg *config.Config
}

func (p *Portal) client() (*razorpay.Client, error) {
	if p.Cfg.RazorpayKeyID == "" || p.Cfg.RazorpayKeySecret == "" {
		return nil, fmt.Errorf("billing not configured")
	}
	return razorpay.NewClient(p.Cfg.RazorpayKeyID, p.Cfg.RazorpayKeySecret), nil
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
func (p *Portal) CancelAtCycleEnd(subscriptionID string) error {
	c, err := p.client()
	if err != nil {
		return err
	}
	_, err = c.Subscription.Cancel(subscriptionID, map[string]interface{}{
		"cancel_at_cycle_end": true,
	}, nil)
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
func (p *Portal) ListSubscriptionInvoices(subscriptionID string) ([]Invoice, error) {
	c, err := p.client()
	if err != nil {
		return nil, err
	}
	raw, err := c.Invoice.All(map[string]interface{}{
		"subscription_id": subscriptionID,
		"count":           100,
	}, nil)
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
func (p *Portal) PaymentUpdateURL(subscriptionID string) (string, error) {
	c, err := p.client()
	if err != nil {
		return "", err
	}
	sub, err := c.Subscription.Fetch(subscriptionID, nil, nil)
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
	sub, err := c.Subscription.Create(subBody, nil)
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
	cur, err := c.Subscription.Fetch(subID, nil, nil)
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
func (p *Portal) FetchSubscriptionDetails(subscriptionID string) (*SubscriptionDetails, error) {
	c, err := p.client()
	if err != nil {
		return nil, err
	}
	sub, err := c.Subscription.Fetch(subscriptionID, nil, nil)
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
	raw, err := c.Invoice.All(map[string]interface{}{
		"subscription_id": subscriptionID,
		"count":           50,
	}, nil)
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
	pay, err := c.Payment.Fetch(paymentID, nil, nil)
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
