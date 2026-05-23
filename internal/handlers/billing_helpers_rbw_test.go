package handlers

// Internal coverage for the unexported billing webhook helpers chargedPaymentMeta
// and receiptDedupKey, which operate on unexported rzp* types and so can't be
// reached from the external _test package.

import (
	"encoding/json"
	"testing"
)

func TestChargedPaymentMeta_RBW(t *testing.T) {
	// nil payment → all-zero
	id, amt, cur := chargedPaymentMeta(rzpWebhookEvent{})
	if id != "" || amt != 0 || cur != "" {
		t.Errorf("nil payment: got %q,%d,%q", id, amt, cur)
	}

	// bad JSON entity → all-zero
	bad := rzpWebhookEvent{Payload: rzpEventPayload{Payment: &rzpEntityWrapper{Entity: json.RawMessage(`{not json`)}}}
	id, amt, cur = chargedPaymentMeta(bad)
	if id != "" || amt != 0 || cur != "" {
		t.Errorf("bad json: got %q,%d,%q", id, amt, cur)
	}

	// valid entity → parsed fields
	ent, _ := json.Marshal(rzpPaymentEntity{ID: "pay_1", Amount: 4900, Currency: "USD"})
	ok := rzpWebhookEvent{Payload: rzpEventPayload{Payment: &rzpEntityWrapper{Entity: ent}}}
	id, amt, cur = chargedPaymentMeta(ok)
	if id != "pay_1" || amt != 4900 || cur != "USD" {
		t.Errorf("valid: got %q,%d,%q", id, amt, cur)
	}
}

func TestReceiptDedupKey_RBW(t *testing.T) {
	// empty sub.ID → ""
	if got := receiptDedupKey(rzpSubscriptionEntity{}, rzpWebhookEvent{}); got != "" {
		t.Errorf("empty sub: got %q", got)
	}

	// paid_count present → paid: key
	pc := int64(3)
	if got := receiptDedupKey(rzpSubscriptionEntity{ID: "sub_1", PaidCount: &pc}, rzpWebhookEvent{}); got != "receipt:sub_1:paid:3" {
		t.Errorf("paid_count: got %q", got)
	}

	// no paid_count, payment id present → pay: key
	ent, _ := json.Marshal(rzpPaymentEntity{ID: "pay_9"})
	ev := rzpWebhookEvent{Payload: rzpEventPayload{Payment: &rzpEntityWrapper{Entity: ent}}}
	if got := receiptDedupKey(rzpSubscriptionEntity{ID: "sub_2"}, ev); got != "receipt:sub_2:pay:pay_9" {
		t.Errorf("pay fallback: got %q", got)
	}

	// no paid_count, no payment id → ""
	if got := receiptDedupKey(rzpSubscriptionEntity{ID: "sub_3"}, rzpWebhookEvent{}); got != "" {
		t.Errorf("neither: got %q", got)
	}
}
