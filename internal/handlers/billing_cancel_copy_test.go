package handlers

// billing_cancel_copy_test.go — F11 (billing-trust audit 2026-05-19) pure
// copy regression for the cancellation summary text.
//
// The pre-fix subscription.canceled audit row carried a bare, misleading
// Summary = "subscription canceled". That string is rendered verbatim by the
// dashboard's Recent Activity feed and is the api-side source of truth the
// worker's cancellation email derives its wording from. A customer reading it
// had no way to know the account stays active on a courtesy floor and that an
// in-flight billing-cycle charge will still complete — so the next charge
// could be mistaken for fraud.
//
// subscriptionCanceledSummary returns the corrected, accurate copy. This test
// pins that wording: it FAILS if the copy regresses to the bare string or
// drops any of the three facts the customer needs (courtesy floor / resources
// keep limits / in-flight cycle charge expected).

import (
	"strings"
	"testing"
)

func TestSubscriptionCanceledSummary_StatesAccurateOutcome(t *testing.T) {
	// Courtesy floor (paid at least once → 'hobby').
	hobby := subscriptionCanceledSummary("hobby")
	if strings.EqualFold(strings.TrimSpace(hobby), "subscription canceled") {
		t.Fatalf("F11: cancellation copy must not be the bare 'subscription canceled' string; got %q", hobby)
	}
	lh := strings.ToLower(hobby)
	for _, want := range []string{"hobby", "current limits", "billing cycle"} {
		if !strings.Contains(lh, want) {
			t.Errorf("F11: courtesy-floor cancellation copy must mention %q so the customer understands the outcome; got %q", want, hobby)
		}
	}

	// Never-paid cancellation (→ 'free' floor): must still be accurate and
	// must NOT claim an in-flight charge (none was ever taken).
	free := subscriptionCanceledSummary("free")
	if strings.EqualFold(strings.TrimSpace(free), "subscription canceled") {
		t.Fatalf("F11: free-floor cancellation copy must not be the bare 'subscription canceled' string; got %q", free)
	}
	lf := strings.ToLower(free)
	if !strings.Contains(lf, "free") {
		t.Errorf("F11: free-floor cancellation copy must name the free plan; got %q", free)
	}
	if !strings.Contains(lf, "current limits") {
		t.Errorf("F11: free-floor cancellation copy must tell the customer resources keep their limits; got %q", free)
	}
	if strings.Contains(lf, "billing cycle") {
		t.Errorf("F11: free-floor cancellation copy must NOT claim an in-flight cycle charge — a never-paid sub took none; got %q", free)
	}
}
