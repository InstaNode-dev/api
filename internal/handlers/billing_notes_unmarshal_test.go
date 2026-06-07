package handlers

// billing_notes_unmarshal_test.go — regression for the Razorpay `notes`
// polymorphism bug found by the live failure-path test (2026-06-07): Razorpay
// sends `notes` as an OBJECT when populated but an empty ARRAY ([]) when absent.
// The old `Notes map[string]string` failed to unmarshal the [] form, so every
// payment.failed webhook with no notes hit
//   "cannot unmarshal array into Go struct field …notes of type map[string]string"
// and the immediate payment-failure handling was skipped. rzpNotes tolerates
// object / array / null.

import (
	"encoding/json"
	"testing"
)

func TestRzpNotes_ToleratesArrayObjectAndNull(t *testing.T) {
	t.Parallel()

	// payment.failed with no notes → Razorpay sends notes:[] (the bug trigger).
	t.Run("payment entity notes:[] parses to empty map", func(t *testing.T) {
		t.Parallel()
		var p rzpPaymentEntity
		err := json.Unmarshal([]byte(`{"id":"pay_x","subscription_id":"sub_x","notes":[]}`), &p)
		if err != nil {
			t.Fatalf("notes:[] must not error, got %v", err)
		}
		if p.Notes == nil || len(p.Notes) != 0 {
			t.Fatalf("notes:[] must decode to an empty map, got %#v", p.Notes)
		}
		if p.SubscriptionID != "sub_x" {
			t.Fatalf("other fields must still decode; got sub=%q", p.SubscriptionID)
		}
	})

	// subscription with team_id notes (the happy path that must keep working).
	t.Run("subscription entity notes:{team_id} decodes", func(t *testing.T) {
		t.Parallel()
		var s rzpSubscriptionEntity
		err := json.Unmarshal([]byte(`{"id":"sub_y","plan_id":"plan_y","notes":{"team_id":"abc"}}`), &s)
		if err != nil {
			t.Fatalf("object notes must decode, got %v", err)
		}
		if s.Notes["team_id"] != "abc" {
			t.Fatalf("team_id must round-trip; got %#v", s.Notes)
		}
	})

	// A malformed object (non-string value) must surface the decode error rather
	// than silently swallow it — covers the json.Unmarshal error branch.
	t.Run("object with non-string value errors", func(t *testing.T) {
		t.Parallel()
		var p rzpPaymentEntity
		err := json.Unmarshal([]byte(`{"id":"p","notes":{"k":123}}`), &p)
		if err == nil {
			t.Fatal("a notes object with a non-string value must return a decode error, not be swallowed")
		}
	})

	// null and empty-array on the subscription entity → empty map, no error.
	for _, tc := range []struct{ name, body string }{
		{"null", `{"id":"s","notes":null}`},
		{"empty array", `{"id":"s","notes":[]}`},
	} {
		tc := tc
		t.Run("subscription notes "+tc.name, func(t *testing.T) {
			t.Parallel()
			var s rzpSubscriptionEntity
			if err := json.Unmarshal([]byte(tc.body), &s); err != nil {
				t.Fatalf("%s notes must not error, got %v", tc.name, err)
			}
			if s.Notes == nil {
				t.Fatalf("%s notes must be a non-nil empty map", tc.name)
			}
		})
	}
}
