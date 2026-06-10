package handlers

// resourcestatus_conversion_test.go — proves the api call sites converted
// from hand-written status / expiry predicates to the shared
// instant.dev/common/resourcestatus package behave IDENTICALLY to the
// pre-conversion literal comparisons.
//
// Each sub-test pins the old expression and the new shared-package call
// against the same input table and asserts they agree for every input.
// If the shared package ever drifts from the original api semantics,
// these tests fail.
//
// Converted call sites covered:
//   - resource.go Pause:  resource.Status == "paused" / != "active"
//   - resource.go Resume: resource.Status != "paused"
//   - webhook.go Receive + ListRequests: resource.Status != "active"
//   - webhook.go Receive + ListRequests: ExpiresAt.Time.Before(time.Now())
//   - logs.go ResourceLogs: resource.Status != "active"
//   - family_bulk_twin.go: r.Status != "active"
//   - resource_family.go: parent.Status == "deleted"

import (
	"testing"
	"time"

	"instant.dev/common/resourcestatus"
)

// allRawStatuses is the set of status strings the resources table can
// hold plus a junk value, so the equivalence check exercises the
// unrecognised-value path too.
var allRawStatuses = []string{"active", "paused", "suspended", "failed", "expired", "deleted", "garbage"}

// TestPauseStatusPredicate_EquivalentToOldLiterals covers resource.go
// Pause: old code rejected with "already_paused" on Status == "paused"
// and with "invalid_state" on Status != "active".
func TestPauseStatusPredicate_EquivalentToOldLiterals(t *testing.T) {
	for _, raw := range allRawStatuses {
		oldAlreadyPaused := raw == "paused"
		oldNotActive := raw != "active"

		s, _ := resourcestatus.Parse(raw)
		newAlreadyPaused := s.IsPaused()
		newNotActive := !s.IsActive()

		if newAlreadyPaused != oldAlreadyPaused {
			t.Errorf("status %q: IsPaused()=%v, old (==\"paused\")=%v", raw, newAlreadyPaused, oldAlreadyPaused)
		}
		if newNotActive != oldNotActive {
			t.Errorf("status %q: !IsActive()=%v, old (!=\"active\")=%v", raw, newNotActive, oldNotActive)
		}
	}
}

// TestResumeStatusPredicate_EquivalentToOldLiterals covers resource.go
// Resume: old code rejected with "not_paused" on Status != "paused".
func TestResumeStatusPredicate_EquivalentToOldLiterals(t *testing.T) {
	for _, raw := range allRawStatuses {
		oldNotPaused := raw != "paused"
		s, _ := resourcestatus.Parse(raw)
		newNotPaused := !s.IsPaused()
		if newNotPaused != oldNotPaused {
			t.Errorf("status %q: !IsPaused()=%v, old (!=\"paused\")=%v", raw, newNotPaused, oldNotPaused)
		}
	}
}

// TestWebhookAndLogsActivePredicate_EquivalentToOldLiterals covers the
// three identical "Status != \"active\"" guards in webhook.go (Receive,
// ListRequests) and logs.go (ResourceLogs), plus family_bulk_twin.go.
func TestWebhookAndLogsActivePredicate_EquivalentToOldLiterals(t *testing.T) {
	for _, raw := range allRawStatuses {
		oldNotActive := raw != "active"
		s, _ := resourcestatus.Parse(raw)
		newNotActive := !s.IsActive()
		if newNotActive != oldNotActive {
			t.Errorf("status %q: !IsActive()=%v, old (!=\"active\")=%v", raw, newNotActive, oldNotActive)
		}
	}
}

// TestFamilyParentDeletedPredicate_EquivalentToOldLiteral covers
// resource_family.go: parent.Status == "deleted".
func TestFamilyParentDeletedPredicate_EquivalentToOldLiteral(t *testing.T) {
	for _, raw := range allRawStatuses {
		oldDeleted := raw == "deleted"
		s, _ := resourcestatus.Parse(raw)
		newDeleted := s.IsDeleted()
		if newDeleted != oldDeleted {
			t.Errorf("status %q: IsDeleted()=%v, old (==\"deleted\")=%v", raw, newDeleted, oldDeleted)
		}
	}
}

// TestWebhookExpiryPredicate_EquivalentToOldLiteral covers the two
// identical webhook.go expiry guards. The OLD expression was
// `ExpiresAt.Time.Before(time.Now())`; the new one is
// `resourcestatus.IsPastTTL(ExpiresAt.Time, time.Now())`.
//
// Note IsPastTTL is `!now.Before(expiresAt)` — i.e. it ALSO returns true
// at the exact equality instant, where `expiresAt.Before(now)` returns
// false. For the webhook path this is a strict improvement (an
// expires_at == now resource is expired) and is exercised explicitly
// below; for every non-equality input the two agree.
func TestWebhookExpiryPredicate_EquivalentToOldLiteral(t *testing.T) {
	now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name      string
		expiresAt time.Time
	}{
		{"1h future", now.Add(time.Hour)},
		{"1h past", now.Add(-time.Hour)},
		{"1ns past", now.Add(-time.Nanosecond)},
		{"1ns future", now.Add(time.Nanosecond)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oldExpired := tc.expiresAt.Before(now)
			newExpired := resourcestatus.IsPastTTL(tc.expiresAt, now)
			if newExpired != oldExpired {
				t.Errorf("expiresAt %v: IsPastTTL=%v, old (.Before(now))=%v",
					tc.expiresAt, newExpired, oldExpired)
			}
		})
	}
	// Equality instant: IsPastTTL treats expires_at == now as past TTL.
	if !resourcestatus.IsPastTTL(now, now) {
		t.Error("IsPastTTL(now, now) must be true — an expires_at == now resource is expired")
	}
}
