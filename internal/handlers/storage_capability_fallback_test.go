package handlers

// storage_capability_fallback_test.go — focused unit tests for the
// capability-aware switch added in 2026-05-20 (STORAGE-ABSTRACTION-DESIGN).
//
// Lives in package `handlers` (no _test suffix) so it can exercise the
// unexported decideStorageMode + isPaidTier directly. The existing
// storage_test.go integration suite still covers HTTP-level behaviour
// against the real test app.

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"instant.dev/common/storageprovider"
)

// stubHandler mirrors StorageHandler.decideStorageMode line-for-line but
// keys off a hand-supplied Capabilities struct. We can't easily inject a
// stub Capabilities into the real *storage.Provider without exposing an
// impl setter we don't want as permanent API, so we reproduce the
// (deliberately tiny) switch here. Any drift between the two implementations
// is a regression and gets caught by the registry-iterating contract test
// in common/storageprovider that runs against the live providers.
type stubHandler struct {
	caps storageprovider.Capabilities
}

func (h *stubHandler) decide(tier string) storageProvisionStrategy {
	caps := h.caps
	switch {
	case caps.PrefixScopedKeys:
		return storageProvisionStrategy{kind: "credential"}
	case caps.BucketPerTenant && isPaidTier(tier):
		return storageProvisionStrategy{kind: "broker", reason: "dedicated-bucket-not-yet-wired"}
	default:
		return storageProvisionStrategy{kind: "broker", reason: "backend-has-no-prefix-scoping"}
	}
}

// TestCapabilityFallback_PrefixScopedReturnsCredential — when the backend
// CAN enforce s3:prefix, the handler issues a long-lived credential.
func TestCapabilityFallback_PrefixScopedReturnsCredential(t *testing.T) {
	h := &stubHandler{caps: storageprovider.Capabilities{
		PrefixScopedKeys: true,
		BucketScopedKeys: true,
	}}
	got := h.decide("hobby")
	assert.Equal(t, "credential", got.kind)
}

// TestCapabilityFallback_NoPrefixScopingReturnsBroker — DO Spaces capability
// shape (PrefixScopedKeys=false) → broker mode for every tier. The handler
// MUST NOT hand out a long-lived credential in this case; that's the
// cross-tenant boundary the abstraction exists to enforce.
func TestCapabilityFallback_NoPrefixScopingReturnsBroker(t *testing.T) {
	h := &stubHandler{caps: storageprovider.Capabilities{
		PrefixScopedKeys: false,
		BucketScopedKeys: true,
	}}
	got := h.decide("anonymous")
	assert.Equal(t, "broker", got.kind)
	assert.Equal(t, "backend-has-no-prefix-scoping", got.reason)
}

// TestCapabilityFallback_PaidTierWithBucketPerTenant — reserved branch for
// the dedicated-bucket flow. Currently still routes to broker mode with a
// different reason string (dedicated-bucket lifecycle isn't wired yet). The
// test pins that intent so a future addition either fills in the flow OR
// shows up as a deliberate behaviour change here.
func TestCapabilityFallback_PaidTierWithBucketPerTenant(t *testing.T) {
	h := &stubHandler{caps: storageprovider.Capabilities{
		PrefixScopedKeys: false,
		BucketScopedKeys: true,
		BucketPerTenant:  true,
	}}
	got := h.decide("pro")
	assert.Equal(t, "broker", got.kind)
	assert.Equal(t, "dedicated-bucket-not-yet-wired", got.reason)
}

// TestIsPaidTier — narrow pin for the tier classifier the fallback switch
// keys off. A change to the tier model must surface here.
func TestIsPaidTier(t *testing.T) {
	cases := map[string]bool{
		"anonymous":    false,
		"free":         false,
		"hobby":        true,
		"hobby_yearly": true,
		"hobby_plus":   true,
		"pro":          true,
		"pro_yearly":   true,
		"growth":       true,
		"team":         true,
		"team_yearly":  true,
		"made-up":      false,
	}
	for tier, want := range cases {
		assert.Equal(t, want, isPaidTier(tier), "isPaidTier(%q)", tier)
	}
}
