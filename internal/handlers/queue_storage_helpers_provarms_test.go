package handlers_test

// queue_storage_helpers_provarms_test.go — covers the remaining error/no-op
// branches of QueueHandler.issueTenantCreds and deprovisionBestEffort that the
// HTTP success paths don't reach.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/plans"
)

// issueTenantCreds error branch: the legacy_open provider returns an error when
// ResourceToken is empty → issueTenantCreds logs, increments NatsAuthFailures,
// and returns (nil, err).
func TestIssueTenantCreds_ProviderError_ReturnsErr(t *testing.T) {
	cfg := &config.Config{
		QueueBackend:   "legacy_open",
		NATSHost:       "nats.test",
		NATSPublicHost: "nats.instanode.dev",
		AESKey:         "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
	}
	h := handlers.NewQueueHandler(nil, nil, cfg, nil, plans.Default())
	// Empty token → legacy_open provider errors → issueTenantCreds error branch.
	creds, err := h.IssueTenantCredsForTest(context.Background(), "", "subj")
	require.Error(t, err)
	assert.Nil(t, creds)
}

// issueTenantCreds success-ish branch: a valid token yields legacy_open creds
// (AuthMode=legacy_open) with no error.
func TestIssueTenantCreds_LegacyOpen_Succeeds(t *testing.T) {
	cfg := &config.Config{
		QueueBackend:   "legacy_open",
		NATSHost:       "nats.test",
		NATSPublicHost: "nats.instanode.dev",
		AESKey:         "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
	}
	h := handlers.NewQueueHandler(nil, nil, cfg, nil, plans.Default())
	creds, err := h.IssueTenantCredsForTest(context.Background(), "tok-123", "subj")
	require.NoError(t, err)
	require.NotNil(t, creds)
}

// deprovisionBestEffort: nil provClient is a no-op (local-provider mode).
func TestDeprovisionBestEffort_NilClient_NoOp(t *testing.T) {
	// Must not panic; returns immediately.
	handlers.DeprovisionBestEffortForTest(context.Background(), nil, "tok", "prid", "postgres", "test.np")
}

// deprovisionBestEffort: unknown resource type → resourceTypeToProto returns
// UNSPECIFIED → early return before the gRPC call (no Deprovision counted).
func TestDeprovisionBestEffort_UnknownType_NoCall(t *testing.T) {
	fake := &fakeProvisioner{}
	pc := newBufconnProvisionerClient(t, fake)
	handlers.DeprovisionBestEffortForTest(context.Background(), pc, "tok", "prid", "not-a-real-type", "test.np")
	assert.Equal(t, 0, fake.deprovisionCount(), "unknown type must not reach the gRPC Deprovision call")
}

// deprovisionBestEffort: known type with a working client → one Deprovision.
func TestDeprovisionBestEffort_KnownType_CallsDeprovision(t *testing.T) {
	fake := &fakeProvisioner{}
	pc := newBufconnProvisionerClient(t, fake)
	handlers.DeprovisionBestEffortForTest(context.Background(), pc, "tok", "prid", "postgres", "test.np")
	assert.GreaterOrEqual(t, fake.deprovisionCount(), 1)
}
