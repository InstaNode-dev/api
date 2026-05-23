package handlers_test

// constructors_provarms_test.go — drives the branches of NewQueueHandler and
// NewStorageHandler that the test app's single construction path doesn't reach:
//   - NewQueueHandler: buildQueueProvider-error → defensive legacy_open fallback
//   - NewStorageHandler: cfg.MinioEndpoint set → provider auto-init success/fail

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/plans"
)

// NewQueueHandler with an unknown QUEUE_BACKEND: buildQueueProvider returns an
// error, so the constructor takes the defensive fallback that builds a
// legacy_open provider directly. Constructor must not panic and must yield a
// usable handler (issueTenantCreds returns legacy_open creds).
func TestNewQueueHandler_BadBackend_FallsBackToLegacyOpen(t *testing.T) {
	cfg := &config.Config{
		QueueBackend:   "bogus-backend",
		NATSHost:       "nats.test",
		NATSPublicHost: "nats.instanode.dev",
		AESKey:         "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
	}
	h := handlers.NewQueueHandler(nil, nil, cfg, nil, plans.Default())
	require.NotNil(t, h)
	// The defensive fallback wired a legacy_open credProvider — a valid token
	// yields legacy_open creds with no error.
	creds, err := h.IssueTenantCredsForTest(context.Background(), "tok-x", "subj")
	require.NoError(t, err)
	require.NotNil(t, creds)
}

// NewStorageHandler auto-inits from cfg.MinioEndpoint when no provider is
// injected. With valid root creds storageprovider.New succeeds (madmin.New does
// not dial at construction).
func TestNewStorageHandler_MinioEndpoint_AutoInitSuccess(t *testing.T) {
	cfg := &config.Config{
		EnabledServices:     "storage",
		AESKey:              "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
		MinioEndpoint:       "minio.test.local:9000",
		MinioPublicEndpoint: "http://minio.test.local:9000",
		MinioRootUser:       "minioadmin",
		MinioRootPassword:   "minioadmin",
		MinioBucketName:     "instant-shared",
	}
	h := handlers.NewStorageHandler(nil, nil, cfg, nil, plans.Default())
	require.NotNil(t, h)
	// Provider was auto-initialised → decideStorageMode is not "unavailable".
	kind, _ := h.DecideStorageModeKindForTest("anonymous")
	assert.NotEqual(t, "unavailable", kind)
}

// NewStorageHandler: MinioEndpoint set but root creds missing → storageprovider.New
// returns an error → the Warn branch runs and the provider stays nil.
func TestNewStorageHandler_MinioEndpoint_AutoInitError_ProviderNil(t *testing.T) {
	cfg := &config.Config{
		EnabledServices:   "storage",
		AESKey:            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
		MinioEndpoint:     "minio.test.local:9000",
		MinioRootUser:     "", // missing → New errors
		MinioRootPassword: "",
	}
	h := handlers.NewStorageHandler(nil, nil, cfg, nil, plans.Default())
	require.NotNil(t, h)
	kind, _ := h.DecideStorageModeKindForTest("anonymous")
	assert.Equal(t, "unavailable", kind, "failed auto-init must leave provider nil")
}
