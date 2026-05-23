package handlers_test

// storage_internals_provarms_test.go — covers StorageHandler.decideStorageMode
// (on the REAL handler, not the stub mirror) and signStorageURL's missing-
// config error branches.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/plans"
)

// decideStorageMode: nil provider → "unavailable".
func TestDecideStorageMode_NilProvider_Unavailable(t *testing.T) {
	cfg := &config.Config{EnabledServices: "storage", AESKey: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"}
	h := handlers.NewStorageHandler(nil, nil, cfg, nil, plans.Default()) // no MinioEndpoint → provider nil
	kind, _ := h.DecideStorageModeKindForTest("anonymous")
	assert.Equal(t, "unavailable", kind)
}

// decideStorageMode: do-spaces (PrefixScopedKeys=false) → broker.
func TestDecideStorageMode_DOSpaces_Broker(t *testing.T) {
	cfg := storageProvConfig(false)
	h := handlers.NewStorageHandler(nil, nil, cfg, newDOSpacesProvider(t), plans.Default())
	kind, reason := h.DecideStorageModeKindForTest("pro")
	assert.Equal(t, "broker", kind)
	assert.Equal(t, "backend-has-no-prefix-scoping", reason)
}

// decideStorageMode: s3 (PrefixScopedKeys=true) → credential.
func TestDecideStorageMode_S3_Credential(t *testing.T) {
	cfg := storageProvConfig(false)
	h := handlers.NewStorageHandler(nil, nil, cfg, newS3PrefixScopedProvider(t), plans.Default())
	kind, _ := h.DecideStorageModeKindForTest("anonymous")
	assert.Equal(t, "credential", kind)
}

// signStorageURL: missing bucket/endpoint → error.
func TestSignStorageURL_MissingBucketEndpoint_Errors(t *testing.T) {
	cfg := &config.Config{EnabledServices: "storage", AESKey: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"}
	// No ObjectStoreBucket / ObjectStoreEndpoint set.
	h := handlers.NewStorageHandler(nil, nil, cfg, newDOSpacesProvider(t), plans.Default())
	_, _, err := h.SignStorageURLForTest(context.Background(), "GET", "prefix/key", time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not configured")
}

// signStorageURL: bucket+endpoint present but no master key → error.
func TestSignStorageURL_MissingMasterKey_Errors(t *testing.T) {
	cfg := &config.Config{
		EnabledServices:     "storage",
		AESKey:              "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
		ObjectStoreBucket:   "instant-shared",
		ObjectStoreEndpoint: "nyc3.test.local",
		// ObjectStoreAccessKey / SecretKey intentionally empty.
	}
	h := handlers.NewStorageHandler(nil, nil, cfg, newDOSpacesProvider(t), plans.Default())
	_, _, err := h.SignStorageURLForTest(context.Background(), "GET", "prefix/key", time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "master")
}

// signStorageURL: fully configured → signs a GET / PUT / HEAD URL offline.
func TestSignStorageURL_Success_AllOps(t *testing.T) {
	cfg := storageProvConfig(false)
	h := handlers.NewStorageHandler(nil, nil, cfg, newDOSpacesProvider(t), plans.Default())
	for _, op := range []string{"GET", "PUT", "HEAD"} {
		url, exp, err := h.SignStorageURLForTest(context.Background(), op, "prefix/obj", time.Minute)
		require.NoErrorf(t, err, "op=%s", op)
		assert.NotEmptyf(t, url, "op=%s url", op)
		assert.WithinDuration(t, time.Now().Add(time.Minute), exp, 5*time.Second)
	}
}
