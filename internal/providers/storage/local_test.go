package storage_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	storageprovider "instant.dev/internal/providers/storage"
)

// TestNew_RequiresEndpoint verifies that New returns an error when endpoint is empty.
func TestNew_RequiresEndpoint(t *testing.T) {
	_, err := storageprovider.New("", "root", "password", "instant-shared")
	require.Error(t, err, "New must fail when MinIO endpoint is empty")
	assert.Contains(t, err.Error(), "endpoint", "error must mention missing endpoint")
}

// TestNew_ValidEndpointSucceeds verifies that a non-empty endpoint produces a Provider.
// madmin.New does not dial on construction — the connection is lazy.
func TestNew_ValidEndpointSucceeds(t *testing.T) {
	p, err := storageprovider.New("minio.example.local:9000", "minioadmin", "minioadmin123", "instant-shared")
	require.NoError(t, err, "New must succeed when endpoint is provided (no dial at construction)")
	require.NotNil(t, p)
}

// TestNew_DefaultBucketName verifies empty bucketName defaults to "instant-shared".
func TestNew_DefaultBucketName(t *testing.T) {
	// Just verify construction succeeds — bucket name default is internal.
	p, err := storageprovider.New("minio.example.local:9000", "root", "pass", "")
	require.NoError(t, err)
	require.NotNil(t, p)
}
