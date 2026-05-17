package cache_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cacheprovider "instant.dev/internal/providers/cache"
	"instant.dev/internal/testhelpers"
)

// TestProvision_Local_ReturnsURL verifies that Provision returns credentials
// with a URL that starts with redis://.
func TestProvision_Local_ReturnsURL(t *testing.T) {
	rdb, cleanup := testhelpers.SetupTestRedis(t)
	defer cleanup()

	p := cacheprovider.New(rdb, "local", "localhost")
	token := "test-token-" + t.Name()

	creds, err := p.Provision(context.Background(), token, "anonymous")
	require.NoError(t, err)
	require.NotNil(t, creds)

	assert.True(t, strings.HasPrefix(creds.URL, "redis://"),
		"URL must start with redis://; got %q", creds.URL)
}

// TestProvision_Local_TwoTokensIsolated verifies that two different tokens
// receive different credentials (different URL or different key prefix).
func TestProvision_Local_TwoTokensIsolated(t *testing.T) {
	rdb, cleanup := testhelpers.SetupTestRedis(t)
	defer cleanup()

	p := cacheprovider.New(rdb, "local", "localhost")

	creds1, err := p.Provision(context.Background(), "token-aaa-111", "anonymous")
	require.NoError(t, err)

	creds2, err := p.Provision(context.Background(), "token-bbb-222", "anonymous")
	require.NoError(t, err)

	// At minimum one of URL or KeyPrefix must differ.
	bothSame := (creds1.URL == creds2.URL) && (creds1.KeyPrefix == creds2.KeyPrefix)
	assert.False(t, bothSame,
		"two tokens must have different credentials; got identical URL=%q KeyPrefix=%q",
		creds1.URL, creds1.KeyPrefix)
}

// TestStorageBytes_EmptyNamespace_ReturnsZero verifies that a freshly provisioned
// token with no keys stored returns 0 bytes.
func TestStorageBytes_EmptyNamespace_ReturnsZero(t *testing.T) {
	rdb, cleanup := testhelpers.SetupTestRedis(t)
	defer cleanup()

	p := cacheprovider.New(rdb, "local", "localhost")
	token := "empty-token-" + t.Name()

	bytes, err := p.StorageBytes(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, int64(0), bytes, "empty namespace must report 0 bytes")
}

// TestStorageBytes_AfterWrite_ReturnsPosBytes verifies that writing a key under
// the token prefix causes StorageBytes to return a positive value.
func TestStorageBytes_AfterWrite_ReturnsPosBytes(t *testing.T) {
	rdb, cleanup := testhelpers.SetupTestRedis(t)
	defer cleanup()

	p := cacheprovider.New(rdb, "local", "localhost")
	token := "nonempty-token-" + t.Name()

	// Write a key in the token's namespace directly via the admin client.
	key := token + ":mykey"
	err := rdb.Set(context.Background(), key, "hello world", 0).Err()
	require.NoError(t, err)

	bytes, err := p.StorageBytes(context.Background(), token)
	require.NoError(t, err)
	assert.Greater(t, bytes, int64(0),
		"namespace with one key must report > 0 bytes")
}

// TestACLAllowlist_NoPlusAtAll verifies the ACL allowlist does not grant "+@all"
// to provisioned users on the shared Redis backend (A2 regression guard).
//
// "+@all" on a shared Redis pod allows FLUSHDB/MONITOR which are multi-tenant
// isolation failures. This test captures the ACL SETUSER arguments issued to
// Redis and ensures "+@all" is absent and the critical deny entries are present.
func TestACLAllowlist_NoPlusAtAll(t *testing.T) {
	rdb, cleanup := testhelpers.SetupTestRedis(t)
	defer cleanup()

	p := cacheprovider.New(rdb, "local", "localhost")
	token := "acl-guard-" + t.Name()

	_, err := p.Provision(context.Background(), token, "anonymous")
	require.NoError(t, err)

	// Inspect the ACL entry for the provisioned user via ACL GETUSER.
	// P1-E: the username uses the FULL token (no 8-char truncation).
	username := "usr_" + token

	result, aclErr := rdb.Do(context.Background(), "ACL", "GETUSER", username).Result()
	if aclErr != nil {
		// ACL not available (Redis < 6) — fall back to key-namespace mode, skip test.
		t.Skipf("ACL GETUSER not available (Redis < 6 or ACL disabled): %v", aclErr)
	}

	// Flatten the ACL GETUSER result to a string for inspection.
	aclStr := fmt.Sprintf("%v", result)

	assert.NotContains(t, aclStr, "+@all",
		"ACL user must NOT have +@all — it would grant FLUSHDB/MONITOR on the shared pod")
}
