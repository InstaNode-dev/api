package storage_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	storageprovider "instant.dev/internal/providers/storage"
)

// TestNew_RequiresEndpoint verifies that New returns an error when endpoint is empty.
func TestNew_RequiresEndpoint(t *testing.T) {
	_, err := storageprovider.New("", "", "root", "password", "instant-shared")
	require.Error(t, err, "New must fail when MinIO endpoint is empty")
	assert.Contains(t, err.Error(), "endpoint", "error must mention missing endpoint")
}

// TestNew_ValidEndpointSucceeds verifies that a non-empty endpoint produces a Provider.
// madmin.New does not dial on construction — the connection is lazy.
func TestNew_ValidEndpointSucceeds(t *testing.T) {
	p, err := storageprovider.New("minio.example.local:9000", "", "minioadmin", "minioadmin123", "instant-shared")
	require.NoError(t, err, "New must succeed when endpoint is provided (no dial at construction)")
	require.NotNil(t, p)
}

// TestNew_DefaultBucketName verifies empty bucketName defaults to "instant-shared".
func TestNew_DefaultBucketName(t *testing.T) {
	// Just verify construction succeeds — bucket name default is internal.
	p, err := storageprovider.New("minio.example.local:9000", "", "root", "pass", "")
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, "instant-shared", p.BucketName(), "empty bucketName must default to instant-shared")
}

// TestNew_PublicEndpointAccepted verifies that a public endpoint override is accepted
// without altering construction. Behavior is exercised end-to-end via Provision().
func TestNew_PublicEndpointAccepted(t *testing.T) {
	p, err := storageprovider.New("minio.example.local:9000", "s3.instanode.dev:9000", "root", "pass", "instant-shared")
	require.NoError(t, err)
	require.NotNil(t, p)
}

// TestResolveBackend exercises the operator-facing alias table. The router
// uses this to translate OBJECT_STORE_MODE / OBJECT_STORE_BACKEND into the
// internal Backend constant.
func TestResolveBackend(t *testing.T) {
	cases := []struct {
		in   string
		want storageprovider.Backend
	}{
		// Admin aliases — all collapse to the secure default.
		{"", storageprovider.BackendMinIOAdmin},
		{"admin", storageprovider.BackendMinIOAdmin},
		{"minio", storageprovider.BackendMinIOAdmin},
		{"minio-admin", storageprovider.BackendMinIOAdmin},
		{"iam", storageprovider.BackendMinIOAdmin},
		{"  ADMIN  ", storageprovider.BackendMinIOAdmin},
		// Shared-key aliases — opt-in only.
		{"shared", storageprovider.BackendSharedKey},
		{"shared-key", storageprovider.BackendSharedKey},
		{"shared_key", storageprovider.BackendSharedKey},
		{"master", storageprovider.BackendSharedKey},
		// Unknown values fall through to the secure default.
		{"garbage", storageprovider.BackendMinIOAdmin},
	}
	for _, tc := range cases {
		got := storageprovider.ResolveBackend(tc.in)
		assert.Equal(t, tc.want, got, "ResolveBackend(%q) = %q, want %q", tc.in, got, tc.want)
	}
}

// TestSharedKeyProvision_ReturnsMasterKey verifies the historical (now opt-in)
// path: every customer gets the master access key + their assigned prefix.
// This is the loophole the admin-mode work is closing — keep the test so the
// router's "production refuses shared-key" gate can't regress without showing
// up here.
func TestSharedKeyProvision_ReturnsMasterKey(t *testing.T) {
	p, err := storageprovider.NewWithBackend(
		storageprovider.BackendSharedKey,
		"do-spaces.example.com:443",
		"https://s3.instanode.dev",
		"DO_MASTER_KEY",
		"DO_MASTER_SECRET",
		"instant-shared",
		true,
	)
	require.NoError(t, err)

	credsA, err := p.Provision(context.Background(), "tokenAAAAAAAAA", "anonymous")
	require.NoError(t, err)
	credsB, err := p.Provision(context.Background(), "tokenBBBBBBBBB", "anonymous")
	require.NoError(t, err)

	assert.Equal(t, "DO_MASTER_KEY", credsA.AccessKeyID, "shared-key mode hands out the master key")
	assert.Equal(t, credsA.AccessKeyID, credsB.AccessKeyID, "shared-key mode hands out the same key to every customer (the loophole)")
	assert.NotEqual(t, credsA.Prefix, credsB.Prefix, "but prefixes are still scoped per-token")
}

// TestSharedKeyDeprovision_NoOp verifies shared-key Deprovision does nothing
// (and never errors) — no per-customer IAM users to release.
func TestSharedKeyDeprovision_NoOp(t *testing.T) {
	p, err := storageprovider.NewWithBackend(
		storageprovider.BackendSharedKey,
		"do-spaces.example.com:443",
		"https://s3.instanode.dev",
		"DO_MASTER_KEY",
		"DO_MASTER_SECRET",
		"instant-shared",
		true,
	)
	require.NoError(t, err)
	require.NoError(t, p.Deprovision(context.Background(), "tokenXYZ", ""))
}

// mockMinIOAdmin captures the path of each admin call so a test can assert
// the provider hit the expected endpoints (PUT add-user, PUT add-canned-policy,
// PUT set-user-or-group-policy on provision; DELETE remove-user +
// DELETE remove-canned-policy on deprovision).
//
// The handler returns 200 for every recognised admin endpoint, which is
// enough to drive the provider through its happy path because madmin-go
// only inspects the status code on these calls.
type mockMinIOAdmin struct {
	mu     sync.Mutex
	server *httptest.Server
	calls  []string
}

func newMockMinIOAdmin() *mockMinIOAdmin {
	m := &mockMinIOAdmin{}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.calls = append(m.calls, r.Method+" "+r.URL.Path)
		m.mu.Unlock()
		// madmin-go expects 200 OK with no body for the admin verbs we exercise.
		w.WriteHeader(http.StatusOK)
	}))
	return m
}

func (m *mockMinIOAdmin) callsContain(t *testing.T, prefix string) bool {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.calls {
		if strings.Contains(c, prefix) {
			return true
		}
	}
	return false
}

func (m *mockMinIOAdmin) close() { m.server.Close() }

// addrFromTestServer trims the scheme off an httptest.Server URL so it can be
// passed to madmin.New (which takes host:port).
func addrFromTestServer(url string) string {
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")
	return url
}

// TestAdminProvision_MintsPerTenantUser drives the admin-mode happy path
// against a mock MinIO admin server. The test asserts that Provision:
//  1. returns a per-tenant access key (not the master)
//  2. returns a freshly-generated secret (16-byte hex = 32 chars)
//  3. hits AddUser + AddCannedPolicy + SetPolicy (the three admin verbs
//     required to mint a prefix-scoped IAM user)
//
// This is the test that closes the shared-key loophole: it documents that
// a successful /storage/new in admin mode does NOT echo the master key.
func TestAdminProvision_MintsPerTenantUser(t *testing.T) {
	mock := newMockMinIOAdmin()
	defer mock.close()

	p, err := storageprovider.NewWithBackend(
		storageprovider.BackendMinIOAdmin,
		addrFromTestServer(mock.server.URL),
		"",
		"minioadmin",
		"minioadmin123",
		"instant-shared",
		false,
	)
	require.NoError(t, err)

	const token = "abcdef1234567890" // 16-char token
	creds, err := p.Provision(context.Background(), token, "hobby")
	require.NoError(t, err, "Provision must succeed against a stub that returns 200 for every admin verb")
	require.NotNil(t, creds)

	// Per-tenant key naming: "key_<FULL-token>" (token-truncation fix — the
	// old scheme truncated to token[:8] and let two tokens collide on one
	// IAM user).
	assert.Equal(t, "key_"+token, creds.AccessKeyID, "AccessKeyID must embed the full token, not an 8-char prefix")
	assert.NotEqual(t, "minioadmin", creds.AccessKeyID, "must not surface the master access key")

	// Secret is a freshly generated 32-char hex string (16 random bytes).
	assert.Len(t, creds.SecretAccessKey, 32, "SecretAccessKey is 16 bytes encoded as hex = 32 chars")
	assert.NotEqual(t, "minioadmin123", creds.SecretAccessKey, "must not surface the master secret")

	// Prefix is the FULL token, slash-terminated; ProviderResourceID is the
	// same value slash-free (what the api persists on provider_resource_id).
	assert.Equal(t, token+"/", creds.Prefix)
	assert.Equal(t, token, creds.ProviderResourceID, "ProviderResourceID must be the canonical slash-free prefix")

	// All three admin verbs ran (AddUser, AddCannedPolicy, SetPolicy).
	assert.True(t, mock.callsContain(t, "/add-user"), "Provision must call AddUser")
	assert.True(t, mock.callsContain(t, "/add-canned-policy"), "Provision must create the prefix-scoped policy")
	// madmin's SetPolicy lands on /set-user-or-group-policy.
	assert.True(t, mock.callsContain(t, "/set-user-or-group-policy"), "Provision must bind policy to user")
}

// TestAdminProvision_PerTenantKeysAreDistinct verifies two tokens get
// distinct access keys + secrets — the basic isolation contract.
func TestAdminProvision_PerTenantKeysAreDistinct(t *testing.T) {
	mock := newMockMinIOAdmin()
	defer mock.close()

	p, err := storageprovider.NewWithBackend(
		storageprovider.BackendMinIOAdmin,
		addrFromTestServer(mock.server.URL),
		"",
		"minioadmin",
		"minioadmin123",
		"instant-shared",
		false,
	)
	require.NoError(t, err)

	a, err := p.Provision(context.Background(), "aaaaaaaaaaaa", "hobby")
	require.NoError(t, err)
	b, err := p.Provision(context.Background(), "bbbbbbbbbbbb", "hobby")
	require.NoError(t, err)

	assert.NotEqual(t, a.AccessKeyID, b.AccessKeyID, "different tokens must produce different IAM users")
	assert.NotEqual(t, a.SecretAccessKey, b.SecretAccessKey, "different tokens must produce different secrets")
	assert.NotEqual(t, a.Prefix, b.Prefix, "different tokens must produce different object prefixes")
}

// TestAdminDeprovision_RemovesUserAndPolicy drives the cleanup path. The
// stub returns 200 to both verbs so the provider should report success.
func TestAdminDeprovision_RemovesUserAndPolicy(t *testing.T) {
	mock := newMockMinIOAdmin()
	defer mock.close()

	p, err := storageprovider.NewWithBackend(
		storageprovider.BackendMinIOAdmin,
		addrFromTestServer(mock.server.URL),
		"",
		"minioadmin",
		"minioadmin123",
		"instant-shared",
		false,
	)
	require.NoError(t, err)

	// Provide the canonical provider_resource_id (full-token prefix) so
	// Deprovision targets the same IAM identifiers Provision created.
	const token = "abcdef1234567890"
	require.NoError(t, p.Deprovision(context.Background(), token, token))
	assert.True(t, mock.callsContain(t, "/remove-user"), "Deprovision must call RemoveUser")
	assert.True(t, mock.callsContain(t, "/remove-canned-policy"), "Deprovision must call RemoveCannedPolicy")
}

// TestNewWithBackend_MissingAdminCreds_FailsClosed verifies the constructor
// refuses to build an admin-mode provider without root credentials. This is
// the "don't silently fall back to shared key in prod" gate the task calls
// out: missing creds → service returns 503 storage admin mode unavailable,
// because the router never gets a non-nil provider to wire into the handler.
func TestNewWithBackend_MissingAdminCreds_FailsClosed(t *testing.T) {
	_, err := storageprovider.NewWithBackend(
		storageprovider.BackendMinIOAdmin,
		"minio.example.local:9000",
		"",
		"",
		"",
		"instant-shared",
		false,
	)
	require.Error(t, err, "admin mode without root user/password must fail at construction (no silent shared-key fallback)")
	assert.Contains(t, err.Error(), "OBJECT_STORE_ACCESS_KEY",
		"error must hint at the missing env vars so operators can fix it")
}

// TestProvider_BackendGetter verifies the public Backend() accessor — used
// by the storage/resource handler to decide whether to emit
// storage.iam_user_created audit events.
func TestProvider_BackendGetter(t *testing.T) {
	admin, err := storageprovider.NewWithBackend(
		storageprovider.BackendMinIOAdmin,
		"minio.example.local:9000",
		"",
		"root", "pw",
		"instant-shared",
		false,
	)
	require.NoError(t, err)
	assert.Equal(t, storageprovider.BackendMinIOAdmin, admin.Backend())

	shared, err := storageprovider.NewWithBackend(
		storageprovider.BackendSharedKey,
		"do-spaces.example.com:443",
		"",
		"key", "secret",
		"instant-shared",
		true,
	)
	require.NoError(t, err)
	assert.Equal(t, storageprovider.BackendSharedKey, shared.Backend())

	// Nil-receiver safety — Backend() must not panic when the provider
	// failed to initialise (e.g. router skipped construction in
	// shared-key+production+!ALLOW).
	var nilProv *storageprovider.Provider
	assert.Equal(t, storageprovider.Backend(""), nilProv.Backend())
}
