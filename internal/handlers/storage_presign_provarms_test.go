package handlers_test

// storage_presign_provarms_test.go — HTTP-level coverage for POST
// /storage/:token/presign success + every error branch, plus signStorageURL
// and the audit/mask helpers. Reuses the offline storageProvFixture (do-spaces
// backend) from storage_provarms_test.go so the handler's storage provider is
// non-nil and signStorageURL (minio-go local HMAC presign — no network) runs.

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/testhelpers"
)

// seedStorageResource inserts an active storage resource for a team (or
// anonymous when teamID == "") with the given provider_resource_id (the
// object prefix). Returns the token.
func seedStorageResource(t *testing.T, db *sql.DB, teamID, prid string) string {
	t.Helper()
	var token string
	if teamID == "" {
		require.NoError(t, db.QueryRowContext(context.Background(), `
			INSERT INTO resources (resource_type, tier, env, status, provider_resource_id)
			VALUES ('storage', 'anonymous', 'development', 'active', $1)
			RETURNING token::text
		`, prid).Scan(&token))
	} else {
		require.NoError(t, db.QueryRowContext(context.Background(), `
			INSERT INTO resources (team_id, resource_type, tier, env, status, provider_resource_id)
			VALUES ($1::uuid, 'storage', 'pro', 'development', 'active', $2)
			RETURNING token::text
		`, teamID, prid).Scan(&token))
	}
	return token
}

// seedResourceWithType inserts an active resource of an arbitrary type/status.
func seedResourceWithType(t *testing.T, db *sql.DB, resourceType, status string) string {
	t.Helper()
	var token string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (resource_type, tier, env, status)
		VALUES ($1, 'anonymous', 'development', $2)
		RETURNING token::text
	`, resourceType, status).Scan(&token))
	return token
}

type presignResp struct {
	OK        bool   `json:"ok"`
	URL       string `json:"url"`
	Method    string `json:"method"`
	Key       string `json:"key"`
	ObjectKey string `json:"object_key"`
	ExpiresAt string `json:"expires_at"`
	Error     string `json:"error"`
}

func doPresign(t *testing.T, fx storageProvFixture, token, jwt string, body map[string]any) (*http.Response, presignResp) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = strings.NewReader(string(b))
	}
	req := httptest.NewRequest(http.MethodPost, "/storage/"+token+"/presign", reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Forwarded-For", "10.120.0.1")
	req.Header.Set("Idempotency-Key", uuid.NewString())
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	resp, err := fx.app.Test(req, 15000)
	require.NoError(t, err)
	var parsed presignResp
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &parsed)
	return resp, parsed
}

// ── success: GET / PUT / HEAD all sign offline via minio-go local HMAC ─────

func TestPresign_Success_GET(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	token := seedStorageResource(t, fx.db, "", "anonprefix")

	resp, body := doPresign(t, fx, token, "", map[string]any{"operation": "GET", "key": "reports/2026.csv"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, body.OK)
	assert.Equal(t, "GET", body.Method)
	assert.NotEmpty(t, body.URL)
	assert.Contains(t, body.ObjectKey, "anonprefix/reports/2026.csv")
	assert.NotEmpty(t, body.ExpiresAt)
}

func TestPresign_Success_PUT(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	token := seedStorageResource(t, fx.db, "", "p2")

	resp, body := doPresign(t, fx, token, "", map[string]any{"operation": "put", "key": "upload.bin", "expires_in": 120})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "PUT", body.Method)
	assert.NotEmpty(t, body.URL)
}

func TestPresign_Success_HEAD(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	token := seedStorageResource(t, fx.db, "", "p3")

	resp, body := doPresign(t, fx, token, "", map[string]any{"operation": "HEAD", "key": "obj"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "HEAD", body.Method)
}

// TestPresign_CanonicalHostSubstitution — API-3 (QA 2026-05-29) end-to-end.
// When ObjectStorePublicURL is configured (production: https://s3.instanode.dev),
// the returned URL must point at the canonical host, NEVER at
// nyc3.digitaloceanspaces.com — leaking the DO provider host + master access-key-id
// prefix is the leak QA flagged.
func TestPresign_CanonicalHostSubstitution(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	// Patch the config in-place — the handler reads through h.cfg, so a
	// post-construction tweak is honoured. Mirrors what production does:
	// OBJECT_STORE_PUBLIC_URL=https://s3.instanode.dev.
	fx.cfg.ObjectStorePublicURL = "https://s3.instanode.dev"

	token := seedStorageResource(t, fx.db, "", "canon-prefix")

	resp, body := doPresign(t, fx, token, "",
		map[string]any{"operation": "GET", "key": "subdir/obj.bin"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.True(t, body.OK)

	// Canonical host present, DO Spaces host MUST be absent.
	assert.True(t, strings.HasPrefix(body.URL, "https://s3.instanode.dev/"),
		"signed URL must start with the canonical host; got %q", body.URL)
	assert.NotContains(t, body.URL, "digitaloceanspaces.com",
		"DO Spaces vendor host must not leak in signed URLs; got %q", body.URL)
	// Path + signature query still intact.
	assert.Contains(t, body.URL, "canon-prefix/subdir/obj.bin")
	assert.Contains(t, body.URL, "X-Amz-Signature=")
	assert.Contains(t, body.URL, "X-Amz-Credential=")
}

// TestPresign_NoCanonicalHost_PassesThrough — local-dev / MinIO fallback: when
// ObjectStorePublicURL is empty (no canonical CNAME configured), the raw signed
// URL is returned unchanged.
func TestPresign_NoCanonicalHost_PassesThrough(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	// Default fixture cfg has ObjectStorePublicURL == "".
	assert.Empty(t, fx.cfg.ObjectStorePublicURL)

	token := seedStorageResource(t, fx.db, "", "nopub")
	resp, body := doPresign(t, fx, token, "",
		map[string]any{"operation": "GET", "key": "x"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	// With no public URL, the original signed host (configured endpoint) is
	// returned. Asserts the no-rewrite branch behaves as a pass-through.
	assert.Contains(t, body.URL, "nyc3.test.local")
	assert.NotContains(t, body.URL, "s3.instanode.dev")
}

// ── TTL cap: requesting > 1h is silently capped to 3600s ───────────────────

func TestPresign_TTLCapped(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	token := seedStorageResource(t, fx.db, "", "p4")

	resp, body := doPresign(t, fx, token, "", map[string]any{"operation": "GET", "key": "x", "expires_in": 99999})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	exp, err := time.Parse(time.RFC3339, body.ExpiresAt)
	require.NoError(t, err)
	assert.LessOrEqual(t, time.Until(exp), time.Hour+2*time.Minute, "TTL must be capped at ~1h")
}

// ── legacy row (empty provider_resource_id) falls back to token prefix ─────

func TestPresign_LegacyRow_FallsBackToTokenPrefix(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	token := seedStorageResource(t, fx.db, "", "") // empty PRID

	resp, body := doPresign(t, fx, token, "", map[string]any{"operation": "GET", "key": "x"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, body.ObjectKey, token+"/x", "empty PRID → token-derived prefix")
}

// ── error branches ─────────────────────────────────────────────────────────

func TestPresign_InvalidTokenUUID_Returns400(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	resp, body := doPresign(t, fx, "not-a-uuid", "", map[string]any{"operation": "GET", "key": "x"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_token", body.Error)
}

func TestPresign_UnparseableBody_Returns400(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	req := httptest.NewRequest(http.MethodPost, "/storage/"+uuid.NewString()+"/presign",
		strings.NewReader("{not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "10.121.0.1")
	resp, err := fx.app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body presignResp
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &body)
	assert.Equal(t, "invalid_body", body.Error)
}

func TestPresign_UnknownToken_Returns404(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	resp, body := doPresign(t, fx, uuid.NewString(), "", map[string]any{"operation": "GET", "key": "x"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Equal(t, "resource_not_found", body.Error)
}

func TestPresign_NotAStorageResource_Returns400(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	token := seedResourceWithType(t, fx.db, "postgres", "active")
	resp, body := doPresign(t, fx, token, "", map[string]any{"operation": "GET", "key": "x"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "not_a_storage_resource", body.Error)
}

func TestPresign_InactiveResource_Returns410(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	token := seedResourceWithType(t, fx.db, "storage", "paused")
	resp, body := doPresign(t, fx, token, "", map[string]any{"operation": "GET", "key": "x"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusGone, resp.StatusCode)
	assert.Equal(t, "resource_inactive", body.Error)
}

func TestPresign_InvalidOperation_Returns400(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	token := seedStorageResource(t, fx.db, "", "p5")
	resp, body := doPresign(t, fx, token, "", map[string]any{"operation": "DELETE", "key": "x"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_operation", body.Error)
}

func TestPresign_MissingKey_Returns400(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	token := seedStorageResource(t, fx.db, "", "p6")
	resp, body := doPresign(t, fx, token, "", map[string]any{"operation": "GET", "key": "   "})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_key", body.Error)
}

func TestPresign_PathTraversalKey_Returns400(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	token := seedStorageResource(t, fx.db, "", "p7")
	resp, body := doPresign(t, fx, token, "", map[string]any{"operation": "GET", "key": "../escape"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "path_unsafe", body.Error)
}

// ── cross-team session is rejected (403) ───────────────────────────────────

func TestPresign_CrossTeamSession_Returns403(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	ownerTeam := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	otherTeam := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	token := seedStorageResource(t, fx.db, ownerTeam, "owned")
	otherJWT := authSessionJWT(t, fx.db, otherTeam)

	resp, body := doPresign(t, fx, token, otherJWT, map[string]any{"operation": "GET", "key": "x"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, "cross_team_session", body.Error)
}

// ── same-team session presigns successfully ────────────────────────────────

func TestPresign_SameTeamSession_Success(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	team := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	token := seedStorageResource(t, fx.db, team, "ownedprefix")
	jwt := authSessionJWT(t, fx.db, team)

	resp, body := doPresign(t, fx, token, jwt, map[string]any{"operation": "GET", "key": "data.json"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, body.OK)
}

// ── presign helpers (unit) ─────────────────────────────────────────────────

func TestPresignHelpers_MaskToken(t *testing.T) {
	assert.Equal(t, "***", handlers.MaskPresignTokenForAuditForTest("short"))
	long := "0123456789abcdef"
	assert.Equal(t, "01234567...", handlers.MaskPresignTokenForAuditForTest(long))
}

func TestPresignHelpers_MaskKey(t *testing.T) {
	assert.Equal(t, "short/key.txt", handlers.MaskPresignKeyForAuditForTest("short/key.txt"))
	long := strings.Repeat("a", 40)
	masked := handlers.MaskPresignKeyForAuditForTest(long)
	assert.Equal(t, 35, len(masked), "32 chars + ellipsis")
	assert.True(t, strings.HasSuffix(masked, "..."))
}

func TestPresignHelpers_SanitiseAndSafe(t *testing.T) {
	assert.True(t, handlers.IsSafePresignKeyForTest("a/b/c"))
	assert.False(t, handlers.IsSafePresignKeyForTest("../x"))
	assert.False(t, handlers.IsSafePresignKeyForTest(""))
	assert.Equal(t, "a/b", handlers.SanitisePresignKeyForTest("/a/./b/.."))
}
