package handlers_test

// storage_presign_block_integration_test.go — W4 storage-presign-block suite.
//
// Closes the matrix C16 row (Storage presign, broker) —
// docs/sessions/2026-06-04/USER-FLOW-INVENTORY-AND-TEST-MATRIX.md:
//
//	C16  POST /storage/:token/presign — signed URL ≤1h, tenant-prefix-scoped;
//	     per-token rate-limit 10/min; cross-team JWT rejected.  Sev P0.
//
// The individual C16 behaviors already have dedicated tests
// (storage_presign_provarms_test.go: GET/PUT/HEAD signing + TTL cap +
// cross-team 403; storage_presign_middleware_test.go: 10/min rate-limit +
// Retry-After). This block suite is the matrix INVENTORY cross-link that
// asserts the C16 contract end-to-end through ONE broker fixture wiring (the
// production middleware chain — OptionalAuth → PresignTokenRateLimit →
// Idempotency → handler), proving the four C16 promises hold together rather
// than in isolation:
//
//	1. tenant-prefix-scoped — the signed object_key is rooted at the resource's
//	   provider_resource_id prefix; a tenant can never sign outside its prefix.
//	2. ≤1h TTL — expires_at is bounded at ~now+1h even when the caller asks for
//	   more (presignMaxTTL=3600, silently capped).
//	3. cross-team JWT rejected — a sibling-team session bearer against another
//	   team's token is 403 cross_team_session (a leaked token laundered through
//	   a legit-but-wrong-team session must not sign).
//	4. broker mode hands out NO long-lived credential — the only access path is
//	   the fresh per-request signed URL (the whole point of broker mode).
//
// Plus the two error legs the matrix's "appropriate error" wording implies:
//	- a non-storage token → 400 not_a_storage_resource (presign signs storage
//	  resources only; the handler does NOT mode-gate beyond resource_type +
//	  active status — broker vs prefix-scoped is a provisioning-time
//	  distinction, both sign through the platform master key here).
//	- an unknown token → 404 resource_not_found.
//
// In-repo integration via the package's setupStorageProvFixture (offline
// do-spaces provider; minio-go signs locally via HMAC, no network) + existing
// seed helpers (seedStorageResource, seedResourceWithType, authSessionJWT,
// doPresign, testhelpers.MustCreateTeamDB). NOTHING here redefines an existing
// helper.

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// ── C16.1 — tenant-prefix-scoped signed URL ──────────────────────────────────

// TestPresignBlock_C16_TenantPrefixScoped asserts the signed object key is
// rooted at the resource's provider_resource_id prefix. The tenant supplies a
// relative key ("exports/jan.csv"); the handler MUST prepend the stored prefix,
// so the object the URL grants access to is always inside the tenant's space.
func TestPresignBlock_C16_TenantPrefixScoped(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	const prefix = "tenants/acme"
	token := seedStorageResource(t, fx.db, "", prefix)

	resp, body := doPresign(t, fx, token, "",
		map[string]any{"operation": "GET", "key": "exports/jan.csv"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.True(t, body.OK)
	assert.Equal(t, prefix+"/exports/jan.csv", body.ObjectKey,
		"signed object_key must be rooted at the resource prefix (tenant-prefix-scoped)")
	// The signed URL itself must contain the prefixed object path.
	assert.Contains(t, body.URL, prefix+"/exports/jan.csv")
}

// ── C16.2 — TTL bounded at ≤1h ───────────────────────────────────────────────

// TestPresignBlock_C16_TTLBoundedAtOneHour asserts the 1h hard cap. A caller
// asking for 24h is silently capped to presignMaxTTL (3600s) — a leaked 1h URL
// is already a lot of attack surface; longer would approach handing out the
// long-lived key.
func TestPresignBlock_C16_TTLBoundedAtOneHour(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	token := seedStorageResource(t, fx.db, "", "ttl-prefix")

	resp, body := doPresign(t, fx, token, "",
		map[string]any{"operation": "GET", "key": "obj.bin", "expires_in": 24 * 3600})
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	exp, err := time.Parse(time.RFC3339, body.ExpiresAt)
	require.NoError(t, err)
	assert.LessOrEqual(t, time.Until(exp), time.Hour+2*time.Minute,
		"a 24h request must be capped to ~1h (presignMaxTTL)")
	assert.Greater(t, time.Until(exp), 30*time.Minute,
		"the cap should land near 1h, not collapse the TTL to near-zero")
}

// ── C16.3 — cross-team session bearer rejected ───────────────────────────────

// TestPresignBlock_C16_CrossTeamSessionRejected asserts the session/team
// cross-check: a team-B session bearer presented against team-A's storage token
// is 403 cross_team_session. The token alone is the primary credential, but a
// present session JWT MUST match the resource team — this blocks a leaked token
// being laundered through an admin's view-as-customer session for a different
// tenant.
func TestPresignBlock_C16_CrossTeamSessionRejected(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	ownerTeam := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	otherTeam := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	require.NotEqual(t, ownerTeam, otherTeam)

	token := seedStorageResource(t, fx.db, ownerTeam, "owner-prefix")
	otherJWT := authSessionJWT(t, fx.db, otherTeam)

	resp, body := doPresign(t, fx, token, otherJWT,
		map[string]any{"operation": "GET", "key": "secret.bin"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, "cross_team_session", body.Error)
}

// TestPresignBlock_C16_SameTeamSessionSigns confirms the positive side of the
// cross-check: the OWNING team's session bearer signs successfully (a 403 for
// the legitimate owner would be a false-positive lockout).
func TestPresignBlock_C16_SameTeamSessionSigns(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	team := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	token := seedStorageResource(t, fx.db, team, "team-prefix")
	jwt := authSessionJWT(t, fx.db, team)

	resp, body := doPresign(t, fx, token, jwt,
		map[string]any{"operation": "PUT", "key": "upload.bin"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, body.OK)
	assert.Equal(t, "PUT", body.Method)
	assert.Contains(t, body.ObjectKey, "team-prefix/upload.bin")
}

// ── C16.4 — broker mode hands out no long-lived credential ───────────────────

// TestPresignBlock_C16_BrokerHandsNoLongLivedCredential asserts the broker
// contract end-to-end: the ONLY access artifact is the short-lived signed URL.
// The presign response must never carry an access_key_id / secret /
// session_token — those belong to the prefix-scoped credential path, not
// broker mode. (The presignResp struct deliberately has no credential fields,
// so we assert positively on what IS returned: a URL + bounded expiry.)
func TestPresignBlock_C16_BrokerHandsNoLongLivedCredential(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	token := seedStorageResource(t, fx.db, "", "broker-prefix")

	resp, body := doPresign(t, fx, token, "",
		map[string]any{"operation": "GET", "key": "data.json"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.True(t, body.OK)
	assert.NotEmpty(t, body.URL, "broker access path returns a signed URL")
	assert.NotEmpty(t, body.ExpiresAt, "the signed URL is short-lived (has an expiry)")
	// The signed URL is a SigV4 presigned request, not a credential handout —
	// it carries the signature inline and expires.
	assert.Contains(t, body.URL, "X-Amz-Signature=",
		"broker URL must be a SigV4 presigned request, not a bare credential")
	assert.Contains(t, body.URL, "X-Amz-Expires=",
		"broker URL must carry an explicit expiry, not a long-lived key")
}

// ── C16 error legs — non-storage token + unknown token ───────────────────────

// TestPresignBlock_C16_NonStorageToken_Returns400 asserts presign only signs
// storage resources. A token owning a postgres resource → 400
// not_a_storage_resource (this is the "non-broker / wrong resource → appropriate
// error" leg; the handler gates on resource_type, not on the storage backend
// mode, since broker vs prefix-scoped both sign through the master key here).
func TestPresignBlock_C16_NonStorageToken_Returns400(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	token := seedResourceWithType(t, fx.db, "postgres", "active")

	resp, body := doPresign(t, fx, token, "",
		map[string]any{"operation": "GET", "key": "x"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "not_a_storage_resource", body.Error)
}

// TestPresignBlock_C16_InactiveStorage_Returns410 asserts a paused/inactive
// storage resource cannot be presigned (the credential window is closed) — 410
// resource_inactive.
func TestPresignBlock_C16_InactiveStorage_Returns410(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	token := seedResourceWithType(t, fx.db, "storage", "paused")

	resp, body := doPresign(t, fx, token, "",
		map[string]any{"operation": "GET", "key": "x"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusGone, resp.StatusCode)
	assert.Equal(t, "resource_inactive", body.Error)
}

// TestPresignBlock_C16_UnknownToken_Returns404 asserts an unknown token UUID is
// 404 resource_not_found (not a 500, not a silent sign of an empty prefix).
func TestPresignBlock_C16_UnknownToken_Returns404(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)

	resp, body := doPresign(t, fx, uuid.NewString(), "",
		map[string]any{"operation": "GET", "key": "x"})
	defer resp.Body.Close()

	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Equal(t, "resource_not_found", body.Error)
}

// TestPresignBlock_C16_PathTraversalRejected asserts a tenant cannot escape its
// prefix via a "../" key — the handler hard-rejects with 400 path_unsafe
// (B17-P0; silent stripping would hide exploit intent). This is the
// tenant-prefix-scoping enforcement at the input boundary.
func TestPresignBlock_C16_PathTraversalRejected(t *testing.T) {
	fx := setupStorageProvFixture(t, newDOSpacesProvider(t), false)
	token := seedStorageResource(t, fx.db, "", "scoped-prefix")

	for _, key := range []string{"../escape", "a/../../etc", "/leading"} {
		resp, body := doPresign(t, fx, token, "",
			map[string]any{"operation": "GET", "key": key})
		require.Equalf(t, http.StatusBadRequest, resp.StatusCode, "key=%q", key)
		assert.Equalf(t, "path_unsafe", body.Error, "key=%q must reject as path_unsafe", key)
		resp.Body.Close()
	}
}
