package handlers_test

// claim_preview_items_alias_test.go — coverage for B5-P1-3 (BugBash
// 2026-05-20): GET /claim/preview must emit `items` as the canonical
// envelope field while keeping `resources` populated as the legacy
// back-compat alias.
//
// Two sites in onboarding.go.ClaimPreview emit the response — the
// already_claimed branch and the happy-path branch. The fix must touch
// both. This test exercises both branches and asserts the dual-key
// envelope on each.
//
// The bug was a contract drift: every other list endpoint on the
// platform (/api/v1/resources, /api/v1/deployments, /api/v1/audit,
// /api/v1/backups, /api/v1/team/invitations) uses `items`, but
// /claim/preview shipped with `resources`. Agents generated against
// the OpenAPI snapshot had to special-case this one envelope shape.
// We can't drop `resources` without breaking the live dashboard /
// sdk-go — so this PR adds `items` as the canonical alias and marks
// `resources` deprecated in the spec.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/crypto"
	"instant.dev/internal/testhelpers"
)

// TestClaimPreview_ItemsAlias_AlreadyClaimedBranch asserts that the
// already_claimed branch of /claim/preview emits BOTH `items` and
// `resources` as empty arrays — the two fields must always co-exist
// so old (dashboard) and new (items-reading) clients both see a
// well-shaped envelope.
func TestClaimPreview_ItemsAlias_AlreadyClaimedBranch(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app := claimPreviewApp(t, db, rdb)

	jti := uuid.New().String()
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO onboarding_events (jti, fingerprint, converted_at, team_id)
		VALUES ($1, $2, now(), NULL)
	`, jti, "fp-items-alias-claimed")
	require.NoError(t, err)

	claims := crypto.OnboardingClaims{
		Fingerprint: "fp-items-alias-claimed",
		Tokens:      []string{},
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(testhelpers.TestJWTSecret))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/claim/preview?t="+signed, nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	testhelpers.DecodeJSON(t, resp, &body)
	assert.Equal(t, true, body["ok"])
	assert.Equal(t, false, body["token_valid"])
	assert.Equal(t, true, body["already_claimed"])

	// B5-P1-3: both envelope keys must be present.
	items, hasItems := body["items"].([]any)
	require.True(t, hasItems, "already_claimed branch must emit `items` envelope key (B5-P1-3)")
	assert.Equal(t, 0, len(items), "already_claimed branch: `items` is the empty list")

	resources, hasResources := body["resources"].([]any)
	require.True(t, hasResources, "already_claimed branch must also keep emitting legacy `resources` key for back-compat")
	assert.Equal(t, 0, len(resources), "already_claimed branch: `resources` legacy alias is the empty list")
}

// TestClaimPreview_ItemsAlias_HappyPathBranch asserts the dual-key
// envelope on the happy path — the branch that surfaces the actual
// resource list to the caller. Items and resources must be equal-shape
// (both arrays of the same length, same element shape) so a switch
// from one to the other is a true alias swap, not a semantic change.
func TestClaimPreview_ItemsAlias_HappyPathBranch(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	provApp, cleanProv := testhelpers.NewTestApp(t, db, rdb)
	defer cleanProv()
	app := claimPreviewApp(t, db, rdb)

	fp := testhelpers.UniqueFingerprint(t)
	res := testhelpers.MustProvisionCacheFull(t, provApp, fp)
	require.NotEmpty(t, res.JWT)

	req := httptest.NewRequest(http.MethodGet, "/claim/preview?t="+res.JWT, nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	testhelpers.DecodeJSON(t, resp, &body)
	assert.Equal(t, true, body["ok"])
	assert.Equal(t, true, body["token_valid"])

	items, hasItems := body["items"].([]any)
	require.True(t, hasItems, "happy-path branch must emit `items` envelope key (B5-P1-3)")
	assert.GreaterOrEqual(t, len(items), 1, "happy path: `items` must surface at least the provisioned resource")

	resources, hasResources := body["resources"].([]any)
	require.True(t, hasResources, "happy-path branch must also keep emitting legacy `resources` key for back-compat")
	assert.Equal(t, len(items), len(resources),
		"`items` and `resources` must be equal-length aliases — drift means one side is missing rows")

	// Element-shape spot-check: every resource in `items` carries a
	// `token` field. (Element-by-element deep-equal between `items`
	// and `resources` is enforced by the equal-length + same-source
	// invariant; the field-shape check guards against accidental
	// projection differences between the two arrays in future edits.)
	for i, it := range items {
		m, ok := it.(map[string]any)
		require.True(t, ok, "items[%d] must be a JSON object", i)
		_, hasToken := m["token"]
		assert.True(t, hasToken, "items[%d] must carry `token` field (ResourceItem schema)", i)
	}
	assert.NotEmpty(t, body["expires_at"])
}
