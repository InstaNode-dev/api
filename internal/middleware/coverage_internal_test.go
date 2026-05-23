package middleware

// coverage_internal_test.go — white-box unit tests for unexported helpers
// across the middleware package. Lives in `package middleware` (not
// middleware_test) so it can reach the unexported pure functions that the
// black-box suites can't see. Targets the 0%-coverage helpers surfaced by
// the coverage audit: env_policy, admin_audit, idempotency canonicalisation,
// presign masking, rate-limit math, and the geo/cloud-vendor lookup table.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fiberAppForLookup builds a Fiber app whose /q route reports the result of
// the unexported defaultEnvLookup as a response header.
func fiberAppForLookup(t *testing.T) *fiber.App {
	t.Helper()
	app := fiber.New()
	h := func(c *fiber.Ctx) error {
		env, err := defaultEnvLookup(c)
		require.NoError(t, err)
		c.Set("X-Env", env)
		return c.SendStatus(fiber.StatusOK)
	}
	app.Get("/q", h)
	app.Post("/q", h)
	app.Get("/p/:env", h)
	return app
}

func probeEnvLookup(t *testing.T, app *fiber.App, path, contentType, body string) string {
	t.Helper()
	method := http.MethodGet
	var rdr *bytes.Reader
	if body != "" || contentType != "" {
		method = http.MethodPost
		rdr = bytes.NewReader([]byte(body))
	}
	var req *http.Request
	if rdr != nil {
		req = httptest.NewRequest(method, path, rdr)
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := app.Test(req, 3000)
	require.NoError(t, err)
	defer resp.Body.Close()
	return resp.Header.Get("X-Env")
}

// ---------------------------------------------------------------------------
// env_policy.go — formatAllowedRoles / envPolicyDeniedAgentAction
// ---------------------------------------------------------------------------

func TestFormatAllowedRoles(t *testing.T) {
	assert.Equal(t, "<none>", formatAllowedRoles(nil))
	assert.Equal(t, "<none>", formatAllowedRoles([]string{}))
	assert.Equal(t, "owner", formatAllowedRoles([]string{"owner"}))
	assert.Equal(t, "owner or developer", formatAllowedRoles([]string{"owner", "developer"}))
	// 3+ uses Oxford-style comma list ending in "or".
	got := formatAllowedRoles([]string{"owner", "admin", "developer"})
	assert.Equal(t, "owner, admin, or developer", got)
}

func TestEnvPolicyDeniedAgentAction(t *testing.T) {
	// Known role.
	out := envPolicyDeniedAgentAction("production", "owner", "deploy", "developer")
	assert.Contains(t, out, "Tell the user")
	assert.Contains(t, out, "production")
	assert.Contains(t, out, "owner")
	assert.Contains(t, out, "deploy")
	assert.Contains(t, out, "developer")
	assert.Contains(t, out, "https://instanode.dev/app/team")

	// Empty caller role falls back to "unknown".
	out2 := envPolicyDeniedAgentAction("staging", "owner or developer", "vault_write", "")
	assert.Contains(t, out2, "unknown")
}

// ---------------------------------------------------------------------------
// admin_audit.go — adminAuditPathSuffix / parseTeamIDFromAdminPath /
// adminAuditSummary / AdminAuditEnsureMetadataNoPrefix
// ---------------------------------------------------------------------------

func TestAdminAuditPathSuffix(t *testing.T) {
	// Empty prefix → sentinel.
	assert.Equal(t, adminAuditSuffixInvalid, adminAuditPathSuffix("/api/v1/secret/customers", ""))

	// Canonical mount → suffix returned.
	assert.Equal(t, "customers/abc/tier",
		adminAuditPathSuffix("/api/v1/secret/customers/abc/tier", "secret"))

	// Bare prefix, no trailing slash → empty suffix.
	assert.Equal(t, "", adminAuditPathSuffix("/api/v1/secret", "secret"))

	// Mismatched prefix → invalid sentinel (don't leak the raw path).
	assert.Equal(t, adminAuditSuffixInvalid,
		adminAuditPathSuffix("/api/v1/other/customers", "secret"))
}

func TestParseTeamIDFromAdminPath(t *testing.T) {
	id := uuid.New()
	// Valid /customers/<uuid>/... segment.
	got := parseTeamIDFromAdminPath("/api/v1/secret/customers/" + id.String() + "/tier")
	assert.Equal(t, id, got)

	// Trailing segment stripped, bare /customers/<uuid>.
	got2 := parseTeamIDFromAdminPath("/api/v1/secret/customers/" + id.String())
	assert.Equal(t, id, got2)

	// No customers segment → Nil.
	assert.Equal(t, uuid.Nil, parseTeamIDFromAdminPath("/api/v1/secret/teams/list"))

	// Non-UUID segment → Nil.
	assert.Equal(t, uuid.Nil, parseTeamIDFromAdminPath("/api/v1/secret/customers/not-a-uuid/tier"))
}

func TestAdminAuditSummary(t *testing.T) {
	// Success path with email + suffix.
	s := adminAuditSummary(AdminAuditMetadata{Email: "a@b.com", PathSuffix: "customers/x"})
	assert.Equal(t, "a@b.com accessed customers/x", s)

	// Anonymous + root.
	s2 := adminAuditSummary(AdminAuditMetadata{})
	assert.Equal(t, "anonymous accessed (root)", s2)

	// Denied path includes reason.
	s3 := adminAuditSummary(AdminAuditMetadata{Email: "x@y.com", PathSuffix: "p", DeniedBy: "rate_limit"})
	assert.Equal(t, "x@y.com denied (rate_limit) on p", s3)
}

func TestAdminAuditEnsureMetadataNoPrefix(t *testing.T) {
	// Empty prefix always true.
	assert.True(t, AdminAuditEnsureMetadataNoPrefix(AdminAuditMetadata{}, ""))

	// Prefix absent from marshaled metadata → true.
	clean := AdminAuditMetadata{Email: "a@b.com", PathSuffix: "customers/x"}
	assert.True(t, AdminAuditEnsureMetadataNoPrefix(clean, "topsecret"))

	// Prefix leaked into a field → false.
	leaked := AdminAuditMetadata{PathSuffix: "topsecret/customers"}
	assert.False(t, AdminAuditEnsureMetadataNoPrefix(leaked, "topsecret"))
}

// ---------------------------------------------------------------------------
// idempotency.go — looksLikeJSON / writeCanonicalJSON / canonicalJSON
// ---------------------------------------------------------------------------

func TestLooksLikeJSON(t *testing.T) {
	assert.True(t, looksLikeJSON([]byte(`{"a":1}`)))
	assert.True(t, looksLikeJSON([]byte(`  [1,2]`)))
	assert.True(t, looksLikeJSON([]byte("\n\t {}")))
	assert.False(t, looksLikeJSON([]byte("plain text")))
	assert.False(t, looksLikeJSON([]byte("")))
	assert.False(t, looksLikeJSON([]byte("   ")))
}

func TestWriteCanonicalJSON_SortsKeys(t *testing.T) {
	in := map[string]interface{}{
		"b": 2,
		"a": 1,
		"c": map[string]interface{}{"z": true, "y": false},
	}
	var buf bytes.Buffer
	require.NoError(t, writeCanonicalJSON(&buf, in))
	// Keys must be sorted recursively.
	assert.Equal(t, `{"a":1,"b":2,"c":{"y":false,"z":true}}`, buf.String())
}

func TestWriteCanonicalJSON_ArrayOrderPreserved(t *testing.T) {
	in := []interface{}{3, 1, 2}
	var buf bytes.Buffer
	require.NoError(t, writeCanonicalJSON(&buf, in))
	assert.Equal(t, `[3,1,2]`, buf.String())
}

func TestCanonicalJSON_NestedMixedTypes(t *testing.T) {
	// Exercises the writeCanonicalJSON default case (string/number/bool/null)
	// nested inside both maps and arrays.
	in := map[string]interface{}{
		"arr":  []interface{}{"s", 1.5, true, nil},
		"flag": false,
		"obj":  map[string]interface{}{"k": "v"},
	}
	out, err := canonicalJSON(in)
	require.NoError(t, err)
	assert.Equal(t, `{"arr":["s",1.5,true,null],"flag":false,"obj":{"k":"v"}}`, out)
}

func TestCanonicalJSON_OrderIndependent(t *testing.T) {
	a, err := canonicalJSON(map[string]interface{}{"x": 1, "y": 2})
	require.NoError(t, err)
	b, err := canonicalJSON(map[string]interface{}{"y": 2, "x": 1})
	require.NoError(t, err)
	assert.Equal(t, a, b, "key order must not change the canonical form")
}

// ---------------------------------------------------------------------------
// presign_token_rate_limit.go — maskPresignToken
// ---------------------------------------------------------------------------

func TestMaskPresignToken(t *testing.T) {
	assert.Equal(t, "***", maskPresignToken("short"))
	assert.Equal(t, "***", maskPresignToken("12345678")) // exactly 8 → masked
	assert.Equal(t, "abcdefgh...", maskPresignToken("abcdefghijklmnop"))
}

// ---------------------------------------------------------------------------
// rate_limit.go — nextUTCMidnight
// ---------------------------------------------------------------------------

func TestNextUTCMidnight(t *testing.T) {
	in := time.Date(2026, 5, 22, 13, 45, 0, 0, time.UTC)
	got := nextUTCMidnight(in)
	want := time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC)
	assert.Equal(t, want, got)
	assert.True(t, got.After(in))

	// A non-UTC input is normalised to UTC first.
	loc := time.FixedZone("UTC+5", 5*3600)
	in2 := time.Date(2026, 12, 31, 23, 0, 0, 0, loc) // 18:00 UTC same day
	got2 := nextUTCMidnight(in2)
	assert.Equal(t, time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), got2)
}

// ---------------------------------------------------------------------------
// log_scrubber.go — scrub free function + ScrubAdminPath edge cases
// ---------------------------------------------------------------------------

func TestScrub_Internal(t *testing.T) {
	h := &LogScrubber{secret: "sekret"}
	assert.Equal(t, "a/<ADMIN>/b", h.scrub("a/sekret/b"))
	// Empty secret on the struct → passthrough.
	h2 := &LogScrubber{secret: ""}
	assert.Equal(t, "untouched", h2.scrub("untouched"))
}

func TestScrubAdminPath_Edges(t *testing.T) {
	assert.Equal(t, "x", ScrubAdminPath("x", ""))      // empty secret
	assert.Equal(t, "", ScrubAdminPath("", "secret"))  // empty input
	assert.Equal(t, strings.Repeat(AdminScrubSentinel, 1)+"/y",
		ScrubAdminPath("secret/y", "secret"))
}

// ---------------------------------------------------------------------------
// geo.go — cloudASNs lookup table sanity
// ---------------------------------------------------------------------------

func TestCloudASNs_Table(t *testing.T) {
	assert.Equal(t, "aws", cloudASNs[16509])
	assert.Equal(t, "gcp", cloudASNs[15169])
	assert.Equal(t, "azure", cloudASNs[8075])
	assert.Equal(t, "cloudflare", cloudASNs[13335])
	_, ok := cloudASNs[1]
	assert.False(t, ok, "unknown ASN must not be in the table")
}

// ---------------------------------------------------------------------------
// auth.go — audienceMatches
// ---------------------------------------------------------------------------

func TestAudienceMatches(t *testing.T) {
	// Empty canonical → never matches (the defensive guard).
	assert.False(t, audienceMatches(jwt.ClaimStrings{"https://h/x"}, ""))
	// Present + matching entry.
	assert.True(t, audienceMatches(jwt.ClaimStrings{"https://a", "https://h/x"}, "https://h/x"))
	// Present + no match.
	assert.False(t, audienceMatches(jwt.ClaimStrings{"https://a"}, "https://h/x"))
}

// ---------------------------------------------------------------------------
// dpop.go — urlMatches
// ---------------------------------------------------------------------------

func TestURLMatches(t *testing.T) {
	// scheme + host case-insensitive, trailing slash ignored, path exact.
	assert.True(t, urlMatches("https://API.example.com/x", "https://api.example.com/x/"))
	assert.True(t, urlMatches("https://h.com", "https://h.com/")) // both normalise to "/"
	// scheme mismatch.
	assert.False(t, urlMatches("http://h.com/x", "https://h.com/x"))
	// host mismatch.
	assert.False(t, urlMatches("https://a.com/x", "https://b.com/x"))
	// path mismatch.
	assert.False(t, urlMatches("https://h.com/x", "https://h.com/y"))
	// unparseable → false.
	assert.False(t, urlMatches("://bad", "https://h.com"))
}

// ---------------------------------------------------------------------------
// idempotency.go — validateIdempotencyKey
// ---------------------------------------------------------------------------

func TestValidateIdempotencyKey(t *testing.T) {
	assert.Error(t, validateIdempotencyKey(""), "empty rejected")
	assert.NoError(t, validateIdempotencyKey("abc-123_OK"))
	// Non-ASCII printable rejected.
	assert.Error(t, validateIdempotencyKey("abc\x01def"))
	assert.Error(t, validateIdempotencyKey("emoji-\U0001F600"))
	// Over the length cap.
	assert.Error(t, validateIdempotencyKey(strings.Repeat("a", 1000)))
}

// ---------------------------------------------------------------------------
// env_policy.go — defaultEnvLookup branch coverage
// ---------------------------------------------------------------------------

func TestDefaultEnvLookup_Branches(t *testing.T) {
	app := fiberAppForLookup(t)
	// query string wins.
	assert.Equal(t, "staging", probeEnvLookup(t, app, "/q?env=staging", "", ""))
	// json body "env".
	assert.Equal(t, "production", probeEnvLookup(t, app, "/q", "application/json", `{"env":"production"}`))
	// json body "to" fallback.
	assert.Equal(t, "qa", probeEnvLookup(t, app, "/q", "application/json", `{"to":"qa"}`))
	// non-json content-type → empty.
	assert.Equal(t, "", probeEnvLookup(t, app, "/q", "text/plain", "env=prod"))
	// empty body → empty.
	assert.Equal(t, "", probeEnvLookup(t, app, "/q", "", ""))
	// :env route param wins (highest precedence).
	assert.Equal(t, "production", probeEnvLookup(t, app, "/p/production", "", ""))
	// malformed JSON body → empty (best-effort parse, no error surfaced).
	assert.Equal(t, "", probeEnvLookup(t, app, "/q", "application/json", `{bad`))
	// JSON body with neither env nor to → empty (the trailing return).
	assert.Equal(t, "", probeEnvLookup(t, app, "/q", "application/json", `{"x":1}`))
}
