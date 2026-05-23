package middleware

// coverage_push3_test.go — white-box top-up batch closing the last
// sub-95% unexported helpers surfaced by the coverage audit:
// dpop jwkThumbprintBase64URL (success), requestCanonicalURL defensive
// fallback (unparseable canonical URL), urlMatches second-arg parse error,
// and canonicalJSON / writeCanonicalJSON unmarshalable-value error path.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// rate_limit.go — incrementWithExpiry nil-client + pipeline-exec error
// ---------------------------------------------------------------------------

func TestIncrementWithExpiry_NilClient(t *testing.T) {
	// CLAUDE.md convention #1: a nil client must NOT SIGSEGV — it returns
	// (0, err) so the caller fails open.
	n, err := incrementWithExpiry(context.Background(), nil, "k", time.Minute)
	assert.Error(t, err)
	assert.Zero(t, n)
}

func TestIncrementWithExpiry_PipelineExecError(t *testing.T) {
	// Point the client at an address nothing is listening on so the
	// pipeline Exec fails — exercises the redis-error branch (fail-open).
	rdb := redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:1", // reserved/closed port
		DialTimeout: 200 * time.Millisecond,
		MaxRetries:  -1,
	})
	defer rdb.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	n, err := incrementWithExpiry(ctx, rdb, "k", time.Minute)
	assert.Error(t, err)
	assert.Zero(t, n)
}

// ---------------------------------------------------------------------------
// dpop.go — jwkThumbprintBase64URL success path
// ---------------------------------------------------------------------------

func TestJWKThumbprintBase64URL_Success(t *testing.T) {
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.FromRaw(raw)
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.AlgorithmKey, jwa.ES256))

	got, err := jwkThumbprintBase64URL(key)
	require.NoError(t, err)
	assert.NotEmpty(t, got)

	// Must equal the RFC 7638 thumbprint encoded base64url-no-pad.
	tp, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	assert.Equal(t, base64URLNoPad(tp), got)
}

// ---------------------------------------------------------------------------
// dpop.go — requestCanonicalURL defensive fallback
// ---------------------------------------------------------------------------

func TestRequestCanonicalURL_FallbackOnUnparseableCanonical(t *testing.T) {
	// Force CanonicalResourceURLFor to return a value url.Parse rejects so
	// the host-less defensive branch runs.
	orig := CanonicalResourceURLFor
	CanonicalResourceURLFor = func(_ *fiber.Ctx) string { return "://%%bad" }
	defer func() { CanonicalResourceURLFor = orig }()

	app := fiber.New()
	app.Get("/widgets", func(c *fiber.Ctx) error {
		got := requestCanonicalURL(c)
		// Falls back to https://<hostname><path>.
		assert.Contains(t, got, "/widgets")
		assert.Contains(t, got, "https://")
		return c.SendStatus(fiber.StatusOK)
	})
	req := httptest.NewRequest(fiber.MethodGet, "/widgets", nil)
	req.Host = "fallback.example.com"
	resp, err := app.Test(req, 3000)
	require.NoError(t, err)
	resp.Body.Close()
}

func TestRequestCanonicalURL_HappyPath(t *testing.T) {
	orig := CanonicalResourceURLFor
	CanonicalResourceURLFor = func(_ *fiber.Ctx) string { return "https://api.example.com" }
	defer func() { CanonicalResourceURLFor = orig }()

	app := fiber.New()
	app.Get("/db/new", func(c *fiber.Ctx) error {
		assert.Equal(t, "https://api.example.com/db/new", requestCanonicalURL(c))
		return c.SendStatus(fiber.StatusOK)
	})
	resp, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/db/new", nil), 3000)
	require.NoError(t, err)
	resp.Body.Close()
}

// ---------------------------------------------------------------------------
// dpop.go — urlMatches: second operand unparseable
// ---------------------------------------------------------------------------

func TestURLMatches_SecondOperandUnparseable(t *testing.T) {
	assert.False(t, urlMatches("https://h.com/x", "://bad"))
}

// ---------------------------------------------------------------------------
// idempotency.go — canonicalJSON / writeCanonicalJSON marshal-error path
// ---------------------------------------------------------------------------

func TestCanonicalJSON_UnmarshalableValueErrors(t *testing.T) {
	// json.Marshal cannot encode a func value → the default branch in
	// writeCanonicalJSON returns an error, surfaced by canonicalJSON.
	_, err := canonicalJSON(map[string]interface{}{"f": func() {}})
	assert.Error(t, err)

	// Same inside a slice element.
	_, err = canonicalJSON([]interface{}{func() {}})
	assert.Error(t, err)

	// Top-level unmarshalable value.
	_, err = canonicalJSON(func() {})
	assert.Error(t, err)
}
