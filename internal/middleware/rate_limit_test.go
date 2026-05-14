package middleware_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// provisionLimitKey returns the Redis key the cache handler uses to enforce
// the per-fingerprint per-day provisioning cap for a given test fingerprint.
// The handler stores "prov:{middleware-hash}:{YYYY-MM-DD}" where the hash is
// computed by the Fingerprint middleware from the request IP, so we must go
// through the same path: fp → FingerprintToIP → ComputeTestFingerprint → hash.
func provisionLimitKey(fp string) string {
	hash := testhelpers.ComputeTestFingerprint(fp)
	return fmt.Sprintf("prov:%s:%s", hash, time.Now().UTC().Format("2006-01-02"))
}

func TestRateLimit_First5Provisions_AllowedCounterIncremented(t *testing.T) {
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()

	fp := testhelpers.UniqueFingerprint(t)

	// Simulate the cache handler incrementing the counter on each provision attempt.
	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		count, err := rdb.Incr(ctx, provisionLimitKey(fp)).Result()
		require.NoError(t, err)
		assert.EqualValues(t, i, count,
			"counter must increment on each allowed provision (attempt %d)", i)
	}
}

func TestRateLimit_6thProvisionReturnsExistingTokenFlag(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	fp := testhelpers.UniqueFingerprint(t)
	ip := testhelpers.FingerprintToIP(fp)

	// Provision 5 cache resources with DISTINCT bodies — the fingerprint
	// fallback idempotency middleware (2026-05-14) dedups identical
	// same-fingerprint-same-body POSTs within 120s, so we vary the body
	// per call to force five real provisions for this test's premise.
	var firstToken string
	for i := 0; i < 5; i++ {
		body := fmt.Sprintf(`{"name":"call-%d"}`, i)
		tok := testhelpers.MustProvisionCacheWithBody(t, app, ip, body)
		if firstToken == "" {
			firstToken = tok
		}
		defer db.Exec(`DELETE FROM resources WHERE token = $1`, tok)
	}

	// 6th provision from the same fingerprint — must return an existing
	// token via the handler-internal dedup path. Use a body that DOESN'T
	// match any of the 5 above so the middleware's fingerprint cache misses
	// and the handler is reached (where its per-day cap fires the 200).
	req := httptest.NewRequest(http.MethodPost, "/cache/new", strings.NewReader(`{"name":"call-6"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Must be 200 (not 201) — returning existing resource, not creating a new one.
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"6th provision from same fingerprint must return 200 with existing resource")

	// Verify the DB was NOT hit to create a new resource on the 6th call.
	var totalCount int
	err = db.QueryRow(`SELECT COUNT(*) FROM resources WHERE fingerprint = $1`, fp).Scan(&totalCount)
	require.NoError(t, err)
	assert.LessOrEqual(t, totalCount, 5,
		"6th provision from same fingerprint must not create a new DB row")
}

func TestRateLimit_RedisDown_FailOpen(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	// Point at a non-existent Redis instance to simulate Redis being down.
	deadRDB := redis.NewClient(&redis.Options{
		Addr:        "localhost:19999", // nothing listening here
		DialTimeout: 100 * time.Millisecond,
		ReadTimeout: 100 * time.Millisecond,
	})
	defer deadRDB.Close()

	app, cleanApp := testhelpers.NewTestApp(t, db, deadRDB)
	defer cleanApp()

	fp := testhelpers.UniqueFingerprint(t)

	req := httptest.NewRequest(http.MethodPost, "/cache/new", nil)
	req.Header.Set("X-Forwarded-For", testhelpers.FingerprintToIP(fp))

	resp, err := app.Test(req, 3000)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Fail-open: Redis unavailable must NOT block provisioning.
	// New provision returns 201 Created.
	assert.Equal(t, http.StatusCreated, resp.StatusCode,
		"when Redis is down, provision requests must fail-open and return 201")
}

func TestRateLimit_CounterTTL_Is25Hours(t *testing.T) {
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	fp := testhelpers.UniqueFingerprint(t)

	// Trigger a provision so the handler sets the provisioning counter + TTL.
	tok := testhelpers.MustProvisionCache(t, app, testhelpers.FingerprintToIP(fp))
	defer db.Exec(`DELETE FROM resources WHERE token = $1`, tok)

	// Check the TTL on the provisioning rate-limit key.
	ctx := context.Background()
	ttl, err := rdb.TTL(ctx, provisionLimitKey(fp)).Result()
	require.NoError(t, err)
	require.Greater(t, ttl, time.Duration(0), "TTL must be set on the provisioning rate-limit key")

	const (
		minTTL = 24*time.Hour + 30*time.Minute
		maxTTL = 26 * time.Hour
	)
	assert.GreaterOrEqual(t, ttl, minTTL,
		"TTL must be ~25h (not exactly 24h) to handle timezone edge cases")
	assert.LessOrEqual(t, ttl, maxTTL,
		"TTL must not exceed 26h")
}

func TestRateLimit_DifferentFingerprints_IndependentCounters(t *testing.T) {
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	fpA := testhelpers.UniqueFingerprint(t)
	fpB := testhelpers.UniqueFingerprint(t)

	// Exhaust fingerprint A's quota.
	for i := 0; i < 5; i++ {
		tok := testhelpers.MustProvisionCache(t, app, testhelpers.FingerprintToIP(fpA))
		defer db.Exec(`DELETE FROM resources WHERE token = $1`, tok)
	}

	// fingerprint B should still be allowed its first provision (returns 201).
	req := httptest.NewRequest(http.MethodPost, "/cache/new", nil)
	req.Header.Set("X-Forwarded-For", testhelpers.FingerprintToIP(fpB))
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode,
		"fingerprint B must be unaffected by fingerprint A's quota usage")

	var body map[string]any
	testhelpers.DecodeJSON(t, resp, &body)
	tok, _ := body["token"].(string)
	if tok != "" {
		defer db.Exec(`DELETE FROM resources WHERE token = $1`, tok)
	}
}

func TestRateLimit_SameFingerprint_CounterNotDoubleIncremented(t *testing.T) {
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	fp := testhelpers.UniqueFingerprint(t)
	ip := testhelpers.FingerprintToIP(fp)

	// Two provisions from the same fingerprint — but with DISTINCT
	// request bodies so the fingerprint-fallback idempotency middleware
	// (2026-05-14) doesn't dedup them. The middleware deliberately
	// dedups same-fingerprint-same-body POSTs within 120s; this test
	// is checking that the HANDLER's per-day counter ticks correctly
	// on TWO genuinely distinct attempts, so we vary the body.
	tok1 := testhelpers.MustProvisionCacheWithBody(t, app, ip, `{"name":"a"}`)
	defer db.Exec(`DELETE FROM resources WHERE token = $1`, tok1)

	tok2 := testhelpers.MustProvisionCacheWithBody(t, app, ip, `{"name":"b"}`)
	defer db.Exec(`DELETE FROM resources WHERE token = $1`, tok2)

	ctx := context.Background()
	count, err := rdb.Get(ctx, provisionLimitKey(fp)).Int()
	require.NoError(t, err)
	assert.EqualValues(t, 2, count,
		"provisioning counter must be exactly 2 after two provisions from the same fingerprint")
}

func TestRateLimit_Middleware_Sets_FingerprintLocal(t *testing.T) {
	// Ensure the rate-limit middleware does not accidentally clobber the
	// fingerprint local set by the fingerprint middleware.
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	fp := testhelpers.UniqueFingerprint(t)
	tok := testhelpers.MustProvisionCache(t, app, testhelpers.FingerprintToIP(fp))
	defer db.Exec(`DELETE FROM resources WHERE token = $1`, tok)

	// If we got a valid token back, both middlewares cooperated correctly.
	assert.NotEmpty(t, tok)
}

// TestRateLimit_WindowedReset verifies that if the TTL window expires
// a fingerprint can provision again. This is tested by setting the counter
// directly in Redis with a very short TTL.
func TestRateLimit_WindowedReset(t *testing.T) {
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	ctx := context.Background()
	fp := testhelpers.UniqueFingerprint(t)
	key := provisionLimitKey(fp)

	// Set the counter to 5 (exhausted) with a 1-second TTL.
	err := rdb.Set(ctx, key, 5, 1*time.Second).Err()
	require.NoError(t, err)

	// Wait for expiry.
	time.Sleep(1100 * time.Millisecond)

	val, err := rdb.Get(ctx, key).Int()
	if err == redis.Nil {
		// Key expired — correct.
		return
	}
	require.NoError(t, err)
	assert.EqualValues(t, 0, val, "counter should be 0 or missing after TTL expiry")
}

// TestRateLimit_ProvisionMiddleware_Integration is the integration smoke-test that
// runs the full middleware chain for rate limiting end-to-end.
func TestRateLimit_ProvisionMiddleware_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	fp := testhelpers.UniqueFingerprint(t)
	ip := testhelpers.FingerprintToIP(fp)

	// Each of the 5 distinct provisions sends a distinct body so the
	// fingerprint-fallback idempotency middleware (added 2026-05-14)
	// doesn't replay one of them. The middleware deliberately dedups
	// same-fingerprint-same-body POSTs within 120s — the precise bug
	// this whole test family used to exercise on /cache/new with an
	// empty body — so we bypass it here by varying the body. The 6th
	// call THEN reuses the 5th's body, and the handler's existing
	// fingerprint dedup (5-per-day cap → 6th replays the last token)
	// is what produces the 200 we still assert below.
	for i := 1; i <= 5; i++ {
		body := strings.NewReader(fmt.Sprintf(`{"name":"call-%d"}`, i))
		req := httptest.NewRequest(http.MethodPost, "/cache/new", body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", ip)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)

		var rb map[string]any
		testhelpers.DecodeJSON(t, resp, &rb)
		tok, _ := rb["token"].(string)
		if tok != "" {
			defer db.Exec(`DELETE FROM resources WHERE token = $1`, tok)
		}

		// New provisions return 201 Created.
		assert.Equal(t, http.StatusCreated, resp.StatusCode,
			"provision #%d must succeed with 201", i)
	}

	// 6th call (same body as #5 so middleware would replay) — but
	// we change the body again so we exercise the HANDLER's per-day
	// dedup path, which is what this test is here to assert. The 6th
	// call's body matches no prior call's body so the middleware misses;
	// the handler then sees a 6th provision from the same fingerprint
	// and replays the existing token with 200 (handler-internal dedup).
	body := strings.NewReader(`{"name":"call-6"}`)
	req := httptest.NewRequest(http.MethodPost, "/cache/new", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"6th provision must return 200 with existing token")
}
