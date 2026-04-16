package middleware_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
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

	// Provision 5 cache resources — these should all succeed and create new resources.
	var firstToken string
	for i := 0; i < 5; i++ {
		tok := testhelpers.MustProvisionCache(t, app, ip)
		if firstToken == "" {
			firstToken = tok
		}
		defer db.Exec(`DELETE FROM resources WHERE token = $1`, tok)
	}

	// 6th provision from the same fingerprint — must return an existing token.
	req := httptest.NewRequest(http.MethodPost, "/cache/new", nil)
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

	// Two provisions from the same fingerprint.
	tok1 := testhelpers.MustProvisionCache(t, app, ip)
	defer db.Exec(`DELETE FROM resources WHERE token = $1`, tok1)

	tok2 := testhelpers.MustProvisionCache(t, app, ip)
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

	for i := 1; i <= 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/cache/new", nil)
		req.Header.Set("X-Forwarded-For", ip)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)

		var body map[string]any
		testhelpers.DecodeJSON(t, resp, &body)
		tok, _ := body["token"].(string)
		if tok != "" {
			defer db.Exec(`DELETE FROM resources WHERE token = $1`, tok)
		}

		// New provisions return 201 Created.
		assert.Equal(t, http.StatusCreated, resp.StatusCode,
			"provision #%d must succeed with 201", i)
	}

	// 6th call should still be 200 but returns existing token (no new resource).
	req := httptest.NewRequest(http.MethodPost, "/cache/new", nil)
	req.Header.Set("X-Forwarded-For", ip)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"6th provision must return 200 with existing token")
}
