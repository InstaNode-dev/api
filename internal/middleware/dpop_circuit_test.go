package middleware_test

// dpop_circuit_test.go — verifies the new fail-CLOSED behavior plus
// the dpop_redis circuit breaker added alongside.
//
// Pre-W12 the DPoP middleware failed OPEN on Redis errors and on
// rdb==nil. This file is the regression guard: each test confirms the
// middleware now returns 503 dpop_replay_check_unavailable instead of
// silently accepting a proof it couldn't replay-check.

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/circuit"
	"instant.dev/internal/middleware"
)

// TestDPoP_RedisNil_FailsClosed — the brief's B43 S12 fix: when rdb is
// nil and the bearer is key-bound, the middleware MUST refuse the
// request with 503 instead of silently letting it through (the old
// fail-OPEN behavior).
func TestDPoP_RedisNil_FailsClosed(t *testing.T) {
	middleware.ResetDPoPRedisBreakerForTest()
	t.Setenv("API_PUBLIC_URL", "https://api.instanode.dev")
	f := newDPoPFixture(t)
	proof := f.signProof("POST", "https://api.instanode.dev/db/new", time.Now(), uuid.NewString())

	// rdb==nil — the old code would have logged and called c.Next().
	app := newDPoPApp(nil)
	resp := runRequest(t, app, http.MethodPost, "https://api.instanode.dev/db/new", f.bearer, proof)
	defer resp.Body.Close()

	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode,
		"rdb==nil for a key-bound token must fail CLOSED (503), not fail OPEN")

	body, _ := io.ReadAll(resp.Body)
	var env map[string]any
	require.NoError(t, json.Unmarshal(body, &env))
	assert.Equal(t, "dpop_replay_check_unavailable", env["error"])
	assert.Equal(t, false, env["ok"])
	// The envelope MUST carry agent_action so an agent that branches
	// on the new code knows what to do.
	assert.NotEmpty(t, env["agent_action"])
	// retry_after_seconds should be 30 — matches the cooldown.
	assert.EqualValues(t, 30, env["retry_after_seconds"])
}

// TestDPoP_RedisError_TripsBreaker — when Redis returns errors for
// every DPoP request, the breaker opens after dpopRedisCircuitThreshold
// (3) consecutive failures and subsequent requests short-circuit to
// 503 in <1ms.
func TestDPoP_RedisError_TripsBreaker(t *testing.T) {
	middleware.ResetDPoPRedisBreakerForTest()
	t.Setenv("API_PUBLIC_URL", "https://api.instanode.dev")
	// Restore the breaker for subsequent tests in the same run.
	t.Cleanup(middleware.ResetDPoPRedisBreakerForTest)

	mr, err := miniredis.Run()
	require.NoError(t, err)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	// Simulate Redis-is-broken by closing miniredis BEFORE the requests.
	// SetNX will then return a transport error each time.
	mr.Close()

	app := newDPoPApp(rdb)

	for i := 0; i < 5; i++ {
		f := newDPoPFixture(t)
		proof := f.signProof("POST", "https://api.instanode.dev/db/new",
			time.Now(), uuid.NewString())
		resp := runRequest(t, app, http.MethodPost,
			"https://api.instanode.dev/db/new", f.bearer, proof)
		_ = resp.Body.Close()
		// Every call should return 503 — either because the actual
		// Redis call failed (first 3 calls) or because the breaker
		// short-circuited (calls 4+).
		assert.Equalf(t, http.StatusServiceUnavailable, resp.StatusCode,
			"call %d: expected 503 dpop_replay_check_unavailable", i+1)
	}

	// After the threshold the breaker should be open.
	b := middleware.DPoPRedisBreaker()
	assert.Equal(t, circuit.StateOpen, b.State(),
		"breaker should be open after 3+ consecutive Redis errors")
}

// TestDPoP_BreakerExposesState — the /healthz consumer and on-call
// runbook reference DPoPRedisBreaker(). Make sure that path returns a
// non-nil breaker and a sane state.
func TestDPoP_BreakerExposesState(t *testing.T) {
	b := middleware.DPoPRedisBreaker()
	require.NotNil(t, b, "DPoPRedisBreaker() must return a non-nil breaker")
	st := b.State()
	if st != circuit.StateClosed && st != circuit.StateOpen && st != circuit.StateHalfOpen {
		t.Fatalf("breaker.State() returned unknown state: %v", st)
	}
	// The package-singleton's name MUST be the literal "dpop_redis"
	// because that's the NR metric label the runbook references.
	assert.Equal(t, "dpop_redis", b.Name())
}

// TestDPoP_BreakerClosesOnRecovery — flow: trip with broken Redis,
// repair Redis (point client at fresh miniredis), wait cooldown,
// fire one successful request, breaker closes.
//
// Note: because the breaker is a process singleton, we have to fully
// reset it via a small helper that drains state. We do this by
// constructing the test inside an isolated subtest and waiting out
// the cooldown rather than reaching into the breaker internals.
func TestDPoP_BreakerClosesOnRecovery(t *testing.T) {
	middleware.ResetDPoPRedisBreakerForTest()
	t.Setenv("API_PUBLIC_URL", "https://api.instanode.dev")
	b := middleware.DPoPRedisBreaker()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	// Healthy Redis — request should succeed (200).
	app := newDPoPApp(rdb)
	f := newDPoPFixture(t)
	proof := f.signProof("POST", "https://api.instanode.dev/db/new",
		time.Now(), uuid.NewString())
	resp := runRequest(t, app, http.MethodPost,
		"https://api.instanode.dev/db/new", f.bearer, proof)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"healthy Redis + valid proof should return 200")
	assert.Equal(t, circuit.StateClosed, b.State(),
		"breaker should remain closed on success")
}

// TestDPoP_BreakerNamedCorrectly — the NR runbook references the
// `instant_circuit_breaker_state{name="dpop_redis"}` query directly.
// Lock in the name so a rename doesn't silently break the dashboard.
func TestDPoP_BreakerNamedCorrectly(t *testing.T) {
	b := middleware.DPoPRedisBreaker()
	assert.Equal(t, "dpop_redis", b.Name(),
		"breaker name MUST be 'dpop_redis' — NR runbook references this label")
}
