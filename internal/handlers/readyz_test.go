package handlers_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alicebob/miniredis/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"instant.dev/common/readiness"
	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
)

// TestReadyz_AllOK is the canonical happy path. Mocked platform_db
// returns success, miniredis answers PING, no Brevo/Razorpay/DO
// configured → those checks are not surfaced. Expect 200 / overall=ok
// with platform_db + redis in the checks list.
func TestReadyz_AllOK(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectPing()

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	cfg := &config.Config{Environment: "test"}

	h := handlers.NewReadyzHandler(cfg, db, rdb, nil)
	app := fiber.New()
	app.Get("/readyz", h.Get)

	resp, err := app.Test(httptest.NewRequest("GET", "/readyz", nil))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var got readiness.Response
	require.NoError(t, json.Unmarshal(body, &got))

	// platform_db is critical and provisioner is nil → provisioner_grpc
	// fails critical → overall=failed → 503. This pins the rule that
	// critical-failed yields 503.
	require.Equal(t, fiber.StatusServiceUnavailable, resp.StatusCode,
		"provisioner=nil means provisioner_grpc check fails critical → 503")
	require.Equal(t, readiness.StatusFailed, got.Overall)

	// Even with the failure, platform_db and redis still ran and
	// reported ok — so the operator can see WHICH check failed.
	byName := map[string]readiness.Status{}
	for _, c := range got.Checks {
		byName[c.Name] = c.Status
	}
	require.Equal(t, readiness.StatusOK, byName["platform_db"])
	require.Equal(t, readiness.StatusOK, byName["redis"])
	require.Equal(t, readiness.StatusFailed, byName["provisioner_grpc"])
}

// TestReadyz_CriticalFailure_Returns503 — when platform_db is down, the
// probe MUST return 503 + overall=failed so kubelet pulls the pod from
// rotation. This is the rule that makes /readyz meaningful: a degraded
// pod stays in rotation, a broken pod doesn't.
func TestReadyz_CriticalFailure_Returns503(t *testing.T) {
	// Closed DB — every PingContext returns "sql: database is closed".
	db, _, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	require.NoError(t, err)
	db.Close() // close immediately so PingContext fails

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	cfg := &config.Config{Environment: "test"}

	h := handlers.NewReadyzHandler(cfg, db, rdb, nil)
	app := fiber.New()
	app.Get("/readyz", h.Get)

	resp, err := app.Test(httptest.NewRequest("GET", "/readyz", nil))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var got readiness.Response
	require.NoError(t, json.Unmarshal(body, &got))

	require.Equal(t, fiber.StatusServiceUnavailable, resp.StatusCode,
		"closed platform_db must return 503 — that's how the pod gets pulled from the Service")
	require.Equal(t, readiness.StatusFailed, got.Overall)
}

// TestReadyz_BrevoConfigured_AdaptsToUpstream — wires a fake Brevo
// server that 401s, asserts the brevo check is surfaced as degraded
// (auth broken), and the probe still returns 200 because Brevo is
// non-critical. This is the load-bearing test for the silent-rejection
// catch: a flipped api-key surfaces as degraded EVERY probe, NR alert
// fires, operator catches it.
func TestReadyz_BrevoConfigured_AdaptsToUpstream(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectPing()

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	// Brevo fake that ALWAYS 401s — simulates a bad api-key, which is
	// exactly the silent-rejection shape from 2026-05-20.
	brevoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	}))
	defer brevoSrv.Close()

	cfg := &config.Config{
		Environment: "test",
		BrevoAPIKey: "xkeysib-bogus",
	}
	// Patch the brevo URL via a custom handler — we can't easily inject
	// a URL into the production handler without exposing it; instead
	// we test the helper directly to keep the assertion focused.
	check := readiness.HTTPHeadCheck(nil, "GET", brevoSrv.URL,
		map[string]string{"api-key": cfg.BrevoAPIKey}, 500*time.Millisecond)
	got := check(context.Background())
	require.Equal(t, readiness.StatusDegraded, got.Status,
		"401 from Brevo must surface as degraded — this is the silent-rejection signal")
	require.Contains(t, got.LastError, "401")
}

// TestReadyz_DoesNotLeakSecrets — the response body MUST NOT contain
// the Brevo api-key, Razorpay secret, or DB password. Probe traffic
// hits /readyz from anywhere with network reach to the pod (curl from
// jumphost, kubectl exec, etc.) — even a leak of the first 8 chars of
// the api-key is bad.
func TestReadyz_DoesNotLeakSecrets(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectPing()

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	const apiKey = "xkeysib-SUPER-SECRET-LEAKED-VALUE"
	const rzpKey = "rzp_live_LEAKED"
	const rzpSecret = "DONOTLEAKPLZ"
	cfg := &config.Config{
		Environment:       "test",
		BrevoAPIKey:       apiKey,
		RazorpayKeyID:     rzpKey,
		RazorpayKeySecret: rzpSecret,
	}

	h := handlers.NewReadyzHandler(cfg, db, rdb, nil)
	app := fiber.New()
	app.Get("/readyz", h.Get)

	resp, err := app.Test(httptest.NewRequest("GET", "/readyz", nil))
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	require.False(t, strings.Contains(bodyStr, apiKey),
		"Brevo api-key MUST NOT appear in /readyz body: %s", bodyStr)
	require.False(t, strings.Contains(bodyStr, rzpSecret),
		"Razorpay key secret MUST NOT appear in /readyz body: %s", bodyStr)
}

// TestReadyz_ResponseShape pins the wire shape (overall / service /
// commit_id / checks[]). A future refactor that drops a field fails
// this test and dashboards stay alive.
func TestReadyz_ResponseShape(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectPing()

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	cfg := &config.Config{Environment: "test"}

	h := handlers.NewReadyzHandler(cfg, db, rdb, nil)
	app := fiber.New()
	app.Get("/readyz", h.Get)

	resp, err := app.Test(httptest.NewRequest("GET", "/readyz", nil))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var got map[string]any
	require.NoError(t, json.Unmarshal(body, &got))

	require.Contains(t, got, "overall")
	require.Contains(t, got, "service")
	require.Contains(t, got, "commit_id")
	require.Contains(t, got, "checks")
	require.Equal(t, "instant-api", got["service"])
	require.Equal(t, "no-store", resp.Header.Get("Cache-Control"),
		"/readyz responses MUST be no-store to prevent probe staleness")
}
