package handlers_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alicebob/miniredis/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"instant.dev/common/readiness"
	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
)

// runReadyz drives the public /readyz handler and returns the decoded body.
func runReadyz(t *testing.T, h *handlers.ReadyzHandler) (int, readiness.Response) {
	t.Helper()
	app := fiber.New()
	app.Get("/readyz", h.Get)
	resp, err := app.Test(httptest.NewRequest("GET", "/readyz", nil), 30000)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var got readiness.Response
	require.NoError(t, json.Unmarshal(body, &got))
	return resp.StatusCode, got
}

func readyzCheckByName(r readiness.Response, name string) (readiness.CheckResult, bool) {
	for _, c := range r.Checks {
		if c.Name == name {
			return c, true
		}
	}
	return readiness.CheckResult{}, false
}

// TestReadyz_CustomerDBCheck_OK covers customerDBCheck happy path (line 251,
// status ok) by calling the CheckFunc directly with a generous context — the
// seam lets us point at the real reachable test DB without competing for the
// runner's 3s overall budget. Skips cleanly when no test DB is configured.
func TestReadyz_CustomerDBCheck_OK(t *testing.T) {
	dsn := os.Getenv("TEST_POSTGRES_CUSTOMERS_URL")
	if dsn == "" {
		dsn = os.Getenv("TEST_DATABASE_URL")
	}
	if dsn == "" {
		t.Skip("no customer DSN configured")
	}

	cfg := &config.Config{Environment: "test", CustomerDatabaseURL: dsn}
	h := handlers.NewReadyzHandler(cfg, nil, nil, nil)

	fn := handlers.CustomerDBCheckForTest(h)
	res := fn(context.Background())
	require.Equal(t, readiness.StatusOK, res.Status, "reachable customer DB → ok")
}

// TestReadyz_CustomerDB_PingFailed covers the PingContext failure arm: a
// valid-looking DSN pointing at a closed port (open succeeds lazily, ping
// fails within the 2s timeout).
func TestReadyz_CustomerDB_PingFailed(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectPing()

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	cfg := &config.Config{
		Environment:         "test",
		CustomerDatabaseURL: "postgres://nobody@127.0.0.1:1/x?sslmode=disable&connect_timeout=1",
	}
	h := handlers.NewReadyzHandler(cfg, db, rdb, nil)

	_, got := runReadyz(t, h)
	cdb, ok := readyzCheckByName(got, "customer_db")
	require.True(t, ok)
	require.Equal(t, readiness.StatusFailed, cdb.Status)
	require.Equal(t, "ping_failed", cdb.LastError)
}

// TestReadyz_NilRedis_FailsRedisCheck covers redisPinger.Ping nil-client arm
// + redisFailedPing.Err()/Error(). A nil *redis.Client makes the redis check
// fail (non-critical → still degraded, not 503-from-redis).
func TestReadyz_NilRedis_FailsRedisCheck(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectPing()

	cfg := &config.Config{Environment: "test"}
	// nil redis client and nil provisioner
	h := handlers.NewReadyzHandler(cfg, db, nil, nil)

	code, got := runReadyz(t, h)
	require.Equal(t, http.StatusServiceUnavailable, code) // provisioner_grpc nil → 503
	rc, ok := readyzCheckByName(got, "redis")
	require.True(t, ok)
	require.Equal(t, readiness.StatusFailed, rc.Status, "nil redis client → redis check fails")
}

// TestReadyz_CustomerDBCheck_EmptyDSN drives the defensive empty-DSN arm of
// customerDBCheck directly (the public path never wires the check with an
// empty DSN, so this seam is the only way to exercise the guard).
func TestReadyz_CustomerDBCheck_EmptyDSN(t *testing.T) {
	cfg := &config.Config{Environment: "test"} // CustomerDatabaseURL == ""
	h := handlers.NewReadyzHandler(cfg, nil, nil, nil)
	fn := handlers.CustomerDBCheckForTest(h)
	res := fn(context.Background())
	require.Equal(t, readiness.StatusFailed, res.Status)
	require.Equal(t, "customer_db_not_configured", res.LastError)
}

// TestReadyz_CustomerDBCheck_OpenFailed drives the sql.Open failure arm via
// the readyzSQLOpen seam (lib/pq's Open is lazy and never errors on a DSN).
func TestReadyz_CustomerDBCheck_OpenFailed(t *testing.T) {
	cfg := &config.Config{Environment: "test", CustomerDatabaseURL: "postgres://x"}
	h := handlers.NewReadyzHandler(cfg, nil, nil, nil)
	restore := handlers.SetReadyzSQLOpenForTest(func(string, string) (*sql.DB, error) {
		return nil, errors.New("driver open boom")
	})
	defer restore()
	fn := handlers.CustomerDBCheckForTest(h)
	res := fn(context.Background())
	require.Equal(t, readiness.StatusFailed, res.Status)
	require.Equal(t, "open_failed", res.LastError)
}

// TestReadyz_StatusToFloat_AllArms walks the status→gauge mapping enum.
func TestReadyz_StatusToFloat_AllArms(t *testing.T) {
	require.Equal(t, 1.0, handlers.StatusToFloatForTest(readiness.StatusOK))
	require.Equal(t, 0.5, handlers.StatusToFloatForTest(readiness.StatusDegraded))
	require.Equal(t, 0.0, handlers.StatusToFloatForTest(readiness.StatusFailed))
}

// TestReadyz_AllUpstreamsConfigured covers the buildChecks branches that add
// brevo / razorpay / do_spaces checks (each gated on config presence). We
// point them at an unreachable host so they fail fast but are still surfaced.
func TestReadyz_AllUpstreamsConfigured(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectPing()

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	cfg := &config.Config{
		Environment:          "test",
		BrevoAPIKey:          "test-brevo-key",
		RazorpayKeyID:        "rzp_test_x",
		RazorpayKeySecret:    "secret",
		ObjectStorePublicURL: "https://s3.example.invalid/bucket",
	}
	h := handlers.NewReadyzHandler(cfg, db, rdb, nil)

	_, got := runReadyz(t, h)
	for _, name := range []string{"brevo", "razorpay", "do_spaces"} {
		_, ok := readyzCheckByName(got, name)
		require.True(t, ok, "check %q should be surfaced when configured", name)
	}
}
