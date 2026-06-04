package handlers_test

// status_realdb_integration_test.go — REAL-DB + REAL-Redis integration coverage
// for GET /api/v1/status (handlers.StatusHandler).
//
// WHY (integration-coverage wave 1, 2026-06-04):
//
// status_test.go / status_final_test.go drive the handler entirely through
// sqlmock — they assert the SELECT strings but never prove the in-memory
// bucketing (15-min slots, current_status derivation, 7d/30d uptime percent)
// is correct against real rows pulled through a real Postgres driver, nor that
// the cache.GetOrSet round-trip against real Redis works end to end.
//
// These tests seed real service_components + uptime_samples rows, hit the
// public endpoint through a Fiber app wired to a real *sql.DB + *redis.Client,
// and assert the computed payload (current_status, uptime percentages, cache
// behaviour). Skipped (not failed) when the test DB/Redis are unreachable so
// the hermetic `-short` gate stays green; CI supplies both.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"

	"instant.dev/internal/handlers"
	"instant.dev/internal/testhelpers"
)

// statusComponentResp mirrors the public per-component shape (subset asserted).
type statusComponentResp struct {
	Slug           string  `json:"slug"`
	Name           string  `json:"name"`
	Category       string  `json:"category"`
	CurrentStatus  string  `json:"current_status"`
	Uptime7dPct    float64 `json:"uptime_7d_pct"`
	Uptime30dPct   float64 `json:"uptime_30d_pct"`
	Last24hSamples []bool  `json:"last_24h_samples"`
}

type statusResp struct {
	OK               bool                  `json:"ok"`
	FreshnessSeconds int                   `json:"freshness_seconds"`
	Components       []statusComponentResp `json:"components"`
	CurrentIncidents []json.RawMessage     `json:"current_incidents"`
}

// statusRealApp mounts GET /api/v1/status wired to real DB + Redis, matching
// the production registration (public, no auth).
func statusRealApp(t *testing.T, app *fiber.App, h *handlers.StatusHandler) {
	t.Helper()
	app.Get("/api/v1/status", h.Get)
}

// getStatus issues GET /api/v1/status and decodes the payload.
func getStatus(t *testing.T, app *fiber.App) (*http.Response, statusResp) {
	t.Helper()
	resp := testhelpers.GetReq(t, app, "/api/v1/status")
	var sr statusResp
	if resp.StatusCode == http.StatusOK {
		testhelpers.DecodeJSON(t, resp, &sr)
	}
	return resp, sr
}

// ── 1. operational component: all-healthy samples → operational + 100% uptime ──

func TestStatus_RealDB_OperationalComponent(t *testing.T) {
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	rdb, rcleanup := testhelpers.SetupTestRedis(t)
	defer rcleanup()

	ctx := context.Background()
	slug := "api-int-" + time.Now().Format("150405.000000")
	if _, err := db.ExecContext(ctx, `INSERT INTO service_components (slug, display_name, category, description)
		VALUES ($1, 'API (integration)', 'core', 'agent-facing API')`, slug); err != nil {
		t.Fatalf("seed component: %v", err)
	}
	// 30 healthy samples over the last 2 hours.
	now := time.Now().UTC()
	for i := 0; i < 30; i++ {
		ts := now.Add(-time.Duration(i) * 4 * time.Minute)
		if _, err := db.ExecContext(ctx, `INSERT INTO uptime_samples (component_slug, sampled_at, healthy, latency_ms)
			VALUES ($1, $2, true, 12)`, slug, ts); err != nil {
			t.Fatalf("seed sample: %v", err)
		}
	}

	app := fiber.New()
	statusRealApp(t, app, handlers.NewStatusHandler(db, rdb))

	resp, sr := getStatus(t, app)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200", resp.StatusCode)
	}
	if !sr.OK {
		t.Error("payload ok must be true")
	}
	comp := findComponent(t, sr, slug)
	if comp.CurrentStatus != "operational" {
		t.Errorf("current_status = %q; want operational (all probes healthy)", comp.CurrentStatus)
	}
	if comp.Uptime7dPct != 100 {
		t.Errorf("uptime_7d_pct = %v; want 100", comp.Uptime7dPct)
	}
	if len(comp.Last24hSamples) != 96 {
		t.Errorf("last_24h_samples len = %d; want 96", len(comp.Last24hSamples))
	}
}

// ── 2. degraded/down component: a recent unhealthy probe drives current_status
//        off "operational" and depresses the uptime percentage. ──

func TestStatus_RealDB_UnhealthyComponentReflected(t *testing.T) {
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	rdb, rcleanup := testhelpers.SetupTestRedis(t)
	defer rcleanup()

	ctx := context.Background()
	slug := "worker-int-" + time.Now().Format("150405.000000")
	if _, err := db.ExecContext(ctx, `INSERT INTO service_components (slug, display_name, category)
		VALUES ($1, 'Worker (integration)', 'core')`, slug); err != nil {
		t.Fatalf("seed component: %v", err)
	}
	now := time.Now().UTC()
	// Most-recent slot: a single unhealthy probe → 0% healthy → "down".
	if _, err := db.ExecContext(ctx, `INSERT INTO uptime_samples (component_slug, sampled_at, healthy)
		VALUES ($1, $2, false)`, slug, now.Add(-1*time.Minute)); err != nil {
		t.Fatalf("seed unhealthy: %v", err)
	}
	// Some older healthy probes so the 7d window isn't all-bad.
	for i := 1; i <= 9; i++ {
		if _, err := db.ExecContext(ctx, `INSERT INTO uptime_samples (component_slug, sampled_at, healthy)
			VALUES ($1, $2, true)`, slug, now.Add(-time.Duration(i)*time.Hour)); err != nil {
			t.Fatalf("seed healthy: %v", err)
		}
	}

	app := fiber.New()
	statusRealApp(t, app, handlers.NewStatusHandler(db, rdb))

	resp, sr := getStatus(t, app)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200", resp.StatusCode)
	}
	comp := findComponent(t, sr, slug)
	// The most-recent slot is 1/1 unhealthy → below the 50% degraded cutoff → "down".
	if comp.CurrentStatus != "down" {
		t.Errorf("current_status = %q; want down (most recent probe unhealthy)", comp.CurrentStatus)
	}
	// 7d uptime: 9 healthy / 10 total = 90%.
	if comp.Uptime7dPct <= 0 || comp.Uptime7dPct >= 100 {
		t.Errorf("uptime_7d_pct = %v; want a partial value in (0,100) reflecting the unhealthy probe", comp.Uptime7dPct)
	}
}

// ── 3. empty DB (no components) → ok:true, zero components, no incidents. The
//        public status page must render a clean empty state, never a 500. ──

func TestStatus_RealDB_EmptyComponentsCleanState(t *testing.T) {
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	rdb, rcleanup := testhelpers.SetupTestRedis(t)
	defer rcleanup()

	// Ensure no components leak in from a reused DB.
	if _, err := db.ExecContext(context.Background(), `DELETE FROM uptime_samples`); err != nil {
		t.Fatalf("clear samples: %v", err)
	}
	if _, err := db.ExecContext(context.Background(), `DELETE FROM service_components`); err != nil {
		t.Fatalf("clear components: %v", err)
	}

	app := fiber.New()
	statusRealApp(t, app, handlers.NewStatusHandler(db, rdb))

	resp, sr := getStatus(t, app)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200 (empty state, never 500)", resp.StatusCode)
	}
	if !sr.OK {
		t.Error("ok must be true even with no components")
	}
	if len(sr.Components) != 0 {
		t.Errorf("components = %d; want 0", len(sr.Components))
	}
	if sr.CurrentIncidents == nil {
		t.Error("current_incidents must serialise as [] (non-nil), not null")
	}
	if sr.FreshnessSeconds != 60 {
		t.Errorf("freshness_seconds = %d; want 60", sr.FreshnessSeconds)
	}
}

// ── 4. cache round-trip: the SECOND request is served from Redis. We prove the
//        cache.GetOrSet write/read path by mutating the DB after the first
//        request and asserting the second request still returns the CACHED
//        (pre-mutation) payload, then a fresh handler (cold cache key) sees the
//        new row. This exercises the real Redis serialise/deserialise path that
//        sqlmock tests can't reach. ──

func TestStatus_RealDB_CacheServesSecondRequest(t *testing.T) {
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	rdb, rcleanup := testhelpers.SetupTestRedis(t)
	defer rcleanup()
	ctx := context.Background()

	// Clean slate so the cached payload is deterministic.
	if _, err := db.ExecContext(ctx, `DELETE FROM uptime_samples`); err != nil {
		t.Fatalf("clear samples: %v", err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM service_components`); err != nil {
		t.Fatalf("clear components: %v", err)
	}
	// Make sure the shared status cache key is cold before we begin.
	rdb.Del(ctx, "status:public:v1")

	slug := "edge-int-" + time.Now().Format("150405.000000")
	if _, err := db.ExecContext(ctx, `INSERT INTO service_components (slug, display_name, category)
		VALUES ($1, 'Edge (integration)', 'edge')`, slug); err != nil {
		t.Fatalf("seed component: %v", err)
	}

	app := fiber.New()
	statusRealApp(t, app, handlers.NewStatusHandler(db, rdb))

	// First request: cache miss → computes from DB (1 component) → writes Redis.
	_, sr1 := getStatus(t, app)
	if len(sr1.Components) != 1 {
		t.Fatalf("first request components = %d; want 1", len(sr1.Components))
	}

	// Mutate the DB: add a second component. A cache HIT must NOT see it.
	slug2 := "edge2-int-" + time.Now().Format("150405.000000")
	if _, err := db.ExecContext(ctx, `INSERT INTO service_components (slug, display_name, category)
		VALUES ($1, 'Edge2 (integration)', 'edge')`, slug2); err != nil {
		t.Fatalf("seed component 2: %v", err)
	}

	// Second request within the 60s TTL: served from Redis → still 1 component.
	_, sr2 := getStatus(t, app)
	if len(sr2.Components) != 1 {
		t.Errorf("second request components = %d; want 1 (must be served from the 60s Redis cache, NOT recomputed)", len(sr2.Components))
	}

	// Cold the cache key → a fresh compute now sees BOTH components, proving the
	// DB mutation was real and only the cache masked it.
	rdb.Del(ctx, "status:public:v1")
	_, sr3 := getStatus(t, app)
	if len(sr3.Components) != 2 {
		t.Errorf("after cache bust components = %d; want 2 (the second component must surface once the cache key is cold)", len(sr3.Components))
	}
}

// ── 5. Redis-down (nil client): compute falls through to the DB. The status
//        page must stay up when the cache is degraded — which is exactly when
//        operators most need an honest reading. ──

func TestStatus_RealDB_NilRedisFallsThroughToDB(t *testing.T) {
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	slug := "prov-int-" + time.Now().Format("150405.000000")
	if _, err := db.ExecContext(ctx, `INSERT INTO service_components (slug, display_name, category)
		VALUES ($1, 'Provisioner (integration)', 'core')`, slug); err != nil {
		t.Fatalf("seed component: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO uptime_samples (component_slug, sampled_at, healthy)
		VALUES ($1, now(), true)`, slug); err != nil {
		t.Fatalf("seed sample: %v", err)
	}

	app := fiber.New()
	// nil Redis — cache.GetOrSet degrades to a per-request DB fetch.
	statusRealApp(t, app, handlers.NewStatusHandler(db, (*redis.Client)(nil)))

	resp, sr := getStatus(t, app)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200 even with Redis down", resp.StatusCode)
	}
	if findComponent(t, sr, slug).Slug != slug {
		t.Errorf("seeded component %q missing from DB-fallback payload", slug)
	}
}

// findComponent returns the component with the given slug, failing the test if
// it is absent.
func findComponent(t *testing.T, sr statusResp, slug string) statusComponentResp {
	t.Helper()
	for _, c := range sr.Components {
		if c.Slug == slug {
			return c
		}
	}
	t.Fatalf("component %q not found in status payload (%d components)", slug, len(sr.Components))
	return statusComponentResp{}
}
