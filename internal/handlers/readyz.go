// /readyz — deep, component-by-component readiness probe for the api.
//
// Wired to the k8s readinessProbe (not livenessProbe). A failed critical
// component (platform_db / provisioner_grpc) returns 503 + overall=failed
// → kubelet pulls the pod from the Service endpoints, no SIGKILL. A
// failed non-critical component (brevo / razorpay / do_spaces) stays at
// 200 + overall=degraded so the pod keeps serving while the NR alert
// fires for the operator.
//
// This is the surface the Brevo silent-rejection bug from 2026-05-20
// would have caught WEEKS earlier — Brevo's /v3/account would have
// returned 401 (auth_401, degraded status, NR alert "any component
// failed/degraded > 5 min").
//
// CONTRACT — the per-check selection and Critical marking is hard-coded
// here (NOT env-tunable) because a misconfigured criticality matrix is
// worse than no /readyz: an operator who turns off the platform_db
// critical flag could ship a pod that 200-degraded-forever while the
// platform DB is down. Changes go through this file + the registry test
// below.
package handlers

import (
	"context"
	"database/sql"
	"encoding/base64"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"

	"instant.dev/common/buildinfo"
	"instant.dev/common/readiness"
	"instant.dev/internal/config"
	"instant.dev/internal/metrics"
	"instant.dev/internal/provisioner"
)

// ReadyzHandler bundles the dependencies the readiness checks need and
// exposes a Fiber-style handler that mounts on the existing router.
//
// The handler owns its readiness.Runner — a single Runner per process
// so the per-check cache is shared across concurrent probe arrivals
// (k8s default periodSeconds=10 means ~6 probes/min/pod even before
// the Service endpoint count or HPA scale enter the math).
type ReadyzHandler struct {
	runner *readiness.Runner
	cfg    *config.Config
	db     *sql.DB
	rdb    *redis.Client
	prov   *provisioner.Client
	// http is the shared HTTP client used for Brevo/Razorpay/DO Spaces
	// probes. Sharing it avoids spinning up a new transport per probe
	// (each transport leaks an idle connection pool until GC).
	http *http.Client
	// draining flips to true on graceful shutdown (MR-P0-7).
	draining atomic.Bool
}

// NewReadyzHandler wires the runner. Pass the same db/rdb/cfg/prov the
// router already holds. The runner is constructed eagerly so the first
// probe arrival doesn't pay for handler init under timeout pressure.
//
// The OBJECT_STORE_PUBLIC_URL is preferred for the do_spaces probe
// because it is the customer-facing URL — a probe against the in-cluster
// endpoint would still work even if egress to the public bucket were
// broken, which would defeat the point.
func NewReadyzHandler(cfg *config.Config, db *sql.DB, rdb *redis.Client, prov *provisioner.Client) *ReadyzHandler {
	h := &ReadyzHandler{
		cfg:  cfg,
		db:   db,
		rdb:  rdb,
		prov: prov,
		http: &http.Client{Timeout: 5 * time.Second},
	}
	h.runner = readiness.NewRunner(
		readiness.Config{
			Service: "instant-api",
			// 10s cache matches the k8s default readinessProbe
			// periodSeconds=10 → ~1 upstream call per check per period.
			CacheTTL:       10 * time.Second,
			OverallTimeout: 3 * time.Second,
			Metrics:        readyzMetrics{},
		},
		h.buildChecks(),
	)
	return h
}

// buildChecks is the canonical registry. Adding a new upstream means
// adding a row here AND a test in readyz_test.go that asserts it's
// surfaced. The Critical column is the bit that decides whether a
// failed status pulls the pod from the Service.
func (h *ReadyzHandler) buildChecks() []readiness.Check {
	checks := []readiness.Check{
		// platform_db — the api's primary DB. If this is down, every
		// authenticated route 500s; pull the pod from rotation.
		{
			Name:     "platform_db",
			Critical: true,
			Fn:       readiness.PingDB(h.db, 2*time.Second),
		},
		// provisioner_grpc — without it, /db/new /cache/new /nosql/new
		// /queue/new all 503 immediately; pull the pod from rotation.
		{
			Name:     "provisioner_grpc",
			Critical: true,
			Fn:       readiness.GRPCHealth(h.prov, 2*time.Second),
		},
		// redis — used for rate limiting and dedup. Critical=false
		// because the api fails open on Redis errors (every rate-limit
		// path returns "allowed" on Redis fault, per CLAUDE.md rule 1).
		// A Redis outage degrades the pod but should NOT pull it out.
		{
			Name:     "redis",
			Critical: false,
			Fn:       readiness.PingRedis(redisPinger{h.rdb}, time.Second),
		},
	}

	// customer_db — only checked when CustomerDatabaseURL is set. The
	// adapter dials a tiny pool just for the ping; production already
	// keeps an open pool through resource handlers.
	if h.cfg.CustomerDatabaseURL != "" {
		checks = append(checks, readiness.Check{
			Name:     "customer_db",
			Critical: false, // customer-DB outage degrades, doesn't kill
			Fn:       h.customerDBCheck(),
		})
	}

	// brevo — the silent-rejection surface from 2026-05-20. Probes
	// /v3/account with the api-key header. 401 → degraded (auth
	// broken, would-have-caught-it); 5xx → failed; reachable → ok.
	if h.cfg.BrevoAPIKey != "" {
		checks = append(checks, readiness.Check{
			Name:     "brevo",
			Critical: false,
			Fn: readiness.HTTPHeadCheck(h.http, "GET",
				"https://api.brevo.com/v3/account",
				map[string]string{"api-key": h.cfg.BrevoAPIKey, "accept": "application/json"},
				3*time.Second),
		})
	}

	// razorpay — gates the payment funnel. Non-critical: if Razorpay
	// is down we still want the api serving reads + provisioning. The
	// /v1/payments endpoint requires basic auth; a probe with a valid
	// key returns 200 with an empty page list. HEAD isn't supported,
	// so we GET with a count=1 to keep the response tiny.
	if h.cfg.RazorpayKeyID != "" && h.cfg.RazorpayKeySecret != "" {
		// Build the basic-auth header inline. Format per RFC 7617:
		//   Authorization: Basic base64("key_id:key_secret")
		// We do this here rather than rely on http.NewRequest + SetBasicAuth
		// so the per-probe path stays allocation-light (one alloc for the
		// base64 string vs four for the Request struct).
		creds := base64.StdEncoding.EncodeToString([]byte(h.cfg.RazorpayKeyID + ":" + h.cfg.RazorpayKeySecret))
		checks = append(checks, readiness.Check{
			Name:     "razorpay",
			Critical: false,
			Fn: readiness.HTTPHeadCheck(h.http, "GET",
				"https://api.razorpay.com/v1/payments?count=1",
				map[string]string{"Authorization": "Basic " + creds},
				3*time.Second),
		})
	}

	// do_spaces — the object-store backend. Non-critical because the
	// agent API stays useful even when /storage/new is down. HEAD the
	// configured PUBLIC URL so we test what customers actually hit.
	if h.cfg.ObjectStorePublicURL != "" {
		checks = append(checks, readiness.Check{
			Name:     "do_spaces",
			Critical: false,
			Fn: readiness.HTTPHeadCheck(h.http, "HEAD",
				h.cfg.ObjectStorePublicURL,
				nil,
				3*time.Second),
		})
	}

	return checks
}

// Get is the Fiber handler. It defers to readiness.Handler under the
// hood but adapts the net/http body to Fiber's response writer.
//
// Mounted at GET /readyz in router.go.
//
// When draining (MarkDraining called during graceful shutdown), Get
// short-circuits to 503 + overall=failed so the kubelet's readiness
// probe pulls the pod from Service endpoints before the listener
// stops accepting new connections (MR-P0-7).
func (h *ReadyzHandler) Get(c *fiber.Ctx) error {
	if h.draining.Load() {
		c.Set("Cache-Control", "no-store")
		c.Status(http.StatusServiceUnavailable)
		return c.JSON(readiness.Response{
			Overall:  readiness.StatusFailed,
			Service:  "instant-api",
			CommitID: buildinfo.GitSHA,
			Checks: []readiness.CheckResult{{
				Name:        "shutting_down",
				Status:      readiness.StatusFailed,
				LastError:   "draining",
				LastCheckAt: time.Now(),
			}},
		})
	}
	resp, code := h.runner.Run(c.UserContext())
	c.Set("Cache-Control", "no-store")
	c.Status(code)
	return c.JSON(resp)
}

// MarkDraining flips the handler into drain mode. Subsequent /readyz
// probes return 503 + overall=failed. Idempotent.
func (h *ReadyzHandler) MarkDraining() { h.draining.Store(true) }

// IsDraining reports whether MarkDraining has been called.
func (h *ReadyzHandler) IsDraining() bool { return h.draining.Load() }

// customerDBCheck builds a CheckFunc that opens a one-shot pool against
// the customer DB. The pool is closed on every call — the cache window
// keeps the open-rate low (one dial per 10s under default config).
//
// We intentionally do NOT cache a long-lived *sql.DB here: the customer
// DB is the provisioner's domain, not the api's. Borrowing its
// connection slots for a probe would steal capacity from real customer
// resources.
func (h *ReadyzHandler) customerDBCheck() readiness.CheckFunc {
	return func(ctx context.Context) readiness.CheckResult {
		callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		dsn := h.cfg.CustomerDatabaseURL
		if dsn == "" {
			return readiness.CheckResult{Status: readiness.StatusFailed, LastError: "customer_db_not_configured"}
		}
		db, err := readyzSQLOpen("postgres", dsn)
		if err != nil {
			return readiness.CheckResult{Status: readiness.StatusFailed, LastError: "open_failed"}
		}
		defer db.Close()
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(0)
		if err := db.PingContext(callCtx); err != nil {
			return readiness.CheckResult{Status: readiness.StatusFailed, LastError: "ping_failed"}
		}
		return readiness.CheckResult{Status: readiness.StatusOK}
	}
}

// readyzSQLOpen is a seam over sql.Open for the customer-DB readiness check.
// lib/pq's Open is fully lazy and never errors on a DSN, so the open-failure
// arm of customerDBCheck (a defensive guard for a future eager driver) is
// only reachable in tests via this var.
var readyzSQLOpen = sql.Open

// redisPinger adapts *redis.Client to the readiness.Pinger interface.
// We keep the adapter in this file (not common/) so common/ doesn't
// pull in go-redis.
type redisPinger struct{ r *redis.Client }

func (p redisPinger) Ping(ctx context.Context) readiness.PingResult {
	if p.r == nil {
		return redisFailedPing{}
	}
	return p.r.Ping(ctx)
}

type redisFailedPing struct{}

func (redisFailedPing) Err() error { return errRedisNil }

// errRedisNil is the synthetic error returned when the redis client is
// nil. Distinct from a real Redis error so /readyz can surface the
// configuration problem.
var errRedisNil = errStaticString("redis_client_nil")

type errStaticString string

func (e errStaticString) Error() string { return string(e) }

// readyzMetrics is the Prometheus hook. Registered with the package-
// level metrics registry so /metrics exposes the gauge series. Backed
// by a sync.Once-guarded gauge created at first probe (so a service
// that never sets ENVIRONMENT enabled paths doesn't register a gauge
// with no series).
type readyzMetrics struct{}

func (readyzMetrics) Observe(name string, status readiness.Status) {
	metrics.ReadyzCheckStatus(name, statusToFloat(status))
}

func statusToFloat(s readiness.Status) float64 {
	switch s {
	case readiness.StatusOK:
		return 1
	case readiness.StatusDegraded:
		return 0.5
	default:
		return 0
	}
}

// Ensure the redisFailedPing satisfies readiness.PingResult at compile
// time. The function is never called — it just pins the contract.
var _ readiness.PingResult = redisFailedPing{}
