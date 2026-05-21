package db

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"instant.dev/internal/metrics"
)

// StartPoolStatsExporter samples *sql.DB.Stats every 5s and re-publishes
// the relevant numbers onto the `instant_pg_pool_*` Prometheus gauges
// (in metrics/metrics.go). It blocks until ctx is cancelled and returns.
//
// Wave-3 chaos verify (2026-05-21) revealed that a 50-concurrent
// /db/new burst could exhaust the DigitalOcean Managed Postgres pool
// without ANY signal in /metrics — operators learned about it from
// downstream worker errors (`event_email_forwarder` failing with
// "remaining connection slots are reserved for non-replication
// superuser connections"). This exporter closes that observability
// gap.
//
// The 5-second sample interval is intentional:
//   - Fast enough to see a 50-burst saturate the pool and resolve.
//   - Slow enough that the Stats() call (a Mutex lock + struct read)
//     is cost-effective on Prom-scrape size.
//
// Callers wire this from main.go AFTER db.ConnectPostgres returns, e.g.
//
//	go db.StartPoolStatsExporter(ctx, platformDB, "platform_db")
//
// The label is the pool's logical name — `platform_db` is the api's
// main pool; future pools (e.g. a read replica) get a different
// label. Cardinality is bounded (one label value per pool the process
// owns), so this never leaks into a high-cardinality explosion.
func StartPoolStatsExporter(ctx context.Context, pool *sql.DB, label string) {
	if pool == nil {
		slog.Warn("db.pool_metrics.skip — nil pool", "label", label)
		return
	}

	const interval = 5 * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	slog.Info("db.pool_metrics.exporter_started",
		"label", label,
		"interval", interval.String(),
	)

	// Emit one sample immediately so the gauge has a value before the
	// first scrape window — a fresh process otherwise shows zero (which
	// Prom rules can't distinguish from "process unreachable").
	publishStats(pool, label)

	for {
		select {
		case <-ctx.Done():
			slog.Info("db.pool_metrics.exporter_stopped", "label", label)
			return
		case <-ticker.C:
			publishStats(pool, label)
		}
	}
}

// publishStats reads pool.Stats() and updates the metrics gauges.
// Exported as a free function (not a method) so tests can call it
// directly without spinning up a ticker.
func publishStats(pool *sql.DB, label string) {
	s := pool.Stats()
	metrics.PGPoolInUse.WithLabelValues(label).Set(float64(s.InUse))
	metrics.PGPoolIdle.WithLabelValues(label).Set(float64(s.Idle))
	metrics.PGPoolOpen.WithLabelValues(label).Set(float64(s.OpenConnections))
	metrics.PGPoolMax.WithLabelValues(label).Set(float64(s.MaxOpenConnections))
	metrics.PGPoolWaitCount.WithLabelValues(label).Set(float64(s.WaitCount))
	metrics.PGPoolWaitDurationSeconds.WithLabelValues(label).Set(s.WaitDuration.Seconds())
}
