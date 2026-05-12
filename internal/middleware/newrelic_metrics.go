package middleware

import (
	"github.com/newrelic/go-agent/v3/newrelic"
)

// Phase-1 custom-metric names. These match the design doc
// (OBSERVABILITY-PLAN-2026-05-12.md → "Custom metrics") so the NR
// dashboards Track 7 ships can pre-bake their queries.
const (
	metricProvisionSuccess = "Custom/Provision/Success"
	metricProvisionFail    = "Custom/Provision/Fail"
	metricResourceExpired  = "Custom/Resource/Expired"
)

// nrAppGlobal is set once at startup from main and read by the emit
// helpers below. Storing the application on a package var lets handler
// code call a single-arg helper (RecordProvisionSuccess("postgres"))
// instead of threading the app through every constructor — Track 3's
// scope explicitly excludes handler signature changes.
//
// nil when the agent is disabled; emit helpers no-op in that case.
var nrAppGlobal *newrelic.Application

// SetNRApp registers the process-wide New Relic application. Called
// exactly once from main.go after newrelic.NewApplication succeeds.
// Safe to pass nil — emit helpers degrade to no-ops.
func SetNRApp(app *newrelic.Application) {
	nrAppGlobal = app
}

// recordOne emits a single increment of the named NR custom metric
// scoped to the service ("api"). The agent batches and flushes on its
// own schedule; this call is non-blocking.
func recordOne(name string, count float64) {
	if nrAppGlobal == nil {
		return
	}
	nrAppGlobal.RecordCustomMetric(name, count)
}

// RecordProvisionSuccess increments Custom/Provision/Success and tags
// the resource family (postgres/redis/mongodb/queue/storage/webhook).
// The family tag lets the NR dashboard break down success rate per
// service without exploding metric cardinality (NR caps at 2k unique
// metric names per minute).
//
// Called from handlers (deploy.go, db.go, cache.go, ...) right after a
// successful provision. Handler files are NOT modified as part of
// Track 3 — this helper exists for those handlers to call once they
// adopt it in a follow-up.
func RecordProvisionSuccess(family string) {
	if nrAppGlobal == nil {
		return
	}
	recordOne(metricProvisionSuccess, 1)
	recordOne(metricProvisionSuccess+"/"+family, 1)
}

// RecordProvisionFail increments Custom/Provision/Fail and tags the
// resource family plus a short reason ("quota", "backend_unavailable",
// "internal"). The reason tag is the same enum used by the
// `error_reason` slog field so log lines and metrics can be joined.
func RecordProvisionFail(family, reason string) {
	if nrAppGlobal == nil {
		return
	}
	recordOne(metricProvisionFail, 1)
	recordOne(metricProvisionFail+"/"+family, 1)
	if reason != "" {
		recordOne(metricProvisionFail+"/"+reason, 1)
	}
}

// RecordResourceExpired increments Custom/Resource/Expired with a
// resource-family tag. Called from the worker's expiry job once the
// expire run finishes; the helper lives here (api/middleware/) because
// the worker also imports `instant.dev/internal/middleware` for the
// shared NR helpers — Track 4 will wire the actual call.
func RecordResourceExpired(family string) {
	if nrAppGlobal == nil {
		return
	}
	recordOne(metricResourceExpired, 1)
	recordOne(metricResourceExpired+"/"+family, 1)
}
