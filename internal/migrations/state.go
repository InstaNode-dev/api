// Package migrations exposes the DB's migration-tracking state to the
// /healthz handler. The source of truth is the schema_migrations table
// created by migration 022_schema_migrations.sql and populated by
// db.RunMigrations. This package is read-only — it never writes.
//
// Caching: GET /healthz is hit on every kube readiness probe (typically
// once per second per pod) and by external canaries. A naïve "query
// the DB on every probe" would put one extra row read per second per pod
// on the platform DB plus measurable latency on a path that the design
// doc requires to stay <10ms p99. We cache the (filename, count) pair
// for cacheTTL (60s) per process — the worst-case staleness window after
// a fresh deploy is one minute, which is shorter than any meaningful
// alarm threshold.
//
// Failure mode: when the DB is unreachable or the schema_migrations
// table doesn't exist yet (race on first boot, pre-022 binary), we
// return (statusUnknown, "", 0, err). The /healthz handler converts
// that into migration_status: "unknown" while still returning 200 OK —
// the service is up, we just can't read the tracking row.
package migrations

import (
	"context"
	"database/sql"
	"sync"
	"time"
)

// Status values surfaced on the /healthz response. Wire-stable strings.
const (
	StatusOK      = "ok"
	StatusUnknown = "unknown"
)

// defaultTTL is the per-process cache window. Tuned to absorb readiness-
// probe traffic (~60 probes/min/pod) into one DB read per pod per minute.
const defaultTTL = 60 * time.Second

// State is the public-facing snapshot the /healthz handler emits.
type State struct {
	Status   string // "ok" or "unknown"
	Filename string // highest-applied migration filename; "" when unknown
	Count    int    // total rows in schema_migrations; 0 when unknown
}

// Reader caches one State per process with a TTL. Safe for concurrent use.
// Clock is injectable so tests can advance time without sleeping.
type Reader struct {
	db    *sql.DB
	ttl   time.Duration
	clock func() time.Time

	mu      sync.Mutex
	cached  State
	expires time.Time
}

// NewReader builds a Reader backed by db. ttl <= 0 means use defaultTTL.
// clock nil means time.Now.
func NewReader(db *sql.DB, ttl time.Duration, clock func() time.Time) *Reader {
	if ttl <= 0 {
		ttl = defaultTTL
	}
	if clock == nil {
		clock = time.Now
	}
	return &Reader{db: db, ttl: ttl, clock: clock}
}

// Get returns the cached State, refreshing from the DB if the TTL has
// elapsed. On DB error returns the previous cached value with status
// flipped to "unknown" (and an empty filename/count if never seeded) so
// the caller always gets a usable State — never blocks /healthz on a DB
// outage.
//
// P2 (BugBash 2026-05-18): the mutex is NEVER held across the (up-to-2s)
// queryState DB call. The old code took r.mu for the whole method, so a
// slow DB serialized every concurrent /healthz probe behind one lock —
// readiness probes piled up and the pod flapped. Now the lock only guards
// the in-memory cache read and write; the DB IO happens lock-free. A
// short window of N concurrent refreshes during a TTL expiry is acceptable
// (each probe is independent and the result is idempotent) and far cheaper
// than serializing every probe.
func (r *Reader) Get(ctx context.Context) State {
	now := r.clock()

	// Fast path: serve the cached value under the lock if still fresh.
	r.mu.Lock()
	if !r.expires.IsZero() && now.Before(r.expires) {
		cached := r.cached
		r.mu.Unlock()
		return cached
	}
	r.mu.Unlock()

	// Refresh: DB IO happens WITHOUT the lock held.
	s, err := queryState(ctx, r.db)

	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		// DB unreachable / schema_migrations missing. Surface "unknown"
		// but keep the TTL — we don't want to hammer a sick DB on every
		// /healthz hit. Refresh in TTL window with a fresh attempt.
		r.cached = State{Status: StatusUnknown}
		r.expires = r.clock().Add(r.ttl)
		return r.cached
	}
	r.cached = s
	r.expires = r.clock().Add(r.ttl)
	return r.cached
}

// queryState reads the highest-filename row and the total count in one
// roundtrip. Two separate queries kept simple: an ORDER BY ... LIMIT 1
// over the PRIMARY KEY index + a COUNT(*) — both cost one index scan.
func queryState(ctx context.Context, db *sql.DB) (State, error) {
	if db == nil {
		return State{Status: StatusUnknown}, sql.ErrConnDone
	}

	// Bound DB time so /healthz never stalls on a slow DB. The 2s budget
	// is generous against a healthy DB (sub-ms) but caps the blast radius
	// if the connection pool is saturated.
	qctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var filename sql.NullString
	if err := db.QueryRowContext(qctx,
		`SELECT filename FROM schema_migrations ORDER BY filename DESC LIMIT 1`,
	).Scan(&filename); err != nil && err != sql.ErrNoRows {
		return State{Status: StatusUnknown}, err
	}

	var count int
	if err := db.QueryRowContext(qctx,
		`SELECT COUNT(*) FROM schema_migrations`,
	).Scan(&count); err != nil {
		return State{Status: StatusUnknown}, err
	}

	return State{
		Status:   StatusOK,
		Filename: filename.String,
		Count:    count,
	}, nil
}
