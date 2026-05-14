// Package testhelpers provides shared utilities for integration tests across the instant.dev platform.
// Tests run against real Postgres and Redis — set TEST_DATABASE_URL and TEST_REDIS_URL env vars.
package testhelpers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"

	"instant.dev/internal/config"
	"instant.dev/internal/crypto"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
)

const (
	defaultTestDBURL        = "postgres://postgres:postgres@localhost:5432/instant_dev_test?sslmode=disable"
	defaultTestRedisURL     = "redis://localhost:6379/15" // DB 15 = isolated test keyspace
	defaultTestCustomersURL = "postgres://instant_cust:instant_cust@localhost:5434/instant_customers?sslmode=disable"
)

// TestJWTSecret is the HMAC secret used by all test JWT helpers (≥32 bytes).
const TestJWTSecret = "test-secret-that-is-at-least-32-bytes-long!!"

// TestAESKeyHex is a 32-byte AES-256 key encoded as 64 hex characters.
const TestAESKeyHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

// SetupTestDB opens a Postgres connection to the test database, runs migrations,
// and returns the *sql.DB along with a cleanup function.
// Override the DSN via TEST_DATABASE_URL.
func SetupTestDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		dsn = defaultTestDBURL
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("testhelpers.SetupTestDB: open: %v", err)
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("testhelpers.SetupTestDB: ping failed: %v\n  (set TEST_DATABASE_URL or start postgres)", err)
	}

	runMigrations(t, db)

	return db, func() { db.Close() }
}

// runMigrations applies the full platform schema.
// Uses IF NOT EXISTS throughout, so safe to call repeatedly.
func runMigrations(t *testing.T, db *sql.DB) {
	t.Helper()

	stmts := []string{
		// trial_ends_at column intentionally not declared here — migration
		// 034 dropped it (see project_no_trial_pay_day_one.md). The DROP COLUMN
		// statement near the bottom of this list keeps reused test DBs in sync.
		`CREATE TABLE IF NOT EXISTS teams (
			id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name              TEXT,
			plan_tier         TEXT NOT NULL DEFAULT 'hobby',
			stripe_customer_id TEXT UNIQUE,
			created_at        TIMESTAMPTZ DEFAULT now()
		)`,
		// Slice 6 (migration 019_env_policy.sql) — mirror the column here
		// so tests pick it up on every DB bring-up.
		`ALTER TABLE teams ADD COLUMN IF NOT EXISTS env_policy JSONB NOT NULL DEFAULT '{}'::jsonb`,
		// 032_team_deletion — GDPR right-to-be-forgotten state machine.
		// Mirrored here so handler unit tests see the same lifecycle columns
		// the API and worker drive in production. CHECK omitted from the test
		// schema on purpose: handlers always write through the typed helpers,
		// and the production migration carries the constraint; doubling it up
		// in the test DDL would make ALTER-friendly additions to the enum a
		// two-place change for no test value.
		`ALTER TABLE teams ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'`,
		`ALTER TABLE teams ADD COLUMN IF NOT EXISTS deletion_requested_at TIMESTAMPTZ`,
		`ALTER TABLE teams ADD COLUMN IF NOT EXISTS tombstoned_at TIMESTAMPTZ`,
		`CREATE INDEX IF NOT EXISTS idx_teams_pending_deletion ON teams(deletion_requested_at) WHERE status = 'deletion_requested'`,
		`CREATE TABLE IF NOT EXISTS users (
			id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			team_id     UUID REFERENCES teams(id) ON DELETE CASCADE,
			email       TEXT UNIQUE NOT NULL,
			github_id   TEXT UNIQUE,
			google_id   TEXT UNIQUE,
			role        TEXT NOT NULL DEFAULT 'member',
			created_at  TIMESTAMPTZ DEFAULT now()
		)`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'member'`,
		`CREATE TABLE IF NOT EXISTS resources (
			id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			team_id          UUID REFERENCES teams(id) ON DELETE SET NULL,
			token            UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),
			resource_type    TEXT NOT NULL,
			name             TEXT,
			connection_url   TEXT,
			tier             TEXT NOT NULL DEFAULT 'anonymous',
			fingerprint      TEXT,
			cloud_vendor     TEXT,
			country_code     CHAR(2),
			status           TEXT NOT NULL DEFAULT 'active',
			migration_status TEXT,
			expires_at       TIMESTAMPTZ,
			storage_bytes    BIGINT DEFAULT 0,
			created_request_id TEXT,
			created_at       TIMESTAMPTZ DEFAULT now()
		)`,
		// 006_key_prefix — provisioner key prefix per resource (Redis dedup path)
		`ALTER TABLE resources ADD COLUMN IF NOT EXISTS key_prefix TEXT NOT NULL DEFAULT ''`,
		// 009_env_column — env scoping for multi-env support
		`ALTER TABLE resources ADD COLUMN IF NOT EXISTS env TEXT NOT NULL DEFAULT 'production'`,
		// provider_resource_id — tracked by some scanners; safe default
		`ALTER TABLE resources ADD COLUMN IF NOT EXISTS provider_resource_id TEXT`,
		// 018_resource_family — env-twin linkage (slice 2 of env-aware deployments)
		`ALTER TABLE resources ADD COLUMN IF NOT EXISTS parent_resource_id UUID REFERENCES resources(id) ON DELETE SET NULL`,
		// 024_resources_paused_status — pause/resume API (suspend without deletion)
		`ALTER TABLE resources ADD COLUMN IF NOT EXISTS paused_at TIMESTAMPTZ`,
		`CREATE INDEX IF NOT EXISTS idx_resources_token       ON resources(token)`,
		`CREATE INDEX IF NOT EXISTS idx_resources_fingerprint ON resources(fingerprint) WHERE team_id IS NULL`,
		`CREATE INDEX IF NOT EXISTS idx_resources_expires     ON resources(expires_at) WHERE status = 'active'`,
		`CREATE INDEX IF NOT EXISTS idx_resources_team        ON resources(team_id) WHERE team_id IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_resources_team_env    ON resources(team_id, env)`,
		`CREATE INDEX IF NOT EXISTS idx_resources_family      ON resources(parent_resource_id) WHERE parent_resource_id IS NOT NULL`,
		`CREATE UNIQUE INDEX IF NOT EXISTS uq_resources_family_env ON resources(parent_resource_id, env) WHERE parent_resource_id IS NOT NULL`,
		`CREATE TABLE IF NOT EXISTS onboarding_events (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			fingerprint     TEXT NOT NULL,
			jwt_issued_at   TIMESTAMPTZ DEFAULT now(),
			jwt_expires_at  TIMESTAMPTZ,
			converted_at    TIMESTAMPTZ,
			team_id         UUID REFERENCES teams(id),
			resource_tokens UUID[],
			jti             TEXT UNIQUE NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_onboarding_jti         ON onboarding_events(jti)`,
		`CREATE INDEX IF NOT EXISTS idx_onboarding_fingerprint ON onboarding_events(fingerprint)`,
		`UPDATE users u SET role = 'owner' FROM (
			SELECT DISTINCT ON (team_id) id FROM users WHERE team_id IS NOT NULL ORDER BY team_id, created_at ASC
		) AS first_user WHERE u.id = first_user.id AND u.role = 'member'`,
		// 029_users_is_primary — explicit boolean for the "primary"
		// user of a team. Backfill marks the earliest-created user per
		// team as primary; the partial unique index enforces at most
		// one primary per team.
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_primary BOOLEAN NOT NULL DEFAULT false`,
		`UPDATE users u SET is_primary = true FROM (
			SELECT DISTINCT ON (team_id) id FROM users WHERE team_id IS NOT NULL ORDER BY team_id, created_at ASC
		) AS first_primary WHERE u.id = first_primary.id AND u.is_primary = false`,
		`CREATE UNIQUE INDEX IF NOT EXISTS uq_users_one_primary_per_team ON users(team_id) WHERE is_primary`,
		`CREATE TABLE IF NOT EXISTS team_invitations (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
			email TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'member',
			invited_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			status TEXT NOT NULL DEFAULT 'pending',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '7 days'
		)`,
		`CREATE INDEX IF NOT EXISTS idx_invitations_team ON team_invitations(team_id)`,
		`CREATE INDEX IF NOT EXISTS idx_invitations_email ON team_invitations(lower(email))`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_invitations_team_email_pending ON team_invitations (team_id, lower(email)) WHERE status = 'pending'`,
		// 010_team_invitations — RBAC + token-based accept
		`CREATE EXTENSION IF NOT EXISTS pgcrypto`,
		`ALTER TABLE team_invitations ADD COLUMN IF NOT EXISTS token TEXT`,
		`ALTER TABLE team_invitations ADD COLUMN IF NOT EXISTS accepted_at TIMESTAMPTZ`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_invitations_token ON team_invitations (token)`,
		// 008_vault — per-team encrypted secret storage
		`CREATE TABLE IF NOT EXISTS vault_secrets (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			team_id         UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
			env             TEXT NOT NULL DEFAULT 'production',
			key             TEXT NOT NULL,
			encrypted_value BYTEA NOT NULL,
			version         INT NOT NULL DEFAULT 1,
			created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
			created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE (team_id, env, key, version)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_vault_secrets_lookup ON vault_secrets (team_id, env, key)`,
		`CREATE TABLE IF NOT EXISTS vault_audit_log (
			id          BIGSERIAL PRIMARY KEY,
			team_id     UUID NOT NULL,
			user_id     UUID,
			action      TEXT NOT NULL,
			env         TEXT NOT NULL,
			secret_key  TEXT NOT NULL,
			ip          TEXT,
			ts          TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_vault_audit_team_ts ON vault_audit_log (team_id, ts DESC)`,
		// 012_audit_log — per-team event stream consumed by the dashboard's
		// Recent Activity feed. Mirrored here so callers that bring up a fresh
		// test DB via SetupTestDB get the table without needing the SQL
		// migrations to have been applied separately.
		`CREATE TABLE IF NOT EXISTS audit_log (
			id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			team_id       UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
			user_id       UUID REFERENCES users(id) ON DELETE SET NULL,
			actor         TEXT NOT NULL DEFAULT 'agent',
			kind          TEXT NOT NULL,
			resource_type TEXT,
			resource_id   UUID,
			summary       TEXT NOT NULL,
			metadata      JSONB,
			created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_team_at ON audit_log (team_id, created_at DESC)`,
		// 028_audit_log_team_id_nullable — drop NOT NULL on team_id so the
		// emit path can record events that fire BEFORE a team exists.
		// Mirrored here so handler tests pick it up without running the
		// SQL migrations separately.
		`ALTER TABLE audit_log ALTER COLUMN team_id DROP NOT NULL`,
		// 003_deployments — Phase 6 container deployments
		`CREATE TABLE IF NOT EXISTS deployments (
			id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			token          TEXT UNIQUE NOT NULL,
			team_id        UUID REFERENCES teams(id) ON DELETE SET NULL,
			namespace      TEXT NOT NULL,
			image          TEXT NOT NULL,
			container_port INT NOT NULL DEFAULT 8080,
			app_url        TEXT NOT NULL,
			tier           TEXT NOT NULL DEFAULT 'anonymous',
			status         TEXT NOT NULL DEFAULT 'pending',
			created_at     TIMESTAMPTZ DEFAULT now(),
			deleted_at     TIMESTAMPTZ
		)`,
		`ALTER TABLE deployments ADD COLUMN IF NOT EXISTS token TEXT`,
		`ALTER TABLE deployments ADD COLUMN IF NOT EXISTS namespace TEXT`,
		`ALTER TABLE deployments ADD COLUMN IF NOT EXISTS image TEXT`,
		`ALTER TABLE deployments ADD COLUMN IF NOT EXISTS container_port INT`,
		`ALTER TABLE deployments ADD COLUMN IF NOT EXISTS app_url TEXT`,
		`ALTER TABLE deployments ADD COLUMN IF NOT EXISTS tier TEXT`,
		`ALTER TABLE deployments ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ`,
		// Drop NOT NULL on token / namespace / image / container_port / app_url
		// (real schema uses app_id; these legacy fields aren't populated by current models).
		`ALTER TABLE deployments ALTER COLUMN token DROP NOT NULL`,
		`ALTER TABLE deployments ALTER COLUMN namespace DROP NOT NULL`,
		`ALTER TABLE deployments ALTER COLUMN image DROP NOT NULL`,
		`ALTER TABLE deployments ALTER COLUMN container_port DROP NOT NULL`,
		`ALTER TABLE deployments ALTER COLUMN app_url DROP NOT NULL`,
		`ALTER TABLE deployments ADD COLUMN IF NOT EXISTS resource_id UUID REFERENCES resources(id) ON DELETE SET NULL`,
		`ALTER TABLE deployments ADD COLUMN IF NOT EXISTS env TEXT NOT NULL DEFAULT 'production'`,
		`ALTER TABLE deployments ADD COLUMN IF NOT EXISTS env_vars JSONB NOT NULL DEFAULT '{}'`,
		`ALTER TABLE deployments ADD COLUMN IF NOT EXISTS app_id TEXT`,
		`ALTER TABLE deployments ADD COLUMN IF NOT EXISTS provider_id TEXT`,
		`ALTER TABLE deployments ADD COLUMN IF NOT EXISTS port INT NOT NULL DEFAULT 8080`,
		`ALTER TABLE deployments ADD COLUMN IF NOT EXISTS error_message TEXT`,
		`ALTER TABLE deployments ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now()`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_deployments_app_id ON deployments(app_id) WHERE app_id IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_deployments_status ON deployments(status)`,
		`CREATE INDEX IF NOT EXISTS idx_deployments_team  ON deployments(team_id) WHERE deleted_at IS NULL`,
		`CREATE INDEX IF NOT EXISTS idx_deployments_token ON deployments(token) WHERE token IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_deployments_resource_id ON deployments(resource_id)`,
		`CREATE INDEX IF NOT EXISTS idx_deployments_team_env ON deployments(team_id, env)`,
		// 012_audit_log — per-team event stream consumed by the dashboard's
		// Recent Activity feed AND by the admin customer-detail endpoint.
		`CREATE TABLE IF NOT EXISTS audit_log (
			id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			team_id       UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
			user_id       UUID REFERENCES users(id) ON DELETE SET NULL,
			actor         TEXT NOT NULL DEFAULT 'agent',
			kind          TEXT NOT NULL,
			resource_type TEXT,
			resource_id   UUID,
			summary       TEXT NOT NULL,
			metadata      JSONB,
			created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_team_at ON audit_log (team_id, created_at DESC)`,
		// 028_audit_log_team_id_nullable — second mirror (the CREATE TABLE
		// above uses IF NOT EXISTS so this ALTER fires once per fresh DB).
		`ALTER TABLE audit_log ALTER COLUMN team_id DROP NOT NULL`,
		// 021_admin_promo_codes — single-use admin-issued promo codes.
		`CREATE TABLE IF NOT EXISTS admin_promo_codes (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			code            TEXT UNIQUE NOT NULL,
			team_id         UUID REFERENCES teams(id) ON DELETE CASCADE,
			issued_by_email TEXT NOT NULL,
			kind            TEXT NOT NULL CHECK (kind IN ('percent_off', 'first_month_free', 'amount_off')),
			value           INTEGER NOT NULL,
			applies_to      INTEGER,
			used_at         TIMESTAMPTZ,
			expires_at      TIMESTAMPTZ NOT NULL,
			created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_admin_promo_codes_code ON admin_promo_codes(code) WHERE used_at IS NULL`,
		`CREATE INDEX IF NOT EXISTS idx_admin_promo_codes_team ON admin_promo_codes(team_id)`,
		// 024_admin_customer_notes — free-text per-team notes by platform admins.
		`CREATE TABLE IF NOT EXISTS admin_customer_notes (
			id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			team_id      UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
			body         TEXT NOT NULL,
			author_email TEXT NOT NULL,
			created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_admin_customer_notes_team ON admin_customer_notes(team_id, created_at DESC)`,
		// 022_deploys_audit — append-only deploy-identity log. Mirrored so
		// handler tests get the table without running migrations separately.
		`CREATE TABLE IF NOT EXISTS deploys_audit (
			id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			service           TEXT NOT NULL,
			commit_id         TEXT NOT NULL,
			image_digest      TEXT NOT NULL,
			version           TEXT,
			build_time        TIMESTAMPTZ,
			applied_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
			migration_version TEXT,
			noticed_by        TEXT NOT NULL DEFAULT 'self-report'
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS uq_deploys_audit_identity ON deploys_audit(service, commit_id, image_digest)`,
		`CREATE INDEX IF NOT EXISTS idx_deploys_audit_service_time ON deploys_audit(service, applied_at DESC)`,
		// 027_payment_dunning — failed-charge dunning state machine.
		`CREATE TABLE IF NOT EXISTS payment_grace_periods (
			id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			team_id          UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
			subscription_id  TEXT NOT NULL,
			status           TEXT NOT NULL DEFAULT 'active',
			started_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
			expires_at       TIMESTAMPTZ NOT NULL,
			reminders_sent   INTEGER NOT NULL DEFAULT 0,
			last_reminder_at TIMESTAMPTZ,
			recovered_at     TIMESTAMPTZ,
			terminated_at    TIMESTAMPTZ
		)`,
		`CREATE INDEX IF NOT EXISTS idx_payment_grace_active ON payment_grace_periods(status, expires_at)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS uq_payment_grace_team_active ON payment_grace_periods(team_id) WHERE status = 'active'`,
		// 026_promote_approvals — email-link approval workflow for non-dev env promotions.
		`CREATE TABLE IF NOT EXISTS promote_approvals (
			id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			token              TEXT UNIQUE NOT NULL,
			team_id            UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
			requested_by_email TEXT NOT NULL,
			promote_kind       TEXT NOT NULL,
			promote_payload    JSONB NOT NULL,
			from_env           TEXT NOT NULL,
			to_env             TEXT NOT NULL,
			status             TEXT NOT NULL DEFAULT 'pending',
			created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
			expires_at         TIMESTAMPTZ NOT NULL,
			approved_at        TIMESTAMPTZ,
			executed_at        TIMESTAMPTZ,
			rejected_at        TIMESTAMPTZ
		)`,
		`CREATE INDEX IF NOT EXISTS idx_promote_approvals_token ON promote_approvals(token) WHERE status = 'pending'`,
		`CREATE INDEX IF NOT EXISTS idx_promote_approvals_pending_exec ON promote_approvals(status) WHERE status = 'approved' AND executed_at IS NULL`,
		// 033_razorpay_webhook_events — replay protection for the Razorpay
		// webhook handler. Mirror so handler tests can hit InsertOnConflict.
		`CREATE TABLE IF NOT EXISTS razorpay_webhook_events (
			event_id     TEXT PRIMARY KEY,
			event_type   TEXT NOT NULL,
			received_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_razorpay_webhook_events_received_at ON razorpay_webhook_events(received_at)`,
		// 030_resource_heartbeat — companion for the worker's provisioner_reconciler
		// and resource_heartbeat jobs (shipped 2026-05-13). Mirrored here so a fresh
		// SetupTestDB has the columns the heartbeat-driven resource model fields read.
		`ALTER TABLE resources ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ`,
		`ALTER TABLE resources ADD COLUMN IF NOT EXISTS degraded BOOLEAN NOT NULL DEFAULT false`,
		`ALTER TABLE resources ADD COLUMN IF NOT EXISTS degraded_reason TEXT`,
		`ALTER TABLE resources ADD COLUMN IF NOT EXISTS last_reconciled_at TIMESTAMPTZ`,
		`CREATE INDEX IF NOT EXISTS idx_resources_degraded ON resources(degraded) WHERE degraded`,
		`CREATE INDEX IF NOT EXISTS idx_resources_pending_sweep ON resources(status, created_at) WHERE status = 'pending'`,
		// 031_backups — customer-facing Postgres backup + restore tables.
		`CREATE TABLE IF NOT EXISTS resource_backups (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			resource_id     UUID NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
			status          TEXT NOT NULL CHECK (status IN ('pending','running','ok','failed')) DEFAULT 'pending',
			backup_kind     TEXT NOT NULL CHECK (backup_kind IN ('scheduled','manual')),
			started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
			finished_at     TIMESTAMPTZ,
			s3_key          TEXT,
			size_bytes      BIGINT,
			tier_at_backup  TEXT,
			error_summary   TEXT,
			triggered_by    UUID REFERENCES users(id),
			created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_backups_resource ON resource_backups(resource_id)`,
		`CREATE INDEX IF NOT EXISTS idx_backups_pending  ON resource_backups(status) WHERE status IN ('pending','running')`,
		`CREATE TABLE IF NOT EXISTS resource_restores (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			resource_id     UUID NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
			backup_id       UUID NOT NULL REFERENCES resource_backups(id),
			status          TEXT NOT NULL CHECK (status IN ('pending','running','ok','failed')) DEFAULT 'pending',
			started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
			finished_at     TIMESTAMPTZ,
			error_summary   TEXT,
			triggered_by    UUID NOT NULL REFERENCES users(id),
			created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_restores_resource ON resource_restores(resource_id)`,
		`CREATE INDEX IF NOT EXISTS idx_restores_pending  ON resource_restores(status) WHERE status IN ('pending','running')`,
		// 034_drop_trial_ends_at — the platform has no trial period (see
		// policy memory project_no_trial_pay_day_one.md). Idempotent with
		// IF EXISTS so test setups bringing up a fresh DB don't trip on the
		// missing column when other code paths drop the field.
		`ALTER TABLE teams DROP COLUMN IF EXISTS trial_ends_at`,
	}

	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("testhelpers.runMigrations: %v\n  SQL: %.120s", err, s)
		}
	}
}

// SetupTestRedis connects to the test Redis (DB 15 by default), flushes the keyspace,
// and returns the client along with a cleanup function.
// Override via TEST_REDIS_URL.
func SetupTestRedis(t *testing.T) (*redis.Client, func()) {
	t.Helper()
	rawURL := os.Getenv("TEST_REDIS_URL")
	if rawURL == "" {
		rawURL = defaultTestRedisURL
	}

	opts, err := redis.ParseURL(rawURL)
	if err != nil {
		t.Fatalf("testhelpers.SetupTestRedis: parse URL: %v", err)
	}

	rdb := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Fatalf("testhelpers.SetupTestRedis: ping failed: %v\n  (set TEST_REDIS_URL or start redis)", err)
	}

	rdb.FlushDB(context.Background())

	return rdb, func() {
		rdb.FlushDB(context.Background())
		rdb.Close()
	}
}

// testConfig returns a *config.Config suitable for tests.
// It does NOT call config.Load() to avoid panicking on missing real env vars.
func testConfig() *config.Config {
	customersURL := os.Getenv("TEST_POSTGRES_CUSTOMERS_URL")
	if customersURL == "" {
		customersURL = defaultTestCustomersURL
	}
	return &config.Config{
		Port:                     "8080",
		DatabaseURL:              defaultTestDBURL,
		RedisURL:                 defaultTestRedisURL,
		JWTSecret:                TestJWTSecret,
		AESKey:                   TestAESKeyHex,
		EnabledServices:          "redis",
		Environment:              "test",
		PostgresProvisionBackend: "local",
		PostgresCustomersURL:     customersURL,
		// Slice 4 of env-aware deployments: production default is `true`, so
		// tests should mirror that. Tests that need the flag off override it
		// after the testConfig call.
		FamilyBindingsEnabled: true,
	}
}

// lastBulkTwinHandler captures the *handlers.BulkTwinHandler constructed
// by the most recent NewTestApp* call so tests can mutate its public
// QuotaHeadroom field without re-plumbing the router. Tests retrieve it
// via LastBulkTwinHandler() — guarded against the "called from no test
// app" case by a nil check.
//
// Concurrency note: tests run sequentially within a single Go test binary
// by default (-parallel handled separately at the t.Parallel boundary).
// Tests that share an app shouldn't share QuotaHeadroom anyway — each
// test that needs it calls NewTestApp fresh and then sets it. A global
// var is the simplest way to avoid widening every NewTestApp signature
// in this package just for one hook.
var lastBulkTwinHandler *handlers.BulkTwinHandler

// LastBulkTwinHandler returns the BulkTwinHandler created by the most
// recent NewTestApp* call. Tests set its QuotaHeadroom field to exercise
// the partial-fill quota gate. Returns nil if no test app has been
// constructed in this process yet — callers should defend with t.Skip
// or a fresh app build.
func LastBulkTwinHandler() *handlers.BulkTwinHandler {
	return lastBulkTwinHandler
}

// NewTestApp creates a Fiber app wired to the provided DB and Redis clients
// using the same handler/middleware chain as production (minus GeoIP lookup).
// Routes registered: POST /cache/new, GET /start, POST /claim, /api/v1/resources.
// Only the "redis" service is enabled. Use NewTestAppWithServices to enable others.
func NewTestApp(t *testing.T, db *sql.DB, rdb *redis.Client) (*fiber.App, func()) {
	t.Helper()
	return NewTestAppWithServices(t, db, rdb, "redis")
}

// NewTestAppWithServices creates a Fiber app identical to NewTestApp but with
// an explicit comma-separated list of enabled services (e.g. "postgres,redis,mongodb,queue,webhook,storage").
// Use this in tests that exercise /db/new, /cache/new, or /nosql/new.
func NewTestAppWithServices(t *testing.T, db *sql.DB, rdb *redis.Client, services string) (*fiber.App, func()) {
	t.Helper()
	cfg := testConfig()
	cfg.EnabledServices = services
	planReg := plans.Default()

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			// respondError already wrote the body — short-circuit so we
			// don't overwrite. Matches the production ErrorHandler in
			// router/router.go.
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{
				"ok":      false,
				"error":   "internal_error",
				"message": err.Error(),
			})
		},
		ProxyHeader: "X-Forwarded-For",
	})

	app.Use(middleware.RequestID())
	// GeoEnrich is skipped in tests (no MaxMind DB in CI).
	app.Use(middleware.Fingerprint())
	app.Use(middleware.RateLimit(rdb, middleware.RateLimitConfig{
		Limit:     provisionLimit,
		KeyPrefix: "rl",
	}))

	onboardH := handlers.NewOnboardingHandler(db, cfg, email.New(""))
	cliAuthH := handlers.NewCLIAuthHandler(db, rdb, cfg, planReg)
	resourceH := handlers.NewResourceHandler(db, rdb, cfg, planReg, nil, nil)
	dbH := handlers.NewDBHandler(db, rdb, cfg, nil, planReg)
	vectorH := handlers.NewVectorHandler(db, rdb, cfg, nil, planReg)
	cacheH := handlers.NewCacheHandler(db, rdb, cfg, nil, planReg)
	nosqlH := handlers.NewNoSQLHandler(db, rdb, cfg, nil, planReg)

	app.Get("/start", onboardH.StartLanding)
	app.Post("/claim", onboardH.Claim)
	app.Get("/auth/me", middleware.RequireAuth(cfg), cliAuthH.GetCurrentUser)

	// Provisioning routes for Phase 2/3/4 services.
	// Idempotency middleware mirrors the production wiring in
	// internal/router/router.go so handler tests exercise the same chain.
	dbGroup := app.Group("/db", middleware.OptionalAuth(cfg))
	dbGroup.Post("/new", middleware.Idempotency(rdb, "db.new"), dbH.NewDB)

	vectorGroup := app.Group("/vector", middleware.OptionalAuth(cfg))
	vectorGroup.Post("/new", vectorH.NewVector)

	cacheGroup := app.Group("/cache", middleware.OptionalAuth(cfg))
	cacheGroup.Post("/new", middleware.Idempotency(rdb, "cache.new"), cacheH.NewCache)

	nosqlGroup := app.Group("/nosql", middleware.OptionalAuth(cfg))
	nosqlGroup.Post("/new", middleware.Idempotency(rdb, "nosql.new"), nosqlH.NewNoSQL)

	// Authenticated resource management (used by isolation tests)
	// Phase 5 services: storage + webhook
	storageH := handlers.NewStorageHandler(db, rdb, cfg, nil, planReg)
	webhookH := handlers.NewWebhookHandler(db, rdb, cfg, planReg)
	app.Post("/storage/new", middleware.OptionalAuth(cfg), middleware.Idempotency(rdb, "storage.new"), storageH.NewStorage)
	app.Post("/webhook/new", middleware.OptionalAuth(cfg), middleware.Idempotency(rdb, "webhook.new"), webhookH.NewWebhook)
	app.Post("/webhook/receive/:token", webhookH.Receive)

	// Phase 6: deploy
	deployH := handlers.NewDeployHandler(db, rdb, cfg, planReg)
	deployGroup := app.Group("/deploy", middleware.RequireAuth(cfg))
	deployGroup.Post("/new", middleware.Idempotency(rdb, "deploy.new"), deployH.New)
	deployGroup.Get("/:id", deployH.Get)
	deployGroup.Get("/:id/logs", deployH.Logs)
	deployGroup.Patch("/:id/env", deployH.UpdateEnv)
	deployGroup.Delete("/:id", deployH.Delete)
	deployGroup.Post("/:id/redeploy", deployH.Redeploy)

	// Register role lookup so RequireRole can resolve the caller's role
	// against the test DB (mirror of the production wiring in router.go).
	// Each call replaces the package-level handle — fine for serial tests;
	// SetupTestDB gives each test its own DB so parallel tests still see a
	// consistent role lookup for their own data.
	middleware.SetRoleLookupDB(db)

	api := app.Group("/api/v1", middleware.RequireAuth(cfg), middleware.PopulateTeamRole())
	whoamiH := handlers.NewWhoamiHandler(db)
	api.Get("/whoami", whoamiH.Get)
	api.Get("/resources", resourceH.List)
	// /families and /:id/family must register BEFORE /:id so Fiber routes
	// the literal segments instead of binding them to the :id wildcard.
	// Matches the production order in internal/router/router.go.
	api.Get("/resources/families", resourceH.ListFamilies)
	api.Get("/resources/:id/family", resourceH.Family)
	api.Get("/resources/:id", resourceH.Get)
	api.Get("/resources/:id/credentials", resourceH.GetCredentials)
	api.Get("/resources/:id/metrics", resourceH.Metrics)
	api.Delete("/resources/:id", resourceH.Delete)
	api.Post("/resources/:id/rotate-credentials", resourceH.RotateCredentials)
	api.Post("/resources/:id/pause", resourceH.Pause)
	api.Post("/resources/:id/resume", resourceH.Resume)

	// GDPR right-to-be-forgotten endpoints (migration 032). Owner-only
	// per RequireRole. The test fixture inserts users with explicit
	// role='owner' to exercise the success path.
	teamDelH := handlers.NewTeamDeletionHandler(db, cfg)
	api.Delete("/team", middleware.RequireRole("owner"), teamDelH.Delete)
	api.Post("/team/restore", middleware.RequireRole("owner"), teamDelH.Restore)
	// Slice 3 of env-aware deployments — spawn a same-type, same-family
	// twin in a new env. Tier-gated to Pro+ inside the handler. Wired here
	// so handler-layer tests (twin_test.go) exercise the full route stack.
	twinH := handlers.NewTwinHandler(dbH, cacheH, nosqlH)
	api.Post("/resources/:id/provision-twin", twinH.ProvisionTwin)
	// Bulk env-twinning — wired so handler-layer tests
	// (family_bulk_twin_test.go) exercise the full route stack. The
	// handler instance is captured in lastBulkTwinHandler so tests can
	// inject QuotaHeadroom (the partial-fill quota hook) without
	// touching the router.
	bulkTwinH := handlers.NewBulkTwinHandler(db, dbH, cacheH, nosqlH, planReg)
	api.Post("/families/bulk-twin", bulkTwinH.BulkTwin)
	lastBulkTwinHandler = bulkTwinH
	// Customer backups + restore (migration 031). Wired here so the
	// handler tests in backup_test.go exercise the full route stack
	// (auth middleware + JSON handler + ownership check) end-to-end.
	backupH := handlers.NewBackupHandler(db, rdb, planReg)
	api.Post("/resources/:id/backup", backupH.CreateBackup)
	api.Get("/resources/:id/backups", backupH.ListBackups)
	api.Post("/resources/:id/restore", backupH.CreateRestore)
	api.Get("/resources/:id/restores", backupH.ListRestores)
	api.Get("/webhooks/:token/requests", webhookH.ListRequests)
	api.Get("/deployments", deployH.List)
	api.Get("/deployments/:id", deployH.Get)
	api.Delete("/deployments/:id", deployH.Delete)
	api.Patch("/deployments/:id", deployH.Patch)

	// A/B-experiment conversion sink — wired into the test app so
	// handler tests can exercise the full route stack (router +
	// auth middleware + JSON handler) end-to-end.
	experimentsH := handlers.NewExperimentsHandler(db)
	api.Post("/experiments/converted", experimentsH.Converted)

	// W7-C customer-facing audit export — JSON + CSV. Wired in tests so
	// the handler-layer tests in audit_export_test.go exercise the full
	// route stack (auth middleware + JSON / CSV handlers + tier gate).
	auditH := handlers.NewAuditHandler(db)
	api.Get("/audit", auditH.List)
	api.Get("/audit.csv", auditH.ListCSV)

	return app, func() { app.Shutdown() }
}

// MustProvisionDB POSTs to /db/new and returns the token.
// The app must be created with NewTestAppWithServices(..., "postgres").
// Skips the test gracefully if the postgres-customers backend is not reachable.
func MustProvisionDB(t *testing.T, app *fiber.App, ip string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/db/new", nil)
	req.Header.Set("X-Forwarded-For", ip)

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("MustProvisionDB: app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		var errBody map[string]any
		if jsonErr := json.Unmarshal(body, &errBody); jsonErr == nil {
			if code, _ := errBody["error"].(string); code == "provision_failed" {
				t.Skipf("MustProvisionDB: postgres-customers not reachable — skipping test (%s)", body)
			}
		}
		t.Fatalf("MustProvisionDB: expected 201, got %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("MustProvisionDB: decode: %v", err)
	}
	if result.Token == "" {
		t.Fatal("MustProvisionDB: token field is empty in response")
	}
	return result.Token
}

// MustProvisionCache POSTs to /cache/new and returns the token.
// ip is passed directly as X-Forwarded-For; use FingerprintToIP(fp) to convert a label first.
// The app must be created with NewTestAppWithServices(..., "redis").
func MustProvisionCache(t *testing.T, app *fiber.App, ip string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/cache/new", nil)
	req.Header.Set("X-Forwarded-For", ip)

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("MustProvisionCache: app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("MustProvisionCache: expected 201/200, got %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("MustProvisionCache: decode: %v", err)
	}
	if result.Token == "" {
		t.Fatal("MustProvisionCache: token field is empty in response")
	}
	return result.Token
}

// MustProvisionNoSQL POSTs to /nosql/new and returns the token.
// The app must be created with NewTestAppWithServices(..., "mongodb").
func MustProvisionNoSQL(t *testing.T, app *fiber.App, ip string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/nosql/new", nil)
	req.Header.Set("X-Forwarded-For", ip)

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("MustProvisionNoSQL: app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		// Skip gracefully when MongoDB is not reachable in the test environment.
		var errBody map[string]any
		if jsonErr := json.Unmarshal(body, &errBody); jsonErr == nil {
			if code, _ := errBody["error"].(string); code == "provision_failed" {
				t.Skipf("MustProvisionNoSQL: MongoDB not reachable — skipping test (%s)", body)
			}
		}
		t.Fatalf("MustProvisionNoSQL: expected 201, got %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("MustProvisionNoSQL: decode: %v", err)
	}
	if result.Token == "" {
		t.Fatal("MustProvisionNoSQL: token field is empty in response")
	}
	return result.Token
}

// provisionLimit is the per-fingerprint daily provisioning cap used in test apps.
// Must match the constant in the production router (currently 5).
const provisionLimit = 5

// ProvisionResult holds the parsed response from POST /cache/new (or any provision endpoint).
type ProvisionResult struct {
	Token string `json:"token"`
	Note  string `json:"note"`
	// JWT extracted from the upgrade URL in Note, e.g. "https://...?t=<jwt>"
	JWT string
}

// MustProvisionCacheFull POSTs to /cache/new and returns the full parsed response,
// including the onboarding JWT extracted from the upgrade URL in the note field.
func MustProvisionCacheFull(t *testing.T, app *fiber.App, fingerprint string) ProvisionResult {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/cache/new", nil)
	req.Header.Set("X-Forwarded-For", FingerprintToIP(fingerprint))

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("MustProvisionCacheFull: app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("MustProvisionCacheFull: expected 201/200, got %d: %s", resp.StatusCode, body)
	}

	var result ProvisionResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("MustProvisionCacheFull: decode: %v", err)
	}
	if result.Token == "" {
		t.Fatal("MustProvisionCacheFull: token field is empty in response")
	}

	// Extract JWT from upgrade URL in note: "...?t=<jwt>"
	if idx := strings.Index(result.Note, "?t="); idx != -1 {
		raw := result.Note[idx+3:]
		if sp := strings.IndexAny(raw, " \t\n"); sp != -1 {
			raw = raw[:sp]
		}
		result.JWT = raw
	}
	return result
}

// ComputeTestFingerprint returns the middleware fingerprint hash that will be
// computed when a request arrives with X-Forwarded-For set to FingerprintToIP(fp).
// Use this to look up Redis keys produced by the provisioning handler (e.g. "prov:{hash}:{date}").
func ComputeTestFingerprint(fp string) string {
	ip := FingerprintToIP(fp)
	hash, _ := crypto.FingerprintIP(ip, "")
	return hash
}

// FingerprintToIP deterministically maps a fingerprint string to a unique IPv4
// in the 10.255.X.Y range, staying within a /24 so all calls from the same
// fingerprint land on the same fingerprint hash.
func FingerprintToIP(fp string) string {
	// Use a simple FNV-like fold to map to 10.255.X.0
	var h uint32
	for _, b := range []byte(fp) {
		h = h*31 + uint32(b)
	}
	return fmt.Sprintf("10.255.%d.1", h%254+1)
}

// OnboardingClaims is a re-export so test files don't need to import crypto directly.
type OnboardingClaims = crypto.OnboardingClaims

// MustSignJWT signs an OnboardingClaims with TestJWTSecret and returns the token string.
func MustSignJWT(t *testing.T, claims crypto.OnboardingClaims) string {
	t.Helper()
	signed, _, err := crypto.SignOnboardingJWT([]byte(TestJWTSecret), claims)
	if err != nil {
		t.Fatalf("MustSignJWT: %v", err)
	}
	return signed
}

// MustSignExpiredJWT creates an already-expired onboarding JWT.
func MustSignExpiredJWT(t *testing.T, claims crypto.OnboardingClaims) string {
	t.Helper()
	// Temporarily set past timestamps on the registered claims.
	past := time.Now().Add(-2 * time.Hour)
	claims.RegisteredClaims = jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(past),
		ExpiresAt: jwt.NewNumericDate(past.Add(15 * time.Minute)),
		ID:        uuid.NewString(),
	}
	// Sign directly with jwt package using past times (bypasses SignOnboardingJWT which sets its own times).
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(TestJWTSecret))
	if err != nil {
		t.Fatalf("MustSignExpiredJWT: %v", err)
	}
	return signed
}

// PostJSON POSTs a JSON body to the Fiber app under test.
func PostJSON(t *testing.T, app *fiber.App, path string, body any) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("PostJSON: encode: %v", err)
		}
	}
	req := httptest.NewRequest(http.MethodPost, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("PostJSON: %v", err)
	}
	return resp
}

// GetReq sends a GET to the Fiber app under test.
func GetReq(t *testing.T, app *fiber.App, path string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("GetReq: %v", err)
	}
	return resp
}

// DecodeJSON decodes the response body into v and closes the body.
func DecodeJSON(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("DecodeJSON: %v", err)
	}
}

// UniqueFingerprint returns a unique test fingerprint string.
func UniqueFingerprint(t *testing.T) string {
	t.Helper()
	return "fp-" + uuid.NewString()
}

// UniqueEmail returns a unique email address for test user creation.
func UniqueEmail(t *testing.T) string {
	t.Helper()
	return "test+" + uuid.NewString()[:8] + "@instant.dev"
}

// sessionClaimsForTest mirrors the payload issued by the auth handler.
type sessionClaimsForTest struct {
	UserID string `json:"uid"`
	TeamID string `json:"tid"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

// MustSignSessionJWT creates a valid session JWT (the kind issued after OAuth login)
// signed with TestJWTSecret. Use this to test authenticated endpoints.
func MustSignSessionJWT(t *testing.T, userID, teamID, email string) string {
	t.Helper()
	claims := sessionClaimsForTest{
		UserID: userID,
		TeamID: teamID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			ID:        uuid.NewString(),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(TestJWTSecret))
	if err != nil {
		t.Fatalf("MustSignSessionJWT: %v", err)
	}
	return signed
}

// MustCreateTeamDB inserts a team with the given plan tier into the test database
// and returns its UUID string.
func MustCreateTeamDB(t *testing.T, db *sql.DB, planTier string) string {
	t.Helper()
	var id string
	err := db.QueryRowContext(context.Background(), `
		INSERT INTO teams (name, plan_tier) VALUES ($1, $2)
		RETURNING id::text
	`, "test-team-"+uuid.NewString()[:8], planTier).Scan(&id)
	if err != nil {
		t.Fatalf("MustCreateTeamDB: %v", err)
	}
	return id
}
