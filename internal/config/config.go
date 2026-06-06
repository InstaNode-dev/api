package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

// Config holds all runtime configuration for the platform.
type Config struct {
	Port                  string
	DatabaseURL           string // platform DB: teams, users, resources
	CustomerDatabaseURL   string // customer DB: provisioned db_{token} databases (Phase 2+)
	RedisURL              string
	JWTSecret             string
	AESKey                string
	MaxMindLicenseKey     string
	GeoLite2DBPath        string
	RazorpayKeyID         string // RAZORPAY_KEY_ID — API key ID (used server-side)
	RazorpayKeySecret     string // RAZORPAY_KEY_SECRET — API key secret
	RazorpayWebhookSecret string // RAZORPAY_WEBHOOK_SECRET — webhook signature verification
	RazorpayPlanIDHobby   string // RAZORPAY_PLAN_ID_HOBBY — plan_id for hobby tier (monthly)
	// RazorpayPlanIDHobbyPlus — plan_id for the W11 hobby_plus tier
	// ($19/mo, monthly). When unset, /api/v1/billing/checkout with
	// plan="hobby_plus" returns 503 billing_not_configured. The operator
	// must create the corresponding Razorpay subscription plan in the
	// dashboard and set this env var before checkout will work.
	RazorpayPlanIDHobbyPlus string // RAZORPAY_PLAN_ID_HOBBY_PLUS — plan_id for hobby_plus tier (monthly)
	RazorpayPlanIDPro       string // RAZORPAY_PLAN_ID_PRO — plan_id for pro tier (monthly)
	// RazorpayPlanIDGrowth — plan_id for the W12 growth tier ($99/mo,
	// monthly). When unset, /api/v1/billing/checkout with plan="growth"
	// returns 503 billing_not_configured; the reconciler also logs
	// `billing.plan_id_to_tier.unrecognised` for any incoming Growth
	// webhook so the operator notices the gap. D28 F3 (2026-05-21).
	RazorpayPlanIDGrowth string // RAZORPAY_PLAN_ID_GROWTH — plan_id for growth tier (monthly)
	RazorpayPlanIDTeam   string // RAZORPAY_PLAN_ID_TEAM — plan_id for team tier (monthly)
	// Yearly billing variants. When unset, the corresponding yearly checkout
	// returns 503 billing_not_configured so partial rollout (monthly already
	// live, yearly plans not yet created in Razorpay dashboard) is safe.
	RazorpayPlanIDHobbyYearly     string // RAZORPAY_PLAN_ID_HOBBY_YEARLY — plan_id for hobby tier (yearly)
	RazorpayPlanIDHobbyPlusYearly string // RAZORPAY_PLAN_ID_HOBBY_PLUS_ANNUAL — plan_id for hobby_plus tier (yearly)
	RazorpayPlanIDProYearly       string // RAZORPAY_PLAN_ID_PRO_YEARLY — plan_id for pro tier (yearly)
	RazorpayPlanIDGrowthYearly    string // RAZORPAY_PLAN_ID_GROWTH_ANNUAL — plan_id for growth tier (yearly)
	RazorpayPlanIDTeamYearly      string // RAZORPAY_PLAN_ID_TEAM_YEARLY — plan_id for team tier (yearly)

	// ── Razorpay TEST-mode credentials (Wave 4b, docs/ci/01-CI-INTEGRATION-DESIGN.md) ──
	// These are the rzp_test_* keys + their plan_ids used ONLY for the
	// synthetic test-cohort (teams.is_test_cohort=true, migration 067) so CI can
	// drive a real test-mode hosted checkout + test-card payment WITHOUT touching
	// the live Razorpay account and WITHOUT needing the live-recurring approval
	// (test mode has no recurring gate). Every field defaults to "" (empty) so
	// the whole test-mode path is INERT in any deployment where the operator has
	// not configured it — a non-cohort team always uses the live keys above, and
	// a cohort team falls back to the normal (skip/inert) behaviour when these
	// are unset. The actual key values MUST NEVER leak in any API response
	// (same NEVER-leak contract as RazorpayKeyID — see trafficEnv/BUG-P112).
	RazorpayTestKeyID         string // RAZORPAY_TEST_KEY_ID — rzp_test_* API key ID (test-cohort only)
	RazorpayTestKeySecret     string // RAZORPAY_TEST_KEY_SECRET — rzp_test_* API key secret (test-cohort only)
	RazorpayTestWebhookSecret string // RAZORPAY_TEST_WEBHOOK_SECRET — webhook signature secret for test-mode events
	// Test-mode plan_ids for the self-serve checkout tiers (hobby / hobby_plus /
	// pro, monthly). Created by the operator in the Razorpay TEST dashboard. When
	// a tier's test plan_id is unset, a cohort checkout for that tier falls back
	// to the inert path (no test-mode subscription is minted).
	RazorpayTestPlanIDHobby     string // RAZORPAY_TEST_PLAN_ID_HOBBY
	RazorpayTestPlanIDHobbyPlus string // RAZORPAY_TEST_PLAN_ID_HOBBY_PLUS
	RazorpayTestPlanIDPro       string // RAZORPAY_TEST_PLAN_ID_PRO
	ResendAPIKey                string
	// EmailProvider explicitly selects the outbound email backend. Accepted
	// values: "brevo" | "resend" | "noop". When empty, internal/email
	// auto-detects: BREVO_API_KEY > RESEND_API_KEY (≠ "CHANGE_ME") > noop.
	// Added 2026-05-14 to recover from the live RESEND_API_KEY="CHANGE_ME"
	// outage by routing through the already-provisioned BREVO_API_KEY.
	EmailProvider      string
	BrevoAPIKey        string // BREVO_API_KEY — Brevo Transactional Email API key
	EmailFromName      string // EMAIL_FROM_NAME — verified-sender display name (default "InstaNode")
	EmailFromAddress   string // EMAIL_FROM_ADDRESS — verified-sender email (default "noreply@instanode.dev")
	GitHubClientID     string
	GitHubClientSecret string
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURI  string // optional default redirect_uri for GET /auth/google/url
	EnabledServices    string
	Environment        string
	// TrustedProxyCIDRs is the comma-separated list of CIDR ranges that the
	// API will trust the X-Forwarded-For header from. Set this to the
	// load-balancer egress CIDRs (e.g. DOKS NodePool subnet) so that XFF is
	// only honoured from infra-internal hops, not from arbitrary public
	// callers. T13 P1-1 fix (BugHunt 2026-05-20).
	//
	// If empty, the API still reads c.IP() but Fiber falls back to
	// RemoteAddr (the direct TCP peer) for ratelimit / fingerprint /
	// audit — which is the safe default for a directly-internet-facing
	// deployment.
	//
	// Format examples: "10.0.0.0/8" or "10.244.0.0/16,10.245.0.0/16".
	TrustedProxyCIDRs        string
	RedisProvisionBackend    string // "local" or "upstash", default "local"
	RedisProvisionHost       string // Redis host for building connection strings, default "localhost"
	MongoAdminURI            string // MONGO_ADMIN_URI, e.g. mongodb://root:root@localhost:27017
	MongoHost                string // MONGO_HOST, e.g. localhost:27017
	PostgresProvisionBackend string // POSTGRES_PROVISION_BACKEND, default "local"
	NeonAPIKey               string // NEON_API_KEY
	NeonRegionID             string // NEON_REGION_ID, default "aws-us-east-1"
	PostgresCustomersURL     string // POSTGRES_CUSTOMERS_URL (for local backend)
	ProvisionerAddr          string // PROVISIONER_ADDR — if set, use gRPC provisioner; if empty, use local providers
	ProvisionerSecret        string // PROVISIONER_SECRET — metadata token sent to provisioner
	NATSHost                 string // NATS_HOST — host for building nats:// connection strings

	// Queue backend (MR-P0-5 — NATS per-tenant isolation, 2026-05-20).
	// QueueBackend selects the queueprovider implementation:
	//   "nats"        — operator-mode NATS with per-tenant accounts (the
	//                   target after cutover)
	//   "legacy_open" — pre-cutover unauthenticated NATS (default during
	//                   the staged-cutover window when NATS_OPERATOR_SEED
	//                   is unset)
	// New rows always default to auth_mode='isolated' on the row, but the
	// CREDENTIALS returned to the caller depend on the backend selection
	// here. Falls back to "legacy_open" when NATS_OPERATOR_SEED is empty so
	// the api can deploy before the operator runs `nsc generate`.
	QueueBackend         string // QUEUE_BACKEND — "nats" | "legacy_open" | "rabbitmq" | "kafka"
	NATSPublicHost       string // NATS_PUBLIC_HOST — hostname embedded in customer URLs (default nats.instanode.dev)
	NATSOperatorSeed     string // NATS_OPERATOR_SEED — operator NKey seed; empty = legacy_open fallback
	NATSSystemAccountKey string // NATS_SYSTEM_ACCOUNT_PUBLIC_KEY — system account public key
	NATSUseTLS           bool   // NATS_USE_TLS — true → tls:// URLs
	R2Endpoint           string // R2_ENDPOINT — R2 endpoint hostname (default: r2.instant.dev)
	R2BucketName         string // R2_BUCKET_NAME — shared R2 bucket name (default: instant-shared)
	R2APIToken           string // R2_API_TOKEN — Cloudflare API token; if empty, R2 is not used
	// Object storage backend for /storage/new (provider-agnostic).
	//
	// ObjectStoreBackend selects the credential-issuance strategy:
	//   "minio-admin" — self-hosted MinIO; uses madmin to mint per-customer
	//                   IAM users with prefix-scoped policies (hard isolation).
	//   "shared-key"  — DO Spaces / AWS S3 / GCS / R2 / B2 / Wasabi; returns
	//                   the platform's master credentials + a per-customer
	//                   prefix to every customer (trust-based isolation).
	// Defaults to "minio-admin" when ObjectStoreBackend is empty AND the
	// legacy MINIO_* env vars are set; otherwise "shared-key".
	ObjectStoreMode      string // OBJECT_STORE_MODE — "admin" (default) or "shared_key"; alias of ObjectStoreBackend
	ObjectStoreBackend   string // OBJECT_STORE_BACKEND — "minio-admin" or "shared-key" (legacy alias of OBJECT_STORE_MODE)
	ObjectStoreEndpoint  string // OBJECT_STORE_ENDPOINT — host:port for admin/bucket ops
	ObjectStorePublicURL string // OBJECT_STORE_PUBLIC_URL — customer-facing base, e.g. "https://s3.instanode.dev"
	ObjectStoreAccessKey string // OBJECT_STORE_ACCESS_KEY — master access key
	ObjectStoreSecretKey string // OBJECT_STORE_SECRET_KEY — master secret key
	ObjectStoreBucket    string // OBJECT_STORE_BUCKET — shared bucket (default: instant-shared)
	ObjectStoreRegion    string // OBJECT_STORE_REGION — e.g. "nyc3" for DO Spaces, "us-east-1" for AWS S3
	ObjectStoreSecure    bool   // OBJECT_STORE_SECURE — true for TLS-terminated endpoints (DO Spaces, AWS S3); default false for in-cluster MinIO

	// ObjectStoreAllowSharedKey is the explicit operator escape hatch that
	// permits shared-key mode in production. Without this flag, the router
	// refuses to start in shared-key mode when ENVIRONMENT=production —
	// surfacing the "every customer has the master key" loophole at boot
	// instead of letting it ship silently. Local dev sets ENVIRONMENT=development
	// so this flag has no effect there.
	ObjectStoreAllowSharedKey bool // OBJECT_STORE_ALLOW_SHARED_KEY — "true" to opt in

	// Legacy MINIO_* env vars — kept as a fallback so old deployments keep
	// working without an immediate env-var migration. New deployments should
	// set the OBJECT_STORE_* vars above and leave these empty.
	MinioEndpoint       string // MINIO_ENDPOINT — legacy alias for OBJECT_STORE_ENDPOINT
	MinioPublicEndpoint string // MINIO_PUBLIC_ENDPOINT — legacy alias for OBJECT_STORE_PUBLIC_URL
	MinioRootUser       string // MINIO_ROOT_USER — legacy alias for OBJECT_STORE_ACCESS_KEY
	MinioRootPassword   string // MINIO_ROOT_PASSWORD — legacy alias for OBJECT_STORE_SECRET_KEY
	MinioBucketName     string // MINIO_BUCKET_NAME — legacy alias for OBJECT_STORE_BUCKET
	DeployDomain        string // DEPLOY_DOMAIN — base domain for container deployments (default: instant.dev)

	// Compute provider for app hosting (Phase 6)
	ComputeProvider   string // COMPUTE_PROVIDER — "noop" or "k8s" (default: "noop")
	KubeNamespaceApps string // KUBE_NAMESPACE_APPS — namespace where user app Deployments run (default: "instant-apps")

	MetricsToken     string // METRICS_TOKEN — if set, required as Bearer token to access /metrics
	DashboardBaseURL string // DASHBOARD_BASE_URL — where to redirect onboarding flows (default: http://localhost:5173)

	// AnalyticsBackend selects the behavioral-intelligence custom-event sink
	// (common/analyticsevent). Read from ANALYTICS_BACKEND. One of "noop"
	// (default — drops every event, zero deps, never errors) or "newrelic"
	// (emits InstantFunnel/InstantFlowTest custom events via the existing
	// *newrelic.Application). Defaulting to "noop" makes funnel emission INERT
	// in any environment where New Relic is not configured — the safe,
	// fail-open default, so no separate feature flag is needed.
	AnalyticsBackend string

	// APIPublicURL is the externally-routable base URL the API runs at
	// — used to construct fully-qualified links in outbound emails
	// (deletion-confirm, etc). Empty in local dev where the dashboard
	// (DASHBOARD_BASE_URL) handles user-facing URL composition; set in
	// production to "https://api.instanode.dev" so an email click reaches
	// the public ingress, not the in-cluster ClusterIP. Read from
	// API_PUBLIC_URL.
	APIPublicURL string

	// DeletionConfirmationTTLMinutes is the lifetime of a pending_deletions
	// row before the worker's pending_deletion_expirer flips it to
	// 'expired'. Defaults to 15. Read from DELETION_CONFIRMATION_TTL_MINUTES.
	// Configurable post-deploy via ConfigMap so a misconfigured email
	// backend that delays delivery doesn't permanently strand users at the
	// default — flip to 30/60 and re-rollout.
	DeletionConfirmationTTLMinutes int

	// FamilyBindingsEnabled controls the "family:<root_id>" syntax in
	// POST /deploy/new resource_bindings (slice 4 of env-aware deployments).
	// Default true. Set FAMILY_BINDINGS_ENABLED=false to disable the resolver
	// path — with the flag off, "family:..." values pass through as raw strings
	// and fail token validation (deterministic disable for rollback).
	FamilyBindingsEnabled bool

	// DeploySourceImageEnabled gates the P2 multi-source "source=image" path
	// (deploy a prebuilt image instead of uploading source). Default FALSE:
	// the skip-Kaniko compute branch changes the live deploy path and can't be
	// validated in CI (no real cluster), so it stays off until the operator
	// flips DEPLOY_SOURCE_IMAGE_ENABLED=true after a canary. Off → /deploy/new
	// rejects source=image with 501; tarball deploys are unaffected.
	DeploySourceImageEnabled bool

	// DeploySourceGitEnabled gates the source=git deploy path (P3): the
	// platform points Kaniko at a git repo URL (shallow clone, optional
	// encrypted token for private repos) instead of an uploaded tarball.
	// Off → /deploy/new rejects source=git with 501; tarball/image unaffected.
	DeploySourceGitEnabled bool

	// DeployScaleToZeroEnabled gates scale-to-zero (idle descheduling, Task #54).
	// Default FALSE: the worker idle-scaler patches idle Deployments to
	// replicas=0 and the api wake path (POST /deploy/:id/wake) brings them back.
	// Off → the wake endpoint returns 501 and nothing in the api scales an app;
	// the worker idle-scaler is independently gated by its own
	// DEPLOY_SCALE_TO_ZERO_ENABLED env so the two services share the flag name.
	// Enabling it is an operator action (see infra runbook) after a canary.
	DeployScaleToZeroEnabled bool

	// ResourceCountCapsEnabled gates per-service resource-count enforcement
	// (Task #55). Default FALSE: when off, the count-check block in every
	// provision handler (db/vector/cache/nosql/storage) is skipped entirely —
	// zero behavior change, so shipping the caps cannot surprise-break an
	// existing heavy tenant with a 402. When on, each handler counts the team's
	// active resources of that type and rejects over-cap provisions with 402 +
	// agent_action, mirroring the always-on queue_count cap. Enabling it is an
	// operator action (kubectl set env RESOURCE_COUNT_CAPS_ENABLED=true) after a
	// usage audit so no current tenant is over the new per-tier caps.
	ResourceCountCapsEnabled bool

	// GitHub App (P4) — install-once push-to-deploy + short-lived installation
	// tokens for private-repo clones. Distinct from the GitHub OAuth *login* app
	// above (GitHubClientID/Secret). GitHubAppEnabled gates the whole feature:
	// off → /integrations/github/* and POST /webhooks/github reject with 501.
	// All values are operator k8s secrets (NOT ConfigMap) — the private key can
	// mint tokens for every installation.
	GitHubAppEnabled       bool
	GitHubAppID            string // GITHUB_APP_ID — numeric App ID (JWT iss)
	GitHubAppSlug          string // GITHUB_APP_SLUG — public slug for the install URL (github.com/apps/<slug>)
	GitHubAppPrivateKey    string // GITHUB_APP_PRIVATE_KEY — RSA PEM (RS256 signing)
	GitHubAppWebhookSecret string // GITHUB_APP_WEBHOOK_SECRET — X-Hub-Signature-256 HMAC key
	GitHubAppClientID      string // GITHUB_APP_CLIENT_ID — for the install/callback OAuth handshake
	GitHubAppClientSecret  string // GITHUB_APP_CLIENT_SECRET

	// Email-feedback webhook secrets. Each provider authenticates its
	// callbacks differently — these env vars give the handler the shared
	// secret (Brevo, SendGrid) or topic ARN (SES via SNS) it needs to
	// reject unsigned traffic. All three may be empty in local dev; the
	// handlers then 401 every request, which is the correct fail-closed
	// behavior for an unauthenticated public endpoint.
	BrevoWebhookSecret string // BREVO_WEBHOOK_SECRET — shared secret for HMAC-SHA256 verification
	SESSNSTopicARN     string // SES_SNS_SUBSCRIPTION_ARN — expected SNS TopicArn on inbound notifications
	SendGridWebhookKey string // SENDGRID_WEBHOOK_PUBLIC_KEY — ECDSA public key (reserved; SendGrid is stubbed today)

	// AdminPathPrefix is the unguessable URL segment under which the
	// founder-only customer-management endpoints register. When set,
	// admin routes mount at /api/v1/<prefix>/customers/... instead of
	// the guessable /api/v1/admin/customers/...
	//
	// Defense-in-depth on top of ADMIN_EMAILS:
	//   - Empty / unset → admin endpoints are NOT registered (closed by
	//     default). The whole surface returns 404. Operators who want
	//     admin access must opt in by setting this var.
	//   - len < 32     → fatal startup error. A weak prefix is worse
	//     than none — it gives a false sense of security.
	//   - non-alphanumeric → fatal startup error. The prefix is a URL
	//     segment; non-alphanumeric characters can collide with Fiber's
	//     route parser, percent-encoding, or path-traversal attempts.
	//
	// The prefix is treated as a secret with the same blast radius as
	// a session token — never logged, never echoed to non-admin callers,
	// only surfaced to admins via GET /auth/me's admin_path_prefix field.
	//
	// Generate with: openssl rand -hex 32 (yields 64 hex chars).
	AdminPathPrefix string

	// WorkerInternalJWTSecret is the HMAC secret used to verify JWTs on the
	// `/internal/teams/:id/terminate` route. The worker's
	// payment_grace_terminator dispatcher signs a short-lived (iat-bounded)
	// HS256 token with this secret and POSTs to the api; the api verifies
	// the signature, the `purpose: "internal_terminate"` claim, and that
	// the `team_id` claim matches the path param.
	//
	// MUST be distinct from JWTSecret. JWTSecret signs customer-facing
	// session + onboarding tokens; reusing the same key here would let a
	// stolen customer JWT (with a crafted `team_id` claim) terminate any
	// team if a future code path ever loosened the claim validation. The
	// two secrets live in independent k8s Secret objects (api's
	// instant-secrets and worker's instant-infra-secrets) so a compromise
	// of one does not auto-compromise the other.
	//
	// Empty → the internal-terminate route still registers but rejects
	// every call with 401 (fail-closed). Operators must set
	// WORKER_INTERNAL_JWT_SECRET in BOTH the api and the worker
	// (same value, generated via `openssl rand -hex 32`).
	WorkerInternalJWTSecret string

	// E2EAccountToken is the shared secret that guards the CI-only
	// ephemeral-test-account surface (POST/DELETE /internal/e2e/account).
	// CI mints real test-cohort accounts against PRODUCTION to run
	// integration tests, then reaps them — that is the only thing this
	// token authorizes.
	//
	// INERT BY DEFAULT (flag-protection): when this is empty, BOTH e2e
	// routes return 404 for every request, hiding the endpoint's
	// existence entirely. The endpoint cannot mint or reap a single
	// account until an operator sets E2E_ACCOUNT_TOKEN — so the surface
	// ships safe-by-default and is only "armed" in the environments
	// (CI/prod) where the secret is wired. The caller authenticates by
	// sending the exact value in the X-E2E-Token request header; the
	// handler does a crypto/subtle constant-time compare and 404s on any
	// mismatch (never 401/403 — a distinguishable status would leak that
	// the route exists).
	//
	// Distinct secret from JWTSecret and WorkerInternalJWTSecret: this
	// one authorizes account *creation/destruction*, a strictly more
	// dangerous capability than session-signing, so it gets its own key
	// and its own k8s Secret entry (generate via `openssl rand -hex 32`).
	E2EAccountToken string
}

// ErrMissingConfig is returned when a required env var is absent.
type ErrMissingConfig struct {
	Key string
}

func (e *ErrMissingConfig) Error() string {
	return fmt.Sprintf("required environment variable %q is not set", e.Key)
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func require(key string) string {
	v := os.Getenv(key)
	if v == "" {
		panic(&ErrMissingConfig{Key: key})
	}
	return v
}

// Load reads configuration from environment variables. Panics on missing required fields.
func Load() *Config {
	cfg := &Config{
		Port:                    getenv("PORT", "8080"),
		DatabaseURL:             require("DATABASE_URL"),
		CustomerDatabaseURL:     getenv("CUSTOMER_DATABASE_URL", ""),
		RedisURL:                getenv("REDIS_URL", "redis://localhost:6379"),
		JWTSecret:               strings.TrimSpace(require("JWT_SECRET")),
		AESKey:                  strings.TrimSpace(require("AES_KEY")),
		MaxMindLicenseKey:       os.Getenv("MAXMIND_LICENSE_KEY"),
		GeoLite2DBPath:          getenv("GEOLITE2_DB_PATH", "./GeoLite2-City.mmdb"),
		RazorpayKeyID:           os.Getenv("RAZORPAY_KEY_ID"),
		RazorpayKeySecret:       os.Getenv("RAZORPAY_KEY_SECRET"),
		RazorpayWebhookSecret:   os.Getenv("RAZORPAY_WEBHOOK_SECRET"),
		RazorpayPlanIDHobby:     os.Getenv("RAZORPAY_PLAN_ID_HOBBY"),
		RazorpayPlanIDHobbyPlus: os.Getenv("RAZORPAY_PLAN_ID_HOBBY_PLUS"),
		RazorpayPlanIDPro:       os.Getenv("RAZORPAY_PLAN_ID_PRO"),
		// D28 F3 (2026-05-21): Growth tier — was previously missing from
		// the env-mapping, causing every subscription.charged webhook for
		// a Growth customer to fall back to "hobby" and silently downgrade.
		RazorpayPlanIDGrowth: os.Getenv("RAZORPAY_PLAN_ID_GROWTH"),
		RazorpayPlanIDTeam:   os.Getenv("RAZORPAY_PLAN_ID_TEAM"),
		// 2026-05-15: the live instant-secrets uses the `_ANNUAL` suffix
		// for every yearly plan id. config.go previously read `_YEARLY`
		// for Hobby + Pro (only HobbyPlus read `_ANNUAL`), so os.Getenv
		// returned "" and yearly checkout 503'd with
		// "Razorpay credentials/plans not configured". All four now read
		// `_ANNUAL` consistently — matching the secret. (Hobby Plus and
		// Team annual keys aren't in the secret yet; those tiers aren't
		// a public yearly checkout path, so an empty value is acceptable
		// until their Razorpay plans are created.)
		RazorpayPlanIDHobbyYearly:     os.Getenv("RAZORPAY_PLAN_ID_HOBBY_ANNUAL"),
		RazorpayPlanIDHobbyPlusYearly: os.Getenv("RAZORPAY_PLAN_ID_HOBBY_PLUS_ANNUAL"),
		RazorpayPlanIDProYearly:       os.Getenv("RAZORPAY_PLAN_ID_PRO_ANNUAL"),
		RazorpayPlanIDGrowthYearly:    os.Getenv("RAZORPAY_PLAN_ID_GROWTH_ANNUAL"),
		RazorpayPlanIDTeamYearly:      os.Getenv("RAZORPAY_PLAN_ID_TEAM_ANNUAL"),

		// Razorpay TEST-mode (rzp_test_*) creds for the synthetic test cohort
		// only. All default "" (inert) — see the struct doc above (Wave 4b).
		RazorpayTestKeyID:           os.Getenv("RAZORPAY_TEST_KEY_ID"),
		RazorpayTestKeySecret:       os.Getenv("RAZORPAY_TEST_KEY_SECRET"),
		RazorpayTestWebhookSecret:   os.Getenv("RAZORPAY_TEST_WEBHOOK_SECRET"),
		RazorpayTestPlanIDHobby:     os.Getenv("RAZORPAY_TEST_PLAN_ID_HOBBY"),
		RazorpayTestPlanIDHobbyPlus: os.Getenv("RAZORPAY_TEST_PLAN_ID_HOBBY_PLUS"),
		RazorpayTestPlanIDPro:       os.Getenv("RAZORPAY_TEST_PLAN_ID_PRO"),
		ResendAPIKey:                os.Getenv("RESEND_API_KEY"),
		EmailProvider:               os.Getenv("EMAIL_PROVIDER"),
		BrevoAPIKey:                 os.Getenv("BREVO_API_KEY"),
		EmailFromName:               os.Getenv("EMAIL_FROM_NAME"),
		EmailFromAddress:            os.Getenv("EMAIL_FROM_ADDRESS"),
		GitHubClientID:              os.Getenv("GITHUB_CLIENT_ID"),
		GitHubClientSecret:          os.Getenv("GITHUB_CLIENT_SECRET"),
		GoogleClientID:              os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret:          os.Getenv("GOOGLE_CLIENT_SECRET"),
		GoogleRedirectURI:           os.Getenv("GOOGLE_REDIRECT_URI"),
		EnabledServices:             getenv("INSTANT_ENABLED_SERVICES", "redis,postgres,mongodb,queue"),
		Environment:                 getenv("ENVIRONMENT", "development"),
		TrustedProxyCIDRs:           os.Getenv("TRUSTED_PROXY_CIDRS"),
		RedisProvisionBackend:       getenv("REDIS_PROVISION_BACKEND", "local"),
		RedisProvisionHost:          getenv("REDIS_PROVISION_HOST", "localhost"),
		MongoAdminURI:               getenv("MONGO_ADMIN_URI", "mongodb://root:root@localhost:27017"),
		MongoHost:                   getenv("MONGO_HOST", "localhost:27017"),
		PostgresProvisionBackend:    getenv("POSTGRES_PROVISION_BACKEND", "local"),
		NeonAPIKey:                  os.Getenv("NEON_API_KEY"),
		NeonRegionID:                getenv("NEON_REGION_ID", "aws-us-east-1"),
		PostgresCustomersURL:        getenv("POSTGRES_CUSTOMERS_URL", "postgres://postgres:postgres@postgres-customers:5432/postgres"),
	}
	cfg.ProvisionerAddr = os.Getenv("PROVISIONER_ADDR") // intentionally empty = use local providers
	cfg.ProvisionerSecret = os.Getenv("PROVISIONER_SECRET")
	cfg.NATSHost = getenv("NATS_HOST", "nats.instant-data.svc.cluster.local")

	// Queue backend selection (MR-P0-5 — NATS per-tenant isolation).
	// Defaults to "nats" — but the `nats` provider itself transparently
	// degrades to legacy_open creds when NATSOperatorSeed is unset, so
	// deploys before the operator key generation still work.
	cfg.QueueBackend = getenv("QUEUE_BACKEND", "nats")
	cfg.NATSPublicHost = getenv("NATS_PUBLIC_HOST", "nats.instanode.dev")
	cfg.NATSOperatorSeed = os.Getenv("NATS_OPERATOR_SEED")
	cfg.NATSSystemAccountKey = os.Getenv("NATS_SYSTEM_ACCOUNT_PUBLIC_KEY")
	cfg.NATSUseTLS = os.Getenv("NATS_USE_TLS") == "true"
	cfg.R2Endpoint = getenv("R2_ENDPOINT", "r2.instant.dev")
	cfg.R2BucketName = getenv("R2_BUCKET_NAME", "instant-shared")
	cfg.R2APIToken = os.Getenv("R2_API_TOKEN")
	// New provider-agnostic object-storage env vars. Fall back to the legacy
	// MINIO_* names so deployments without OBJECT_STORE_* set keep working
	// unchanged (the LoadFromEnv tail below resolves the effective values).
	cfg.ObjectStoreMode = os.Getenv("OBJECT_STORE_MODE")
	cfg.ObjectStoreBackend = os.Getenv("OBJECT_STORE_BACKEND")
	cfg.ObjectStoreEndpoint = os.Getenv("OBJECT_STORE_ENDPOINT")
	cfg.ObjectStorePublicURL = os.Getenv("OBJECT_STORE_PUBLIC_URL")
	cfg.ObjectStoreAccessKey = os.Getenv("OBJECT_STORE_ACCESS_KEY")
	cfg.ObjectStoreSecretKey = os.Getenv("OBJECT_STORE_SECRET_KEY")
	cfg.ObjectStoreBucket = getenv("OBJECT_STORE_BUCKET", "instant-shared")
	cfg.ObjectStoreRegion = os.Getenv("OBJECT_STORE_REGION")
	cfg.ObjectStoreSecure = os.Getenv("OBJECT_STORE_SECURE") == "true"
	cfg.ObjectStoreAllowSharedKey = os.Getenv("OBJECT_STORE_ALLOW_SHARED_KEY") == "true"

	cfg.MinioEndpoint = os.Getenv("MINIO_ENDPOINT")
	cfg.MinioPublicEndpoint = os.Getenv("MINIO_PUBLIC_ENDPOINT")
	cfg.MinioRootUser = os.Getenv("MINIO_ROOT_USER")
	cfg.MinioRootPassword = os.Getenv("MINIO_ROOT_PASSWORD")
	cfg.MinioBucketName = getenv("MINIO_BUCKET_NAME", "instant-shared")

	// Effective object-storage config: prefer new OBJECT_STORE_* names;
	// fall back to legacy MINIO_* for backward compat.
	if cfg.ObjectStoreEndpoint == "" {
		cfg.ObjectStoreEndpoint = cfg.MinioEndpoint
	}
	if cfg.ObjectStorePublicURL == "" {
		cfg.ObjectStorePublicURL = cfg.MinioPublicEndpoint
	}
	if cfg.ObjectStoreAccessKey == "" {
		cfg.ObjectStoreAccessKey = cfg.MinioRootUser
	}
	if cfg.ObjectStoreSecretKey == "" {
		cfg.ObjectStoreSecretKey = cfg.MinioRootPassword
	}
	if cfg.ObjectStoreBucket == "instant-shared" && cfg.MinioBucketName != "" && cfg.MinioBucketName != "instant-shared" {
		cfg.ObjectStoreBucket = cfg.MinioBucketName
	}
	// Mode resolution precedence:
	//   1. OBJECT_STORE_MODE (new, operator-facing name)
	//   2. OBJECT_STORE_BACKEND (legacy alias)
	//   3. Default → "admin" (BackendMinIOAdmin). This is the secure
	//      default that closes the shared-key isolation loophole.
	//      Shared-key mode is now opt-in via OBJECT_STORE_MODE=shared_key
	//      (or =shared-key); production additionally requires
	//      OBJECT_STORE_ALLOW_SHARED_KEY=true to actually start.
	if cfg.ObjectStoreMode == "" {
		cfg.ObjectStoreMode = cfg.ObjectStoreBackend
	}
	if cfg.ObjectStoreBackend == "" {
		cfg.ObjectStoreBackend = cfg.ObjectStoreMode
	}
	if cfg.ObjectStoreMode == "" {
		cfg.ObjectStoreMode = "admin"
		cfg.ObjectStoreBackend = "minio-admin"
	}
	// Email-feedback webhook auth secrets. Empty values → handler rejects
	// every inbound webhook (fail-closed). Operators MUST set these in
	// production; absence is logged via the BrevoWebhookSecret_set etc.
	// flags emitted by logStartupConfig.
	cfg.BrevoWebhookSecret = os.Getenv("BREVO_WEBHOOK_SECRET")
	cfg.SESSNSTopicARN = os.Getenv("SES_SNS_SUBSCRIPTION_ARN")
	cfg.SendGridWebhookKey = os.Getenv("SENDGRID_WEBHOOK_PUBLIC_KEY")

	cfg.WorkerInternalJWTSecret = strings.TrimSpace(os.Getenv("WORKER_INTERNAL_JWT_SECRET"))
	// E2E_ACCOUNT_TOKEN: empty = the /internal/e2e/* surface is inert
	// (every call 404s). See Config.E2EAccountToken for the full posture.
	cfg.E2EAccountToken = strings.TrimSpace(os.Getenv("E2E_ACCOUNT_TOKEN"))
	cfg.DeployDomain = getenv("DEPLOY_DOMAIN", "instant.dev")
	cfg.ComputeProvider = getenv("COMPUTE_PROVIDER", "noop")
	cfg.KubeNamespaceApps = getenv("KUBE_NAMESPACE_APPS", "instant-apps")
	cfg.MetricsToken = os.Getenv("METRICS_TOKEN")              // empty = open (local dev)
	cfg.AnalyticsBackend = getenv("ANALYTICS_BACKEND", "noop") // noop = inert (no NR sink)
	cfg.DashboardBaseURL = getenv("DASHBOARD_BASE_URL", "http://localhost:5173")
	cfg.APIPublicURL = strings.TrimRight(getenv("API_PUBLIC_URL", ""), "/")
	// Parse DELETION_CONFIRMATION_TTL_MINUTES; fall back to 15 on
	// empty/invalid. We deliberately accept an invalid value silently
	// (rather than panic) because a typo on a periphery env var should
	// never stop the api from booting — the default is safe and the WARN
	// log surfaces the bad value to operators.
	cfg.DeletionConfirmationTTLMinutes = 15
	if raw := strings.TrimSpace(os.Getenv("DELETION_CONFIRMATION_TTL_MINUTES")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			cfg.DeletionConfirmationTTLMinutes = n
		} else {
			slog.Warn("config.deletion_confirmation_ttl.invalid",
				"raw", raw,
				"fallback_minutes", cfg.DeletionConfirmationTTLMinutes,
				"note", "set DELETION_CONFIRMATION_TTL_MINUTES to a positive integer to override",
			)
		}
	}
	// FAMILY_BINDINGS_ENABLED: default true. Only "false" / "0" disables.
	switch strings.ToLower(strings.TrimSpace(os.Getenv("FAMILY_BINDINGS_ENABLED"))) {
	case "false", "0", "no":
		cfg.FamilyBindingsEnabled = false
	default:
		cfg.FamilyBindingsEnabled = true
	}

	// DEPLOY_SOURCE_IMAGE_ENABLED: default FALSE (off until operator canary).
	switch strings.ToLower(strings.TrimSpace(os.Getenv("DEPLOY_SOURCE_IMAGE_ENABLED"))) {
	case "true", "1", "yes":
		cfg.DeploySourceImageEnabled = true
	default:
		cfg.DeploySourceImageEnabled = false
	}

	// DEPLOY_SOURCE_GIT_ENABLED: default FALSE (off until operator canary).
	switch strings.ToLower(strings.TrimSpace(os.Getenv("DEPLOY_SOURCE_GIT_ENABLED"))) {
	case "true", "1", "yes":
		cfg.DeploySourceGitEnabled = true
	default:
		cfg.DeploySourceGitEnabled = false
	}

	// DEPLOY_SCALE_TO_ZERO_ENABLED: default FALSE (off until operator canary).
	// Shared flag name with the worker idle-scaler; the api half gates the wake
	// endpoint + any api-initiated scale, the worker half gates the idle sweep.
	switch strings.ToLower(strings.TrimSpace(os.Getenv("DEPLOY_SCALE_TO_ZERO_ENABLED"))) {
	case "true", "1", "yes":
		cfg.DeployScaleToZeroEnabled = true
	default:
		cfg.DeployScaleToZeroEnabled = false
	}

	// RESOURCE_COUNT_CAPS_ENABLED: default FALSE (Task #55). Off → the per-service
	// count-check block in every provision handler is skipped (zero behavior
	// change). On → over-cap provisions get 402. Operator action after a usage
	// audit so no current tenant is retroactively over a new per-tier cap.
	switch strings.ToLower(strings.TrimSpace(os.Getenv("RESOURCE_COUNT_CAPS_ENABLED"))) {
	case "true", "1", "yes":
		cfg.ResourceCountCapsEnabled = true
	default:
		cfg.ResourceCountCapsEnabled = false
	}

	// GITHUB_APP_ENABLED: default FALSE (off until the operator registers the
	// App and provisions GITHUB_APP_* secrets — see infra/GITHUB-APP-RUNBOOK.md).
	switch strings.ToLower(strings.TrimSpace(os.Getenv("GITHUB_APP_ENABLED"))) {
	case "true", "1", "yes":
		cfg.GitHubAppEnabled = true
	default:
		cfg.GitHubAppEnabled = false
	}
	cfg.GitHubAppID = os.Getenv("GITHUB_APP_ID")
	cfg.GitHubAppSlug = os.Getenv("GITHUB_APP_SLUG")
	cfg.GitHubAppPrivateKey = os.Getenv("GITHUB_APP_PRIVATE_KEY")
	cfg.GitHubAppWebhookSecret = os.Getenv("GITHUB_APP_WEBHOOK_SECRET")
	cfg.GitHubAppClientID = os.Getenv("GITHUB_APP_CLIENT_ID")
	cfg.GitHubAppClientSecret = os.Getenv("GITHUB_APP_CLIENT_SECRET")
	// Fail-closed when the App is enabled: an empty GITHUB_APP_WEBHOOK_SECRET
	// makes the webhook HMAC verifiable with a publicly-known (empty) key — any
	// attacker could forge a valid X-Hub-Signature-256. Likewise an empty
	// private key / App ID can't mint tokens. Panic at Load (like JWT_SECRET)
	// rather than silently serve an auth-bypassing webhook. (Review HIGH-1.)
	if cfg.GitHubAppEnabled {
		if len(strings.TrimSpace(cfg.GitHubAppWebhookSecret)) < 16 {
			panic(&ErrMissingConfig{Key: "GITHUB_APP_WEBHOOK_SECRET (>=16 chars required when GITHUB_APP_ENABLED=true)"})
		}
		if strings.TrimSpace(cfg.GitHubAppPrivateKey) == "" {
			panic(&ErrMissingConfig{Key: "GITHUB_APP_PRIVATE_KEY (required when GITHUB_APP_ENABLED=true)"})
		}
		if strings.TrimSpace(cfg.GitHubAppID) == "" {
			panic(&ErrMissingConfig{Key: "GITHUB_APP_ID (required when GITHUB_APP_ENABLED=true)"})
		}
	}

	if len(cfg.JWTSecret) < 32 {
		panic("JWT_SECRET must be at least 32 bytes")
	}
	if len(cfg.AESKey) != 64 {
		panic("AES_KEY must be exactly 32 bytes hex-encoded (64 hex chars)")
	}

	// Admin-path-prefix validation. See AdminPathPrefix field doc above.
	cfg.AdminPathPrefix = strings.TrimSpace(os.Getenv("ADMIN_PATH_PREFIX"))
	if err := validateAdminPathPrefix(cfg.AdminPathPrefix); err != nil {
		panic(err.Error())
	}
	if cfg.AdminPathPrefix == "" {
		// Closed by default. Log loudly so operators know the admin
		// surface is unreachable from the network until they set the
		// env var. Use Warn (not Info) to surface in dashboards that
		// filter at Warn+ level.
		slog.Warn("admin.endpoints.disabled",
			"reason", "ADMIN_PATH_PREFIX is empty or unset",
			"impact", "admin routes are NOT registered; the entire /api/v1/<prefix>/customers surface returns 404",
		)
	} else {
		// Never log the prefix value itself — it's a credential. Just
		// log that it's configured so operators can confirm wiring.
		slog.Info("admin.endpoints.enabled",
			"prefix_len", len(cfg.AdminPathPrefix),
		)
	}

	logStartupConfig(cfg)
	return cfg
}

// validateAdminPathPrefix enforces the safety properties documented on
// Config.AdminPathPrefix:
//
//   - Empty → OK (closed-by-default; caller must skip route registration).
//   - len < 32 → error (a short prefix offers no obscurity benefit and
//     gives a false sense of security).
//   - Non-alphanumeric → error (prefix is a URL segment; bytes outside
//     [A-Za-z0-9] can collide with Fiber's router, trigger percent-encoding
//     edge cases, or be confused with path-traversal attempts).
//
// Exported as a free function (not a method) so tests can drive it directly
// without constructing a Config.
func validateAdminPathPrefix(p string) error {
	if p == "" {
		return nil // closed by default; caller skips registration
	}
	if len(p) < 32 {
		return fmt.Errorf("ADMIN_PATH_PREFIX must be at least 32 characters (got %d) — generate via `openssl rand -hex 32`", len(p))
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		default:
			return fmt.Errorf("ADMIN_PATH_PREFIX must be alphanumeric only (offending byte 0x%02x at index %d) — generate via `openssl rand -hex 32`", c, i)
		}
	}
	return nil
}

// ValidateAdminPathPrefix is the exported wrapper around validateAdminPathPrefix
// for tests that don't want to build a full Config and exercise Load's panic
// behavior. Returns nil for empty (closed-by-default) and a structured error
// for any rejected value.
func ValidateAdminPathPrefix(p string) error {
	return validateAdminPathPrefix(p)
}

// IsServiceEnabled reports whether serviceName appears in the comma-separated EnabledServices list.
func (c *Config) IsServiceEnabled(serviceName string) bool {
	for _, s := range strings.Split(c.EnabledServices, ",") {
		if strings.TrimSpace(s) == serviceName {
			return true
		}
	}
	return false
}

// warnIfMetricsTokenMissing emits a loud startup WARN when /metrics is
// publicly readable in a non-development environment. SRR security-
// cluster 2026-05-21 / C19 P0 / PB03: the prod api on 2026-05-21 was
// serving /metrics with no auth because METRICS_TOKEN was unset; the
// exposed counters leaked internal infra topology + abuse-block rates
// to anyone on the public internet. Silent fallthrough hid this from
// the operator. Promoting it to a startup WARN ensures it lands in
// k8s `kubectl logs` and any log aggregator on the first boot after
// the env var is dropped.
//
// We intentionally do NOT fail-closed (panic / refuse to boot) — the
// local-dev / docker-compose flow runs without METRICS_TOKEN by design
// (open metrics is the cheapest dev affordance), and the equivalent
// flag flip on the worker / provisioner sidecars would also need to be
// fail-closed for consistency. Loud WARN is the appropriate guardrail:
// the operator sees the gap in the first deploy log, has time to
// rotate a token, and we don't accidentally hard-bounce prod over a
// monitoring side-channel.
//
// Split out so the path is independently testable
// (TestWarnIfMetricsTokenMissing_Prod_Emits etc.).
func warnIfMetricsTokenMissing(cfg *Config) {
	if cfg.MetricsToken != "" {
		return
	}
	// In local dev metrics-open is intentional; emit nothing.
	if cfg.Environment == "development" || cfg.Environment == "test" {
		return
	}
	slog.Warn("config.metrics_token.missing",
		"environment", cfg.Environment,
		"impact", "Prometheus /metrics endpoint is publicly readable — internal infra topology, abuse-block rates, and circuit-breaker state leak to any caller",
		"fix", "set METRICS_TOKEN to a random 32-byte hex (openssl rand -hex 32) and update the Prometheus scrape config to send Authorization: Bearer <token>",
	)
}

func logStartupConfig(cfg *Config) {
	warnIfMetricsTokenMissing(cfg)
	slog.Info("config.loaded",
		"port", cfg.Port,
		"environment", cfg.Environment,
		"enabled_services", cfg.EnabledServices,
		"geolite2_db_path", cfg.GeoLite2DBPath,
		"database_url", mask(cfg.DatabaseURL),
		"customer_database_url_set", cfg.CustomerDatabaseURL != "",
		"redis_url", mask(cfg.RedisURL),
		"jwt_secret", maskSecret(cfg.JWTSecret),
		"aes_key", maskSecret(cfg.AESKey),
		"razorpay_key_set", cfg.RazorpayKeyID != "",
		"resend_key_set", cfg.ResendAPIKey != "" && cfg.ResendAPIKey != "CHANGE_ME",
		"brevo_key_set", cfg.BrevoAPIKey != "",
		"email_provider", cfg.EmailProvider,
		"email_from_address_set", cfg.EmailFromAddress != "",
		"github_oauth_set", cfg.GitHubClientID != "",
		"google_oauth_set", cfg.GoogleClientID != "",
		"google_redirect_uri_set", cfg.GoogleRedirectURI != "",
		"redis_provision_backend", cfg.RedisProvisionBackend,
		"redis_provision_host", cfg.RedisProvisionHost,
		"mongo_admin_uri", mask(cfg.MongoAdminURI),
		"mongo_host", cfg.MongoHost,
		"postgres_provision_backend", cfg.PostgresProvisionBackend,
		"postgres_customers_url", mask(cfg.PostgresCustomersURL),
		"neon_region_id", cfg.NeonRegionID,
		"nats_host", cfg.NATSHost,
		"r2_endpoint", cfg.R2Endpoint,
		"r2_bucket_name", cfg.R2BucketName,
		"minio_endpoint", cfg.MinioEndpoint,
		"minio_public_endpoint", cfg.MinioPublicEndpoint,
		"minio_bucket_name", cfg.MinioBucketName,
		"object_store_mode", cfg.ObjectStoreMode,
		"object_store_backend", cfg.ObjectStoreBackend,
		"object_store_endpoint_set", cfg.ObjectStoreEndpoint != "",
		"object_store_bucket", cfg.ObjectStoreBucket,
		"object_store_secure", cfg.ObjectStoreSecure,
		"object_store_allow_shared_key", cfg.ObjectStoreAllowSharedKey,
		"deploy_domain", cfg.DeployDomain,
		"compute_provider", cfg.ComputeProvider,
		"kube_namespace_apps", cfg.KubeNamespaceApps,
		"dashboard_base_url", cfg.DashboardBaseURL,
	)
}

func mask(s string) string {
	if len(s) <= 12 {
		return "***"
	}
	return s[:8] + "***" + s[len(s)-4:]
}

func maskSecret(s string) string {
	if len(s) == 0 {
		return ""
	}
	return s[:4] + strings.Repeat("*", len(s)-4)
}
