package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// Config holds all runtime configuration for the platform.
type Config struct {
	Port                     string
	DatabaseURL              string // platform DB: teams, users, resources
	CustomerDatabaseURL      string // customer DB: provisioned db_{token} databases (Phase 2+)
	RedisURL                 string
	JWTSecret                string
	AESKey                   string
	MaxMindLicenseKey        string
	GeoLite2DBPath           string
	RazorpayKeyID            string // RAZORPAY_KEY_ID — API key ID (used server-side)
	RazorpayKeySecret        string // RAZORPAY_KEY_SECRET — API key secret
	RazorpayWebhookSecret    string // RAZORPAY_WEBHOOK_SECRET — webhook signature verification
	RazorpayPlanIDHobby      string // RAZORPAY_PLAN_ID_HOBBY — plan_id for hobby tier
	RazorpayPlanIDPro        string // RAZORPAY_PLAN_ID_PRO — plan_id for pro tier
	RazorpayPlanIDTeam       string // RAZORPAY_PLAN_ID_TEAM — plan_id for team tier
	ResendAPIKey             string
	GitHubClientID           string
	GitHubClientSecret       string
	GoogleClientID           string
	GoogleClientSecret       string
	GoogleRedirectURI        string // optional default redirect_uri for GET /auth/google/url
	EnabledServices          string
	Environment              string
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
	R2Endpoint               string // R2_ENDPOINT — R2 endpoint hostname (default: r2.instant.dev)
	R2BucketName             string // R2_BUCKET_NAME — shared R2 bucket name (default: instant-shared)
	R2APIToken               string // R2_API_TOKEN — Cloudflare API token; if empty, R2 is not used
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
	ObjectStoreBackend    string // OBJECT_STORE_BACKEND — "minio-admin" or "shared-key"
	ObjectStoreEndpoint   string // OBJECT_STORE_ENDPOINT — host:port for admin/bucket ops
	ObjectStorePublicURL  string // OBJECT_STORE_PUBLIC_URL — customer-facing base, e.g. "https://s3.instanode.dev"
	ObjectStoreAccessKey  string // OBJECT_STORE_ACCESS_KEY — master access key
	ObjectStoreSecretKey  string // OBJECT_STORE_SECRET_KEY — master secret key
	ObjectStoreBucket     string // OBJECT_STORE_BUCKET — shared bucket (default: instant-shared)
	ObjectStoreRegion     string // OBJECT_STORE_REGION — e.g. "nyc3" for DO Spaces, "us-east-1" for AWS S3
	ObjectStoreSecure     bool   // OBJECT_STORE_SECURE — true for TLS-terminated endpoints (DO Spaces, AWS S3); default false for in-cluster MinIO

	// Legacy MINIO_* env vars — kept as a fallback so old deployments keep
	// working without an immediate env-var migration. New deployments should
	// set the OBJECT_STORE_* vars above and leave these empty.
	MinioEndpoint       string // MINIO_ENDPOINT — legacy alias for OBJECT_STORE_ENDPOINT
	MinioPublicEndpoint string // MINIO_PUBLIC_ENDPOINT — legacy alias for OBJECT_STORE_PUBLIC_URL
	MinioRootUser       string // MINIO_ROOT_USER — legacy alias for OBJECT_STORE_ACCESS_KEY
	MinioRootPassword   string // MINIO_ROOT_PASSWORD — legacy alias for OBJECT_STORE_SECRET_KEY
	MinioBucketName     string // MINIO_BUCKET_NAME — legacy alias for OBJECT_STORE_BUCKET
	DeployDomain      string // DEPLOY_DOMAIN — base domain for container deployments (default: instant.dev)

	// Compute provider for app hosting (Phase 6)
	ComputeProvider   string // COMPUTE_PROVIDER — "noop" or "k8s" (default: "noop")
	KubeNamespaceApps string // KUBE_NAMESPACE_APPS — namespace where user app Deployments run (default: "instant-apps")

	MetricsToken     string // METRICS_TOKEN — if set, required as Bearer token to access /metrics
	DashboardBaseURL string // DASHBOARD_BASE_URL — where to redirect onboarding flows (default: http://localhost:5173)
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
		Port:                     getenv("PORT", "8080"),
		DatabaseURL:              require("DATABASE_URL"),
		CustomerDatabaseURL:      getenv("CUSTOMER_DATABASE_URL", ""),
		RedisURL:                 getenv("REDIS_URL", "redis://localhost:6379"),
		JWTSecret:                strings.TrimSpace(require("JWT_SECRET")),
		AESKey:                   strings.TrimSpace(require("AES_KEY")),
		MaxMindLicenseKey:        os.Getenv("MAXMIND_LICENSE_KEY"),
		GeoLite2DBPath:           getenv("GEOLITE2_DB_PATH", "./GeoLite2-City.mmdb"),
		RazorpayKeyID:            os.Getenv("RAZORPAY_KEY_ID"),
		RazorpayKeySecret:        os.Getenv("RAZORPAY_KEY_SECRET"),
		RazorpayWebhookSecret:    os.Getenv("RAZORPAY_WEBHOOK_SECRET"),
		RazorpayPlanIDHobby:      os.Getenv("RAZORPAY_PLAN_ID_HOBBY"),
		RazorpayPlanIDPro:        os.Getenv("RAZORPAY_PLAN_ID_PRO"),
		RazorpayPlanIDTeam:       os.Getenv("RAZORPAY_PLAN_ID_TEAM"),
		ResendAPIKey:             os.Getenv("RESEND_API_KEY"),
		GitHubClientID:           os.Getenv("GITHUB_CLIENT_ID"),
		GitHubClientSecret:       os.Getenv("GITHUB_CLIENT_SECRET"),
		GoogleClientID:           os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret:       os.Getenv("GOOGLE_CLIENT_SECRET"),
		GoogleRedirectURI:        os.Getenv("GOOGLE_REDIRECT_URI"),
		EnabledServices:          getenv("INSTANT_ENABLED_SERVICES", "redis,postgres,mongodb,queue"),
		Environment:              getenv("ENVIRONMENT", "development"),
		RedisProvisionBackend:    getenv("REDIS_PROVISION_BACKEND", "local"),
		RedisProvisionHost:       getenv("REDIS_PROVISION_HOST", "localhost"),
		MongoAdminURI:            getenv("MONGO_ADMIN_URI", "mongodb://root:root@localhost:27017"),
		MongoHost:                getenv("MONGO_HOST", "localhost:27017"),
		PostgresProvisionBackend: getenv("POSTGRES_PROVISION_BACKEND", "local"),
		NeonAPIKey:               os.Getenv("NEON_API_KEY"),
		NeonRegionID:             getenv("NEON_REGION_ID", "aws-us-east-1"),
		PostgresCustomersURL:     getenv("POSTGRES_CUSTOMERS_URL", "postgres://postgres:postgres@postgres-customers:5432/postgres"),
	}
	cfg.ProvisionerAddr = os.Getenv("PROVISIONER_ADDR") // intentionally empty = use local providers
	cfg.ProvisionerSecret = os.Getenv("PROVISIONER_SECRET")
	cfg.NATSHost = getenv("NATS_HOST", "nats.instant-data.svc.cluster.local")
	cfg.R2Endpoint = getenv("R2_ENDPOINT", "r2.instant.dev")
	cfg.R2BucketName = getenv("R2_BUCKET_NAME", "instant-shared")
	cfg.R2APIToken = os.Getenv("R2_API_TOKEN")
	// New provider-agnostic object-storage env vars. Fall back to the legacy
	// MINIO_* names so deployments without OBJECT_STORE_* set keep working
	// unchanged (the LoadFromEnv tail below resolves the effective values).
	cfg.ObjectStoreBackend = os.Getenv("OBJECT_STORE_BACKEND")
	cfg.ObjectStoreEndpoint = os.Getenv("OBJECT_STORE_ENDPOINT")
	cfg.ObjectStorePublicURL = os.Getenv("OBJECT_STORE_PUBLIC_URL")
	cfg.ObjectStoreAccessKey = os.Getenv("OBJECT_STORE_ACCESS_KEY")
	cfg.ObjectStoreSecretKey = os.Getenv("OBJECT_STORE_SECRET_KEY")
	cfg.ObjectStoreBucket = getenv("OBJECT_STORE_BUCKET", "instant-shared")
	cfg.ObjectStoreRegion = os.Getenv("OBJECT_STORE_REGION")
	cfg.ObjectStoreSecure = os.Getenv("OBJECT_STORE_SECURE") == "true"

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
	if cfg.ObjectStoreBackend == "" {
		// Default to minio-admin when the legacy MINIO_* vars are present
		// (preserves existing behavior); shared-key otherwise.
		if cfg.MinioEndpoint != "" {
			cfg.ObjectStoreBackend = "minio-admin"
		} else {
			cfg.ObjectStoreBackend = "shared-key"
		}
	}
	cfg.DeployDomain = getenv("DEPLOY_DOMAIN", "instant.dev")
	cfg.ComputeProvider = getenv("COMPUTE_PROVIDER", "noop")
	cfg.KubeNamespaceApps = getenv("KUBE_NAMESPACE_APPS", "instant-apps")
	cfg.MetricsToken = os.Getenv("METRICS_TOKEN") // empty = open (local dev)
	cfg.DashboardBaseURL = getenv("DASHBOARD_BASE_URL", "http://localhost:5173")

	if len(cfg.JWTSecret) < 32 {
		panic("JWT_SECRET must be at least 32 bytes")
	}
	if len(cfg.AESKey) != 64 {
		panic("AES_KEY must be exactly 32 bytes hex-encoded (64 hex chars)")
	}

	logStartupConfig(cfg)
	return cfg
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

func logStartupConfig(cfg *Config) {
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
		"resend_key_set", cfg.ResendAPIKey != "",
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
