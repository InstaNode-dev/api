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
	MigratorAddr             string // MIGRATOR_ADDR — HTTP address of the migrator service
	MigratorSecret           string // MIGRATOR_SECRET — shared secret for migrator HTTP API
	NATSHost                 string // NATS_HOST — host for building nats:// connection strings
	R2Endpoint               string // R2_ENDPOINT — R2 endpoint hostname (default: r2.instant.dev)
	R2BucketName             string // R2_BUCKET_NAME — shared R2 bucket name (default: instant-shared)
	R2APIToken               string // R2_API_TOKEN — Cloudflare API token; if empty, R2 is not used
	// MinIO S3-compatible storage (local dev backend for /storage/new)
	MinioEndpoint     string // MINIO_ENDPOINT — host:port (e.g. minio.instant-data.svc.cluster.local:9000)
	MinioRootUser     string // MINIO_ROOT_USER — admin access key
	MinioRootPassword string // MINIO_ROOT_PASSWORD — admin secret key
	MinioBucketName   string // MINIO_BUCKET_NAME — shared bucket (default: instant-shared)
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
		JWTSecret:                require("JWT_SECRET"),
		AESKey:                   require("AES_KEY"),
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
	cfg.MigratorAddr = os.Getenv("MIGRATOR_ADDR")
	cfg.MigratorSecret = os.Getenv("MIGRATOR_SECRET")
	cfg.NATSHost = getenv("NATS_HOST", "nats.instant-data.svc.cluster.local")
	cfg.R2Endpoint = getenv("R2_ENDPOINT", "r2.instant.dev")
	cfg.R2BucketName = getenv("R2_BUCKET_NAME", "instant-shared")
	cfg.R2APIToken = os.Getenv("R2_API_TOKEN")
	cfg.MinioEndpoint = os.Getenv("MINIO_ENDPOINT")
	cfg.MinioRootUser = os.Getenv("MINIO_ROOT_USER")
	cfg.MinioRootPassword = os.Getenv("MINIO_ROOT_PASSWORD")
	cfg.MinioBucketName = getenv("MINIO_BUCKET_NAME", "instant-shared")
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
