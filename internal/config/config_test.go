package config

import (
	"os"
	"strings"
	"testing"
)

// hexKey64 returns a deterministic 64-char hex string for AES_KEY.
const hexKey64 = "0011223344556677889900112233445566778899aabbccddeeff001122334455"

// applyBaselineEnv writes the minimum env vars Load() requires (DATABASE_URL,
// JWT_SECRET, AES_KEY) plus optional overrides. It also clears every other
// var Load() reads, so the test gets a deterministic env regardless of host
// shape.
func applyBaselineEnv(t *testing.T, overrides map[string]string) {
	t.Helper()
	// Clear every env var Load() touches so we get deterministic defaults.
	for _, k := range allKeys() {
		t.Setenv(k, "")
		_ = os.Unsetenv(k)
	}
	// Set the required trio plus any caller overrides.
	t.Setenv("DATABASE_URL", "postgres://localhost/test")
	t.Setenv("JWT_SECRET", strings.Repeat("J", 32))
	t.Setenv("AES_KEY", hexKey64)
	for k, v := range overrides {
		t.Setenv(k, v)
	}
}

// allKeys enumerates every env var Load() reads. Used to clear host-state.
func allKeys() []string {
	return []string{
		"PORT", "DATABASE_URL", "CUSTOMER_DATABASE_URL", "REDIS_URL",
		"JWT_SECRET", "AES_KEY", "MAXMIND_LICENSE_KEY", "GEOLITE2_DB_PATH",
		"RAZORPAY_KEY_ID", "RAZORPAY_KEY_SECRET", "RAZORPAY_WEBHOOK_SECRET",
		"RAZORPAY_PLAN_ID_HOBBY", "RAZORPAY_PLAN_ID_HOBBY_PLUS",
		"RAZORPAY_PLAN_ID_PRO", "RAZORPAY_PLAN_ID_GROWTH",
		"RAZORPAY_PLAN_ID_TEAM", "RAZORPAY_PLAN_ID_HOBBY_ANNUAL",
		"RAZORPAY_PLAN_ID_HOBBY_PLUS_ANNUAL", "RAZORPAY_PLAN_ID_PRO_ANNUAL",
		"RAZORPAY_PLAN_ID_GROWTH_ANNUAL", "RAZORPAY_PLAN_ID_TEAM_ANNUAL",
		"RESEND_API_KEY", "EMAIL_PROVIDER", "BREVO_API_KEY",
		"EMAIL_FROM_NAME", "EMAIL_FROM_ADDRESS",
		"GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET",
		"GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_REDIRECT_URI",
		"INSTANT_ENABLED_SERVICES", "ENVIRONMENT", "TRUSTED_PROXY_CIDRS",
		"REDIS_PROVISION_BACKEND", "REDIS_PROVISION_HOST",
		"MONGO_ADMIN_URI", "MONGO_HOST",
		"POSTGRES_PROVISION_BACKEND", "NEON_API_KEY", "NEON_REGION_ID",
		"POSTGRES_CUSTOMERS_URL", "PROVISIONER_ADDR", "PROVISIONER_SECRET",
		"NATS_HOST", "QUEUE_BACKEND", "NATS_PUBLIC_HOST",
		"NATS_OPERATOR_SEED", "NATS_SYSTEM_ACCOUNT_PUBLIC_KEY", "NATS_USE_TLS",
		"R2_ENDPOINT", "R2_BUCKET_NAME", "R2_API_TOKEN",
		"OBJECT_STORE_MODE", "OBJECT_STORE_BACKEND", "OBJECT_STORE_ENDPOINT",
		"OBJECT_STORE_PUBLIC_URL", "OBJECT_STORE_ACCESS_KEY",
		"OBJECT_STORE_SECRET_KEY", "OBJECT_STORE_BUCKET",
		"OBJECT_STORE_REGION", "OBJECT_STORE_SECURE",
		"OBJECT_STORE_ALLOW_SHARED_KEY",
		"MINIO_ENDPOINT", "MINIO_PUBLIC_ENDPOINT", "MINIO_ROOT_USER",
		"MINIO_ROOT_PASSWORD", "MINIO_BUCKET_NAME",
		"DEPLOY_DOMAIN", "COMPUTE_PROVIDER", "KUBE_NAMESPACE_APPS",
		"METRICS_TOKEN", "DASHBOARD_BASE_URL", "API_PUBLIC_URL",
		"DELETION_CONFIRMATION_TTL_MINUTES", "FAMILY_BINDINGS_ENABLED",
		"DEPLOY_SOURCE_IMAGE_ENABLED", "DEPLOY_SOURCE_GIT_ENABLED",
		"GITHUB_APP_ENABLED", "GITHUB_APP_ID", "GITHUB_APP_SLUG", "GITHUB_APP_PRIVATE_KEY",
		"GITHUB_APP_WEBHOOK_SECRET", "GITHUB_APP_CLIENT_ID", "GITHUB_APP_CLIENT_SECRET",
		"BREVO_WEBHOOK_SECRET", "SES_SNS_SUBSCRIPTION_ARN",
		"SENDGRID_WEBHOOK_PUBLIC_KEY",
		"WORKER_INTERNAL_JWT_SECRET", "ADMIN_PATH_PREFIX",
		"E2E_ACCOUNT_TOKEN",
	}
}

func TestErrMissingConfig_Error(t *testing.T) {
	e := &ErrMissingConfig{Key: "FOO"}
	if got := e.Error(); !strings.Contains(got, "FOO") || !strings.Contains(got, "required") {
		t.Fatalf("unexpected Error() output: %q", got)
	}
}

func TestGetenv_FallbackAndExplicit(t *testing.T) {
	_ = os.Unsetenv("X_UNIT_GETENV")
	if got := getenv("X_UNIT_GETENV", "fallback"); got != "fallback" {
		t.Fatalf("expected fallback, got %q", got)
	}
	t.Setenv("X_UNIT_GETENV", "explicit")
	if got := getenv("X_UNIT_GETENV", "fallback"); got != "explicit" {
		t.Fatalf("expected explicit, got %q", got)
	}
	// Empty string falls back too — getenv treats "" as missing.
	t.Setenv("X_UNIT_GETENV", "")
	if got := getenv("X_UNIT_GETENV", "fallback"); got != "fallback" {
		t.Fatalf("empty env should fall back, got %q", got)
	}
}

func TestRequire_PanicsOnMissing(t *testing.T) {
	_ = os.Unsetenv("X_UNIT_REQUIRE")
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic")
		}
		err, ok := r.(*ErrMissingConfig)
		if !ok {
			t.Fatalf("expected *ErrMissingConfig, got %T", r)
		}
		if err.Key != "X_UNIT_REQUIRE" {
			t.Fatalf("key=%q", err.Key)
		}
	}()
	_ = require("X_UNIT_REQUIRE")
}

func TestRequire_ReturnsValueWhenSet(t *testing.T) {
	t.Setenv("X_UNIT_REQUIRE", "ok")
	if got := require("X_UNIT_REQUIRE"); got != "ok" {
		t.Fatalf("got %q", got)
	}
}

func TestMask(t *testing.T) {
	if got := mask(""); got != "***" {
		t.Fatalf("empty: %q", got)
	}
	if got := mask("short"); got != "***" {
		t.Fatalf("short: %q", got)
	}
	// 12 chars is still "***" — boundary
	if got := mask("123456789012"); got != "***" {
		t.Fatalf("12-char: %q", got)
	}
	// 13+ → first 8, ***, last 4
	got := mask("abcdefgh12345678ijklmn")
	if !strings.HasPrefix(got, "abcdefgh") || !strings.Contains(got, "***") || !strings.HasSuffix(got, "klmn") {
		t.Fatalf("long: %q", got)
	}
}

func TestMaskSecret(t *testing.T) {
	if got := maskSecret(""); got != "" {
		t.Fatalf("empty: %q", got)
	}
	// 4 chars exactly — prefix is whole string, no stars
	if got := maskSecret("abcd"); got != "abcd" {
		t.Fatalf("4-char: %q", got)
	}
	// Longer — prefix is first 4, rest stars
	if got := maskSecret("abcdefghij"); got != "abcd******" {
		t.Fatalf("10-char: %q", got)
	}
}

func TestValidateAdminPathPrefix(t *testing.T) {
	if err := ValidateAdminPathPrefix(""); err != nil {
		t.Fatalf("empty must pass (closed by default), got %v", err)
	}
	// 32 chars alphanumeric — valid
	if err := ValidateAdminPathPrefix(strings.Repeat("a", 32)); err != nil {
		t.Fatalf("32-char alphanumeric should pass, got %v", err)
	}
	// 31 chars — too short
	if err := ValidateAdminPathPrefix(strings.Repeat("a", 31)); err == nil {
		t.Fatal("31-char must fail (too short)")
	}
	// 32 chars but contains '-' — fail
	bad := strings.Repeat("a", 31) + "-"
	if err := ValidateAdminPathPrefix(bad); err == nil {
		t.Fatal("non-alphanumeric must fail")
	}
	// Spaces, slashes, digits — covers each ASCII class
	if err := ValidateAdminPathPrefix(strings.Repeat("0", 16) + strings.Repeat("Z", 16)); err != nil {
		t.Fatalf("digit+upper should pass, got %v", err)
	}
	if err := ValidateAdminPathPrefix(strings.Repeat(" ", 32)); err == nil {
		t.Fatal("space-byte 0x20 must fail")
	}
	if err := ValidateAdminPathPrefix(strings.Repeat("/", 32)); err == nil {
		t.Fatal("slash must fail")
	}
}

func TestConfig_IsServiceEnabled(t *testing.T) {
	c := &Config{EnabledServices: "redis, postgres,mongodb,queue"}
	for _, s := range []string{"redis", "postgres", "mongodb", "queue"} {
		if !c.IsServiceEnabled(s) {
			t.Errorf("expected %s enabled", s)
		}
	}
	if c.IsServiceEnabled("storage") {
		t.Error("storage must NOT be enabled")
	}
	// Empty list
	if (&Config{}).IsServiceEnabled("redis") {
		t.Error("empty list must not match")
	}
}

func TestLoad_E2EAccountToken(t *testing.T) {
	// Unset → empty (inert-by-default: the /internal/e2e/* surface 404s).
	applyBaselineEnv(t, nil)
	if got := Load().E2EAccountToken; got != "" {
		t.Errorf("E2EAccountToken default: want empty (inert), got %q", got)
	}
	// Set (with surrounding whitespace) → trimmed value.
	applyBaselineEnv(t, map[string]string{"E2E_ACCOUNT_TOKEN": "  secret-token  "})
	if got := Load().E2EAccountToken; got != "secret-token" {
		t.Errorf("E2EAccountToken: want trimmed 'secret-token', got %q", got)
	}
}

func TestLoad_HappyPath_AppliesDefaults(t *testing.T) {
	applyBaselineEnv(t, nil)
	cfg := Load()
	if cfg.Port != "8080" {
		t.Errorf("Port default: %q", cfg.Port)
	}
	if cfg.RedisURL != "redis://localhost:6379" {
		t.Errorf("RedisURL default: %q", cfg.RedisURL)
	}
	if cfg.Environment != "development" {
		t.Errorf("Environment default: %q", cfg.Environment)
	}
	if cfg.EnabledServices != "redis,postgres,mongodb,queue" {
		t.Errorf("EnabledServices default: %q", cfg.EnabledServices)
	}
	if cfg.GeoLite2DBPath != "./GeoLite2-City.mmdb" {
		t.Errorf("GeoLite2DBPath default: %q", cfg.GeoLite2DBPath)
	}
	if cfg.RedisProvisionBackend != "local" {
		t.Errorf("RedisProvisionBackend default: %q", cfg.RedisProvisionBackend)
	}
	if cfg.MongoAdminURI != "mongodb://root:root@localhost:27017" {
		t.Errorf("MongoAdminURI default: %q", cfg.MongoAdminURI)
	}
	if cfg.QueueBackend != "nats" {
		t.Errorf("QueueBackend default: %q", cfg.QueueBackend)
	}
	if cfg.NATSPublicHost != "nats.instanode.dev" {
		t.Errorf("NATSPublicHost default: %q", cfg.NATSPublicHost)
	}
	if cfg.DeployDomain != "instant.dev" {
		t.Errorf("DeployDomain default: %q", cfg.DeployDomain)
	}
	if cfg.ComputeProvider != "noop" {
		t.Errorf("ComputeProvider default: %q", cfg.ComputeProvider)
	}
	if cfg.KubeNamespaceApps != "instant-apps" {
		t.Errorf("KubeNamespaceApps default: %q", cfg.KubeNamespaceApps)
	}
	if cfg.DashboardBaseURL != "http://localhost:5173" {
		t.Errorf("DashboardBaseURL default: %q", cfg.DashboardBaseURL)
	}
	if cfg.DeletionConfirmationTTLMinutes != 15 {
		t.Errorf("DeletionConfirmationTTLMinutes default: %d", cfg.DeletionConfirmationTTLMinutes)
	}
	if !cfg.FamilyBindingsEnabled {
		t.Error("FamilyBindingsEnabled default must be true")
	}
	if cfg.DeploySourceImageEnabled {
		t.Error("DeploySourceImageEnabled default must be false (off until operator canary)")
	}
	if cfg.DeploySourceGitEnabled {
		t.Error("DeploySourceGitEnabled default must be false (off until operator canary)")
	}
	if cfg.GitHubAppEnabled {
		t.Error("GitHubAppEnabled default must be false (off until operator registers the App)")
	}
	// Object store mode resolution: with everything empty → "admin" / "minio-admin"
	if cfg.ObjectStoreMode != "admin" || cfg.ObjectStoreBackend != "minio-admin" {
		t.Errorf("ObjectStoreMode/Backend defaults: %q/%q", cfg.ObjectStoreMode, cfg.ObjectStoreBackend)
	}
}

func TestLoad_OverrideDefaults(t *testing.T) {
	applyBaselineEnv(t, map[string]string{
		"PORT":                           "9090",
		"REDIS_URL":                      "redis://r:6379",
		"ENVIRONMENT":                    "production",
		"INSTANT_ENABLED_SERVICES":       "postgres",
		"GEOLITE2_DB_PATH":               "/data/geo.mmdb",
		"RAZORPAY_KEY_ID":                "rzp_test_x",
		"RESEND_API_KEY":                 "re_x",
		"BREVO_API_KEY":                  "br_x",
		"EMAIL_PROVIDER":                 "brevo",
		"EMAIL_FROM_ADDRESS":             "noreply@x.dev",
		"EMAIL_FROM_NAME":                "X",
		"GITHUB_CLIENT_ID":               "gh-x",
		"GOOGLE_CLIENT_ID":               "g-x",
		"GOOGLE_REDIRECT_URI":            "https://x/callback",
		"REDIS_PROVISION_BACKEND":        "upstash",
		"REDIS_PROVISION_HOST":           "redis.x",
		"MONGO_HOST":                     "mongo.x",
		"POSTGRES_PROVISION_BACKEND":     "neon",
		"NEON_API_KEY":                   "nk-x",
		"PROVISIONER_ADDR":               "prov:50051",
		"PROVISIONER_SECRET":             "ps",
		"NATS_HOST":                      "nats.x",
		"QUEUE_BACKEND":                  "legacy_open",
		"NATS_PUBLIC_HOST":               "public.x",
		"NATS_OPERATOR_SEED":             "SO_seed",
		"NATS_SYSTEM_ACCOUNT_PUBLIC_KEY": "ACSYS",
		"NATS_USE_TLS":                   "true",
		"R2_ENDPOINT":                    "r2.x",
		"R2_BUCKET_NAME":                 "x-bucket",
		"R2_API_TOKEN":                   "r2tok",
		"DEPLOY_DOMAIN":                  "x.dev",
		"COMPUTE_PROVIDER":               "k8s",
		"KUBE_NAMESPACE_APPS":            "x-apps",
		"METRICS_TOKEN":                  strings.Repeat("M", 64),
		"DASHBOARD_BASE_URL":             "https://dash.x",
		"API_PUBLIC_URL":                 "https://api.x/",
		"BREVO_WEBHOOK_SECRET":           "brevo-wh",
		"SES_SNS_SUBSCRIPTION_ARN":       "arn:aws:sns:x",
		"SENDGRID_WEBHOOK_PUBLIC_KEY":    "sg-key",
		"WORKER_INTERNAL_JWT_SECRET":     "  worker-secret  ",
		"TRUSTED_PROXY_CIDRS":            "10.0.0.0/8",
		"MAXMIND_LICENSE_KEY":            "mm",
	})
	cfg := Load()
	if cfg.Port != "9090" || cfg.Environment != "production" {
		t.Fatalf("overrides not applied: port=%q env=%q", cfg.Port, cfg.Environment)
	}
	if cfg.QueueBackend != "legacy_open" {
		t.Errorf("QueueBackend override: %q", cfg.QueueBackend)
	}
	if !cfg.NATSUseTLS {
		t.Error("NATSUseTLS must be true when env=true")
	}
	// API_PUBLIC_URL — trailing slash must be trimmed.
	if cfg.APIPublicURL != "https://api.x" {
		t.Errorf("APIPublicURL trim: %q", cfg.APIPublicURL)
	}
	// WORKER_INTERNAL_JWT_SECRET trim
	if cfg.WorkerInternalJWTSecret != "worker-secret" {
		t.Errorf("WorkerInternalJWTSecret trim: %q", cfg.WorkerInternalJWTSecret)
	}
	if cfg.MetricsToken == "" {
		t.Error("MetricsToken should be set")
	}
}

func TestLoad_FamilyBindingsDisabled(t *testing.T) {
	for _, val := range []string{"false", "FALSE", "0", "no", "  No  "} {
		applyBaselineEnv(t, map[string]string{"FAMILY_BINDINGS_ENABLED": val})
		cfg := Load()
		if cfg.FamilyBindingsEnabled {
			t.Errorf("FAMILY_BINDINGS_ENABLED=%q should disable", val)
		}
	}
	// Unrecognized value → default true
	applyBaselineEnv(t, map[string]string{"FAMILY_BINDINGS_ENABLED": "yes"})
	if !Load().FamilyBindingsEnabled {
		t.Error(`FAMILY_BINDINGS_ENABLED="yes" must default to true`)
	}
}

func TestLoad_DeploySourceImageEnabled(t *testing.T) {
	for _, val := range []string{"true", "1", "yes", "TRUE", "  Yes  "} {
		applyBaselineEnv(t, map[string]string{"DEPLOY_SOURCE_IMAGE_ENABLED": val})
		if !Load().DeploySourceImageEnabled {
			t.Errorf("DEPLOY_SOURCE_IMAGE_ENABLED=%q should enable", val)
		}
	}
	// Unrecognized / off values → stays disabled.
	for _, val := range []string{"false", "0", "no", "maybe", ""} {
		applyBaselineEnv(t, map[string]string{"DEPLOY_SOURCE_IMAGE_ENABLED": val})
		if Load().DeploySourceImageEnabled {
			t.Errorf("DEPLOY_SOURCE_IMAGE_ENABLED=%q should stay disabled", val)
		}
	}
}

func TestLoad_DeploySourceGitEnabled(t *testing.T) {
	for _, val := range []string{"true", "1", "yes", "TRUE", "  Yes  "} {
		applyBaselineEnv(t, map[string]string{"DEPLOY_SOURCE_GIT_ENABLED": val})
		if !Load().DeploySourceGitEnabled {
			t.Errorf("DEPLOY_SOURCE_GIT_ENABLED=%q should enable", val)
		}
	}
	for _, val := range []string{"false", "0", "no", "maybe", ""} {
		applyBaselineEnv(t, map[string]string{"DEPLOY_SOURCE_GIT_ENABLED": val})
		if Load().DeploySourceGitEnabled {
			t.Errorf("DEPLOY_SOURCE_GIT_ENABLED=%q should stay disabled", val)
		}
	}
}

func TestLoad_GitHubAppEnabled(t *testing.T) {
	// When enabling the App, Load() fails closed unless the webhook secret +
	// private key + app id are present (review HIGH-1), so set them here.
	appSecrets := func(enabled string) map[string]string {
		return map[string]string{
			"GITHUB_APP_ENABLED":        enabled,
			"GITHUB_APP_WEBHOOK_SECRET": "a-sufficiently-long-webhook-secret",
			"GITHUB_APP_PRIVATE_KEY":    "-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----",
			"GITHUB_APP_ID":             "12345",
		}
	}
	for _, val := range []string{"true", "1", "yes", "TRUE", "  Yes  "} {
		applyBaselineEnv(t, appSecrets(val))
		if !Load().GitHubAppEnabled {
			t.Errorf("GITHUB_APP_ENABLED=%q should enable", val)
		}
	}
	for _, val := range []string{"false", "0", "no", "maybe", ""} {
		applyBaselineEnv(t, map[string]string{"GITHUB_APP_ENABLED": val})
		if Load().GitHubAppEnabled {
			t.Errorf("GITHUB_APP_ENABLED=%q should stay disabled", val)
		}
	}

	// Fail-closed: enabling without each required secret must panic, not
	// silently serve an HMAC-bypassable / token-less App.
	mustPanic := func(name string, env map[string]string) {
		defer func() {
			if recover() == nil {
				t.Errorf("%s: Load() must panic", name)
			}
		}()
		applyBaselineEnv(t, env)
		_ = Load()
	}
	mustPanic("no webhook secret", map[string]string{"GITHUB_APP_ENABLED": "true"})
	mustPanic("no private key", map[string]string{
		"GITHUB_APP_ENABLED":        "true",
		"GITHUB_APP_WEBHOOK_SECRET": "a-sufficiently-long-webhook-secret",
	})
	mustPanic("no app id", map[string]string{
		"GITHUB_APP_ENABLED":        "true",
		"GITHUB_APP_WEBHOOK_SECRET": "a-sufficiently-long-webhook-secret",
		"GITHUB_APP_PRIVATE_KEY":    "-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----",
	})
	// the GITHUB_APP_* values are plumbed verbatim.
	applyBaselineEnv(t, map[string]string{
		"GITHUB_APP_ID":             "12345",
		"GITHUB_APP_PRIVATE_KEY":    "-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----",
		"GITHUB_APP_WEBHOOK_SECRET": "whsec",
		"GITHUB_APP_CLIENT_ID":      "Iv1.abc",
		"GITHUB_APP_CLIENT_SECRET":  "cs",
	})
	c := Load()
	if c.GitHubAppID != "12345" || c.GitHubAppWebhookSecret != "whsec" ||
		c.GitHubAppClientID != "Iv1.abc" || c.GitHubAppClientSecret != "cs" ||
		c.GitHubAppPrivateKey == "" {
		t.Errorf("GITHUB_APP_* not plumbed: %+v", c.GitHubAppID)
	}
}

func TestLoad_DeletionTTL_OverrideAndInvalid(t *testing.T) {
	applyBaselineEnv(t, map[string]string{"DELETION_CONFIRMATION_TTL_MINUTES": "30"})
	if got := Load().DeletionConfirmationTTLMinutes; got != 30 {
		t.Errorf("override: got %d", got)
	}
	applyBaselineEnv(t, map[string]string{"DELETION_CONFIRMATION_TTL_MINUTES": "abc"})
	if got := Load().DeletionConfirmationTTLMinutes; got != 15 {
		t.Errorf("invalid value should fall back to 15, got %d", got)
	}
	applyBaselineEnv(t, map[string]string{"DELETION_CONFIRMATION_TTL_MINUTES": "-5"})
	if got := Load().DeletionConfirmationTTLMinutes; got != 15 {
		t.Errorf("negative value should fall back to 15, got %d", got)
	}
	applyBaselineEnv(t, map[string]string{"DELETION_CONFIRMATION_TTL_MINUTES": "0"})
	if got := Load().DeletionConfirmationTTLMinutes; got != 15 {
		t.Errorf("zero value should fall back to 15, got %d", got)
	}
	// Whitespace-only is treated as empty by the TrimSpace guard.
	applyBaselineEnv(t, map[string]string{"DELETION_CONFIRMATION_TTL_MINUTES": "   "})
	if got := Load().DeletionConfirmationTTLMinutes; got != 15 {
		t.Errorf("whitespace-only should fall back to 15, got %d", got)
	}
}

func TestLoad_ObjectStore_MinioFallback(t *testing.T) {
	applyBaselineEnv(t, map[string]string{
		"MINIO_ENDPOINT":        "minio:9000",
		"MINIO_PUBLIC_ENDPOINT": "https://s3.x",
		"MINIO_ROOT_USER":       "miniouser",
		"MINIO_ROOT_PASSWORD":   "miniosecret",
		"MINIO_BUCKET_NAME":     "x-bucket",
	})
	cfg := Load()
	if cfg.ObjectStoreEndpoint != "minio:9000" {
		t.Errorf("MINIO_ENDPOINT fallback: %q", cfg.ObjectStoreEndpoint)
	}
	if cfg.ObjectStorePublicURL != "https://s3.x" {
		t.Errorf("MINIO_PUBLIC_ENDPOINT fallback: %q", cfg.ObjectStorePublicURL)
	}
	if cfg.ObjectStoreAccessKey != "miniouser" {
		t.Errorf("MINIO_ROOT_USER fallback: %q", cfg.ObjectStoreAccessKey)
	}
	if cfg.ObjectStoreSecretKey != "miniosecret" {
		t.Errorf("MINIO_ROOT_PASSWORD fallback: %q", cfg.ObjectStoreSecretKey)
	}
	// MINIO_BUCKET_NAME overrides the default-only "instant-shared" path.
	if cfg.ObjectStoreBucket != "x-bucket" {
		t.Errorf("MINIO_BUCKET_NAME fallback: %q", cfg.ObjectStoreBucket)
	}
}

func TestLoad_ObjectStore_ExplicitOverridesFallback(t *testing.T) {
	applyBaselineEnv(t, map[string]string{
		"OBJECT_STORE_ENDPOINT":         "nyc3.digitaloceanspaces.com",
		"OBJECT_STORE_PUBLIC_URL":       "https://s3.instanode.dev",
		"OBJECT_STORE_ACCESS_KEY":       "AKIA",
		"OBJECT_STORE_SECRET_KEY":       "SECRET",
		"OBJECT_STORE_BUCKET":           "do-bucket",
		"OBJECT_STORE_REGION":           "nyc3",
		"OBJECT_STORE_SECURE":           "true",
		"OBJECT_STORE_ALLOW_SHARED_KEY": "true",
		// Set MINIO_* so we prove they DON'T win.
		"MINIO_ENDPOINT":  "minio:9000",
		"MINIO_ROOT_USER": "ignored",
	})
	cfg := Load()
	if cfg.ObjectStoreEndpoint != "nyc3.digitaloceanspaces.com" {
		t.Errorf("explicit OBJECT_STORE_ENDPOINT should win: %q", cfg.ObjectStoreEndpoint)
	}
	if cfg.ObjectStoreAccessKey != "AKIA" {
		t.Errorf("explicit AccessKey: %q", cfg.ObjectStoreAccessKey)
	}
	if !cfg.ObjectStoreSecure {
		t.Error("OBJECT_STORE_SECURE=true not honoured")
	}
	if !cfg.ObjectStoreAllowSharedKey {
		t.Error("OBJECT_STORE_ALLOW_SHARED_KEY=true not honoured")
	}
}

func TestLoad_ObjectStore_ModeBackendAliases(t *testing.T) {
	// OBJECT_STORE_MODE wins when set.
	applyBaselineEnv(t, map[string]string{
		"OBJECT_STORE_MODE": "shared-key",
	})
	cfg := Load()
	if cfg.ObjectStoreMode != "shared-key" {
		t.Errorf("Mode (explicit): %q", cfg.ObjectStoreMode)
	}
	// Backend inherits from Mode when only Mode is set.
	if cfg.ObjectStoreBackend != "shared-key" {
		t.Errorf("Backend inherits from Mode: %q", cfg.ObjectStoreBackend)
	}

	// OBJECT_STORE_BACKEND-only sets both.
	applyBaselineEnv(t, map[string]string{
		"OBJECT_STORE_BACKEND": "do-spaces",
	})
	cfg = Load()
	if cfg.ObjectStoreBackend != "do-spaces" || cfg.ObjectStoreMode != "do-spaces" {
		t.Errorf("Backend-only: mode=%q backend=%q", cfg.ObjectStoreMode, cfg.ObjectStoreBackend)
	}
}

func TestLoad_PanicsOnMissingRequired(t *testing.T) {
	cases := []string{"DATABASE_URL", "JWT_SECRET", "AES_KEY"}
	for _, missing := range cases {
		t.Run(missing, func(t *testing.T) {
			applyBaselineEnv(t, nil)
			_ = os.Unsetenv(missing)
			t.Setenv(missing, "")
			defer func() {
				if r := recover(); r == nil {
					t.Fatalf("expected panic when %s missing", missing)
				}
			}()
			_ = Load()
		})
	}
}

func TestLoad_PanicsOnShortJWT(t *testing.T) {
	applyBaselineEnv(t, map[string]string{"JWT_SECRET": "tooshort"})
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for short JWT_SECRET")
		}
		msg, _ := r.(string)
		if !strings.Contains(msg, "JWT_SECRET") {
			t.Fatalf("panic msg: %v", r)
		}
	}()
	_ = Load()
}

func TestLoad_PanicsOnBadAESKey(t *testing.T) {
	applyBaselineEnv(t, map[string]string{"AES_KEY": strings.Repeat("a", 63)})
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for short AES_KEY")
		}
		msg, _ := r.(string)
		if !strings.Contains(msg, "AES_KEY") {
			t.Fatalf("panic msg: %v", r)
		}
	}()
	_ = Load()
}

func TestLoad_PanicsOnBadAdminPathPrefix(t *testing.T) {
	applyBaselineEnv(t, map[string]string{"ADMIN_PATH_PREFIX": "tooshort"})
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on short admin prefix")
		}
	}()
	_ = Load()
}

func TestLoad_AdminPathPrefix_Valid(t *testing.T) {
	prefix := strings.Repeat("a", 64)
	applyBaselineEnv(t, map[string]string{"ADMIN_PATH_PREFIX": prefix})
	cfg := Load()
	if cfg.AdminPathPrefix != prefix {
		t.Errorf("AdminPathPrefix: %q", cfg.AdminPathPrefix)
	}
}

func TestLoad_LogStartupConfig_MetricsToken_Prod(t *testing.T) {
	// Cover the production-no-token branch end-to-end through Load().
	applyBaselineEnv(t, map[string]string{
		"ENVIRONMENT": "production",
	})
	cfg := Load()
	if cfg.MetricsToken != "" {
		t.Fatal("test setup: METRICS_TOKEN must be empty for this branch")
	}
	if cfg.Environment != "production" {
		t.Fatalf("env: %q", cfg.Environment)
	}
}

// TestLoad_RazorpayPlanIDs ensures every plan-id env mapping lands on the
// matching Config field (D28 F3 / 2026-05-15 alignment).
func TestLoad_RazorpayPlanIDs(t *testing.T) {
	applyBaselineEnv(t, map[string]string{
		"RAZORPAY_PLAN_ID_HOBBY":             "plan_hobby",
		"RAZORPAY_PLAN_ID_HOBBY_PLUS":        "plan_hp",
		"RAZORPAY_PLAN_ID_PRO":               "plan_pro",
		"RAZORPAY_PLAN_ID_GROWTH":            "plan_growth",
		"RAZORPAY_PLAN_ID_TEAM":              "plan_team",
		"RAZORPAY_PLAN_ID_HOBBY_ANNUAL":      "plan_hobby_y",
		"RAZORPAY_PLAN_ID_HOBBY_PLUS_ANNUAL": "plan_hp_y",
		"RAZORPAY_PLAN_ID_PRO_ANNUAL":        "plan_pro_y",
		"RAZORPAY_PLAN_ID_GROWTH_ANNUAL":     "plan_growth_y",
		"RAZORPAY_PLAN_ID_TEAM_ANNUAL":       "plan_team_y",
		"RAZORPAY_KEY_SECRET":                "secret",
		"RAZORPAY_WEBHOOK_SECRET":            "whsec",
	})
	c := Load()
	checks := map[string]string{
		"hobby":    c.RazorpayPlanIDHobby,
		"hp":       c.RazorpayPlanIDHobbyPlus,
		"pro":      c.RazorpayPlanIDPro,
		"growth":   c.RazorpayPlanIDGrowth,
		"team":     c.RazorpayPlanIDTeam,
		"hobby_y":  c.RazorpayPlanIDHobbyYearly,
		"hp_y":     c.RazorpayPlanIDHobbyPlusYearly,
		"pro_y":    c.RazorpayPlanIDProYearly,
		"growth_y": c.RazorpayPlanIDGrowthYearly,
		"team_y":   c.RazorpayPlanIDTeamYearly,
	}
	for tag, got := range checks {
		want := "plan_" + tag
		if got != want {
			t.Errorf("%s: got %q want %q", tag, got, want)
		}
	}
	if c.RazorpayKeySecret != "secret" || c.RazorpayWebhookSecret != "whsec" {
		t.Error("KeySecret/WebhookSecret not loaded")
	}
}
