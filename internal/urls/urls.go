// Package urls centralises every public hostname, cluster-internal FQDN, and
// onboarding URL the platform produces. The previous status quo had each
// string scattered across handler/middleware/template code — the last domain
// rename (instant.dev → instanode.dev) needed a 28-site sed sweep and still
// missed places.
//
// Rules of the road:
//
//   1. Anywhere a Go file would write "instanode.dev" or "instant-pg-proxy.svc"
//      as a string literal, import this package instead.
//   2. Operator-facing config (env vars, configmaps) is NOT in scope here —
//      those still flow through config.Config. This package is for code-only
//      constants that don't make sense as runtime config.
//   3. Email templates and marketing copy live elsewhere; this package is for
//      programmatic URLs the API itself produces.
//   4. Test files SHOULD continue to use string literals — tests asserting
//      "got 'instanode.dev'" should not import this package, or the test
//      tautologically passes whenever the constant changes.
package urls

// Public hostnames returned to customers and referenced in URL strings the
// API itself produces.
const (
	// PublicAPIBase is the canonical resource URL of the agent-facing API.
	// Used as the default JWT audience and in URL construction for any
	// response that needs to point a caller back at us.
	PublicAPIBase = "https://api.instanode.dev"

	// PublicMarketingBase is the customer-facing marketing site. /start lives
	// here and is the entry point for the claim flow.
	PublicMarketingBase = "https://instanode.dev"

	// StartURLPrefix is the bare path that anonymous resources point users at
	// to claim — append "?t=<onboarding-jwt>" to produce the upgrade URL.
	StartURLPrefix = PublicMarketingBase + "/start"

	// DeploymentWildcard is the suffix every /deploy/new and /stacks/new
	// service URL gets prefixed by its app-id slug.
	DeploymentWildcard = "deployment.instanode.dev"

	// StoragePublicHost is the customer-facing S3 endpoint hostname.
	StoragePublicHost = "s3.instanode.dev"
)

// Cluster-internal FQDNs for the per-protocol proxies. These are written into
// "internal_url" response fields and used by /deploy /stacks pipelines when
// a workload needs to reach a provisioned resource without going through the
// public LoadBalancer (DOKS doesn't hairpin reliably). See friction PR #2.
const (
	InternalPGProxy    = "instant-pg-proxy.instant.svc.cluster.local:5432"
	InternalRedisProxy = "instant-redis-proxy.instant.svc.cluster.local:6379"
	InternalMongoProxy = "instant-mongo-proxy.instant.svc.cluster.local:27017"
	InternalNATSProxy  = "instant-nats-proxy.instant.svc.cluster.local:4222"

	// InternalMinIO is the in-cluster MinIO endpoint used by the kaniko build
	// context delivery (presigned URL fetched by init-container). Customers
	// use StoragePublicHost above.
	InternalMinIO = "minio.instant-data.svc.cluster.local:9000"
)

// UpgradeStartURL builds the URL we hand to anonymous users so they can claim
// their resources. token is the onboarding JWT (single-use, 7d TTL). Returning
// a single canonical builder avoids the previous pattern of fmt.Sprintf with
// inline string literals in every handler.
func UpgradeStartURL(token string) string {
	if token == "" {
		return StartURLPrefix
	}
	return StartURLPrefix + "?t=" + token
}
