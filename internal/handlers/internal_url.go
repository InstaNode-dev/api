package handlers

import (
	"net/url"

	"github.com/gofiber/fiber/v2"

	"instant.dev/internal/urls"
)

// internalURLResponseKey is the JSON key that carries the cluster-internal
// proxy address back to in-cluster callers. Centralized here so both the
// helper and any future tests reference a single named constant — never
// scatter raw "internal_url" string literals in handler code.
const internalURLResponseKey = "internal_url"

// tierAnonymous is the tier identifier for anonymous (unclaimed) resources.
// Centralized here so the anon-internal_url guard can be grep-audited.
const tierAnonymous = "anonymous"

// setInternalURL conditionally writes `internal_url` into resp.
//
// Contract (W11 hardening, 2026-05-14):
//   - Anonymous-tier responses MUST NOT include internal_url. The
//     cluster-internal proxy FQDN (e.g. instant-pg-proxy.instant.svc.cluster.local)
//     leaks infra topology to any unauthenticated curl. Anon callers
//     legitimately use only the public connection_url; they can't deploy
//     in-cluster workloads (POST /deploy/new requires a claimed team), so
//     internal_url has zero utility for them.
//   - Claimed/authenticated responses (paid tiers — hobby, pro, growth,
//     team) DO include internal_url. Pro users running /deploy/new
//     workloads alongside their DB need it because DOKS doesn't hairpin
//     traffic back through the public LB.
//
// Why a helper and not a guard at every callsite: there are ~12 callsites
// across db.go, cache.go, nosql.go, queue.go, vector.go (storage.go and
// webhook.go don't carry internal_url). Centralizing the "anon → omit"
// rule here means a future tier addition (e.g. "free_signed_in") only
// has to update this one function, and a grep for "internal_url" in
// handlers stays clean.
//
// Returns resp unchanged so callsites can chain idiomatically.
//
// connectionURL: the customer-facing public URL we'll rewrite via
// proxiedInternalURL. Empty input yields no internal_url field even
// for paid tiers (we never emit a half-formed value).
// kind: "postgres", "redis", "mongodb", "queue" — passed through to
// proxiedInternalURL for the per-protocol host substitution.
func setInternalURL(resp fiber.Map, tier, connectionURL, kind string) fiber.Map {
	if tier == tierAnonymous {
		return resp
	}
	if connectionURL == "" {
		return resp
	}
	resp[internalURLResponseKey] = proxiedInternalURL(connectionURL, kind)
	return resp
}

// proxiedInternalURL rewrites a customer-facing public URL to the cluster-internal
// address of the per-protocol proxy. Workloads deployed inside the same cluster
// (e.g. /deploy/new apps in their own namespace) cannot reach the public LB IP
// reliably — DOKS doesn't hairpin — so /db/new and friends return BOTH the public
// connection_url and an internal_url. In-cluster callers use internal_url; external
// callers use connection_url.
//
// Why a central proxy and not per-namespace services: the four protocol proxies
// (pg-proxy, redis-proxy, mongo-proxy, nats-proxy) already demux by token /
// password / database-name in the protocol's auth frame, so a single FQDN per
// resource type is sufficient. This matches what was empirically verified to
// work for QuickPoll's in-cluster deploy on 2026-05-11.
//
// Returns the input unchanged for unknown resource types or unparseable URLs.
func proxiedInternalURL(publicURL, resourceType string) string {
	if publicURL == "" {
		return publicURL
	}
	parsed, err := url.Parse(publicURL)
	if err != nil || parsed.Host == "" {
		return publicURL
	}
	switch resourceType {
	case "postgres":
		parsed.Host = urls.InternalPGProxy
	case "redis":
		parsed.Host = urls.InternalRedisProxy
	case "mongodb":
		parsed.Host = urls.InternalMongoProxy
	case "queue":
		parsed.Host = urls.InternalNATSProxy
	default:
		return publicURL
	}
	return parsed.String()
}
