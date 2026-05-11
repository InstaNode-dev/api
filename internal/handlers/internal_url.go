package handlers

import (
	"net/url"

	"instant.dev/internal/urls"
)

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
