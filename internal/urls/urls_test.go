package urls

import (
	"strings"
	"testing"
)

// These tests guard the constants from accidental edits — the whole point of
// extracting them was to make a domain rename a one-file diff. If someone
// edits a value here they should also fix the test, which surfaces the
// change in code review.

func TestPublicHostnames_MatchExpectedShape(t *testing.T) {
	cases := []struct {
		name, got, contains string
	}{
		{"PublicAPIBase has scheme + api subdomain", PublicAPIBase, "https://api.instanode.dev"},
		{"PublicMarketingBase has scheme + apex", PublicMarketingBase, "https://instanode.dev"},
		{"StartURLPrefix is api + /start", StartURLPrefix, "https://api.instanode.dev/start"},
		{"DeploymentWildcard is bare host", DeploymentWildcard, "deployment.instanode.dev"},
		{"StoragePublicHost is bare host", StoragePublicHost, "s3.instanode.dev"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.got != c.contains {
				t.Errorf("%s = %q; want %q", c.name, c.got, c.contains)
			}
			// All public hostnames must point at instanode.dev — block the
			// old instant.dev domain from sneaking back in via a typo.
			if strings.Contains(c.got, "instant.dev") {
				t.Errorf("%s leaks old domain instant.dev: %q", c.name, c.got)
			}
		})
	}
}

func TestInternalProxyHostnames_CorrectPortsAndService(t *testing.T) {
	cases := []struct {
		name, got, suffix, port string
	}{
		{"pg-proxy", InternalPGProxy, ".svc.cluster.local:5432", "5432"},
		{"redis-proxy", InternalRedisProxy, ".svc.cluster.local:6379", "6379"},
		{"mongo-proxy", InternalMongoProxy, ".svc.cluster.local:27017", "27017"},
		{"nats-proxy", InternalNATSProxy, ".svc.cluster.local:4222", "4222"},
		{"minio", InternalMinIO, ".svc.cluster.local:9000", "9000"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !strings.HasSuffix(c.got, c.suffix) {
				t.Errorf("%s = %q; must end with %q (k8s cluster-local FQDN + standard port)", c.name, c.got, c.suffix)
			}
		})
	}
}

func TestUpgradeStartURL_Composition(t *testing.T) {
	cases := []struct {
		name, token, want string
	}{
		{"with token", "ey.abc.def", "https://api.instanode.dev/start?t=ey.abc.def"},
		{"empty token returns bare /start", "", "https://api.instanode.dev/start"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := UpgradeStartURL(c.token); got != c.want {
				t.Errorf("UpgradeStartURL(%q) = %q; want %q", c.token, got, c.want)
			}
		})
	}
}
