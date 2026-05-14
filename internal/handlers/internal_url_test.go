package handlers

import (
	"testing"

	"github.com/gofiber/fiber/v2"
)

// TestSetInternalURL pins the W11 "scrub internal_url for anonymous" contract.
// The helper centralises the omit-on-anon rule; these cases drive every axis
// that handler responses route through it.
func TestSetInternalURL(t *testing.T) {
	const pgURL = "postgres://usr_x:pass@pg.instanode.dev:5432/db_x?sslmode=disable"
	const wantPgInternal = "postgres://usr_x:pass@instant-pg-proxy.instant.svc.cluster.local:5432/db_x?sslmode=disable"

	cases := []struct {
		name         string
		tier         string
		connURL      string
		kind         string
		wantInternal string // empty string ⇒ key absent
	}{
		{
			name:         "anonymous tier MUST NOT emit internal_url",
			tier:         "anonymous",
			connURL:      pgURL,
			kind:         "postgres",
			wantInternal: "",
		},
		{
			name:         "hobby tier emits internal_url",
			tier:         "hobby",
			connURL:      pgURL,
			kind:         "postgres",
			wantInternal: wantPgInternal,
		},
		{
			name:         "pro tier emits internal_url",
			tier:         "pro",
			connURL:      pgURL,
			kind:         "postgres",
			wantInternal: wantPgInternal,
		},
		{
			name:         "team tier emits internal_url",
			tier:         "team",
			connURL:      pgURL,
			kind:         "postgres",
			wantInternal: wantPgInternal,
		},
		{
			name:         "growth tier emits internal_url",
			tier:         "growth",
			connURL:      pgURL,
			kind:         "postgres",
			wantInternal: wantPgInternal,
		},
		{
			name:         "empty connection URL on paid tier does NOT emit internal_url",
			tier:         "pro",
			connURL:      "",
			kind:         "postgres",
			wantInternal: "",
		},
		{
			name:         "empty connection URL on anon tier does NOT emit internal_url",
			tier:         "anonymous",
			connURL:      "",
			kind:         "postgres",
			wantInternal: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := fiber.Map{"ok": true, "connection_url": c.connURL}
			setInternalURL(resp, c.tier, c.connURL, c.kind)
			got, present := resp[internalURLResponseKey]
			if c.wantInternal == "" {
				if present {
					t.Errorf("internal_url MUST be omitted for tier=%q connURL=%q; got %v",
						c.tier, c.connURL, got)
				}
				return
			}
			if !present {
				t.Fatalf("internal_url missing for tier=%q; expected %q", c.tier, c.wantInternal)
			}
			gotStr, ok := got.(string)
			if !ok {
				t.Fatalf("internal_url is not a string: %T %v", got, got)
			}
			if gotStr != c.wantInternal {
				t.Errorf("internal_url mismatch:\n  got  = %q\n  want = %q", gotStr, c.wantInternal)
			}
		})
	}
}

// TestSetInternalURL_ReturnsSameMap pins the chaining contract: callers can
// rely on the returned map being the same instance they passed in (allows
// "return setInternalURL(resp, ...)" patterns in handler code if ever needed).
func TestSetInternalURL_ReturnsSameMap(t *testing.T) {
	resp := fiber.Map{"ok": true}
	out := setInternalURL(resp, "pro", "postgres://x@y/z", "postgres")
	// Same backing map — mutating one reflects in the other.
	out["sentinel"] = "v"
	if resp["sentinel"] != "v" {
		t.Fatalf("setInternalURL must return the same map instance")
	}
}

func TestProxiedInternalURL(t *testing.T) {
	cases := []struct {
		name, in, rt, want string
	}{
		{
			name: "postgres rewrites host to pg-proxy, keeps credentials + db",
			in:   "postgres://usr_x:pass@pg.instanode.dev:5432/db_x?sslmode=disable",
			rt:   "postgres",
			want: "postgres://usr_x:pass@instant-pg-proxy.instant.svc.cluster.local:5432/db_x?sslmode=disable",
		},
		{
			name: "redis rewrites to redis-proxy",
			in:   "redis://:pass@redis.instanode.dev/0",
			rt:   "redis",
			want: "redis://:pass@instant-redis-proxy.instant.svc.cluster.local:6379/0",
		},
		{
			name: "mongodb rewrites to mongo-proxy",
			in:   "mongodb://usr_x:pass@mongo.instanode.dev:27017/db_x?authSource=db_x",
			rt:   "mongodb",
			want: "mongodb://usr_x:pass@instant-mongo-proxy.instant.svc.cluster.local:27017/db_x?authSource=db_x",
		},
		{
			name: "queue rewrites to nats-proxy",
			in:   "nats://token@nats.instanode.dev:4222",
			rt:   "queue",
			want: "nats://token@instant-nats-proxy.instant.svc.cluster.local:4222",
		},
		{
			name: "unknown resource type returns input unchanged",
			in:   "https://s3.instanode.dev/bucket/prefix/",
			rt:   "storage",
			want: "https://s3.instanode.dev/bucket/prefix/",
		},
		{
			name: "empty input returns empty",
			in:   "",
			rt:   "postgres",
			want: "",
		},
		{
			name: "malformed input returns input unchanged",
			in:   "::not a url::",
			rt:   "postgres",
			want: "::not a url::",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := proxiedInternalURL(c.in, c.rt)
			if got != c.want {
				t.Errorf("\n  in   = %q\n  rt   = %q\n  got  = %q\n  want = %q", c.in, c.rt, got, c.want)
			}
		})
	}
}
