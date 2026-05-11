package handlers

import "testing"

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
