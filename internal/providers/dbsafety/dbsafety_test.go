package dbsafety

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// ─── HostFromDSN ──────────────────────────────────────────────────────────────

func TestHostFromDSN(t *testing.T) {
	cases := []struct {
		name string
		dsn  string
		want string
	}{
		{"empty", "", ""},
		{"postgres_with_userpass_port", "postgres://admin:pw@pg.instanode.dev:25060/instant_customers?sslmode=require", "pg.instanode.dev"},
		{"postgres_localhost", "postgres://postgres:postgres@localhost:5432/postgres", "localhost"},
		{"postgres_short_name", "postgres://instant_cust:x@postgres-customers:5432/instant_customers?sslmode=disable", "postgres-customers"},
		{"mongodb_localhost", "mongodb://root:root@localhost:27017", "localhost"},
		{"mongodb_managed_fqdn", "mongodb://u:p@db-mongo.ondigitalocean.com:27017/admin", "db-mongo.ondigitalocean.com"},
		{"ipv4_loopback", "postgres://u:p@127.0.0.1:5432/d", "127.0.0.1"},
		{"raw_hostport_no_scheme", "pg.example.com:5432", "pg.example.com"},
		{"mongo_multihost_fallback", "mongodb://u:p@host-a:27017,host-b:27017/admin", "host-a"},
		{"no_host_just_path", "postgres:///d", ""},
		{"host_no_port", "postgres://u:p@plainhost/d", "plainhost"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := HostFromDSN(c.dsn); got != c.want {
				t.Fatalf("HostFromDSN(%q) = %q; want %q", c.dsn, got, c.want)
			}
		})
	}
}

// TestHostFromDSN_ManualFallback exercises the manual-scan path for DSNs the
// stdlib url.Parse cannot give a host for (so the url.Parse branch is skipped
// and the fallback scan runs end-to-end, including the SplitHostPort error arm).
func TestHostFromDSN_ManualFallback(t *testing.T) {
	// A scheme-less, userinfo-less, port-less host: url.Parse yields no Host,
	// SplitHostPort fails (no port), so the bare string is returned.
	if got := HostFromDSN("barehost"); got != "barehost" {
		t.Fatalf("manual fallback host = %q; want %q", got, "barehost")
	}
}

// ─── IsDevHost ────────────────────────────────────────────────────────────────

func TestIsDevHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"", false},
		{"localhost", true},
		{"LOCALHOST", true},
		{"  localhost  ", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"10.1.2.3", true},
		{"172.16.0.5", true},
		{"192.168.1.1", true},
		{"169.254.10.10", true},      // link-local v4
		{"fe80::1", true},            // link-local v6
		{"fc00::1", true},            // unique-local v6 (IsPrivate)
		{"8.8.8.8", false},           // public IP
		{"postgres-customers", true}, // in-cluster short name (no dot)
		{"mongodb", true},            // in-cluster short name
		{"pg.instanode.dev", false},  // routable FQDN
		{"db.ondigitalocean.com", false},
	}
	for _, c := range cases {
		t.Run(c.host, func(t *testing.T) {
			if got := IsDevHost(c.host); got != c.want {
				t.Fatalf("IsDevHost(%q) = %v; want %v", c.host, got, c.want)
			}
		})
	}
}

// ─── IsProductionTarget ───────────────────────────────────────────────────────

func TestIsProductionTarget(t *testing.T) {
	cases := []struct {
		name string
		env  string
		dsn  string
		want bool
	}{
		{"dev_host_dev_env", EnvDevelopment, "postgres://u:p@localhost:5432/d", false},
		{"dev_host_test_env", EnvTest, "postgres://u:p@127.0.0.1:5432/d", false},
		{"dev_host_empty_env", "", "postgres://u:p@postgres-customers:5432/d", false},
		// Prod-class ENVIRONMENT refuses even a dev-class host: the fallback
		// must never run in prod (in prod, postgres-customers IS the real
		// customer cluster — the truehomie case).
		{"dev_host_prod_env_refused", "production", "postgres://u:p@localhost:5432/d", true},
		{"dev_host_staging_env_refused", "staging", "postgres://u:p@postgres-customers:5432/d", true},
		{"prod_host_dev_env_still_refused", EnvDevelopment, "postgres://u:p@pg.instanode.dev:25060/d", true},
		{"prod_host_test_env_still_refused", EnvTest, "mongodb://u:p@db.ondigitalocean.com:27017/admin", true},
		{"prod_host_prod_env", "production", "postgres://u:p@pg.instanode.dev:25060/d", true},
		{"empty_dsn_dev_env_is_prod", EnvDevelopment, "", true},
		{"public_ip_dev_env_is_prod", EnvDevelopment, "postgres://u:p@8.8.8.8:5432/d", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsProductionTarget(c.env, c.dsn); got != c.want {
				t.Fatalf("IsProductionTarget(%q,%q) = %v; want %v", c.env, c.dsn, got, c.want)
			}
		})
	}
}

// ─── CheckDatabaseName / CheckUserName ────────────────────────────────────────

func TestCheckDatabaseName(t *testing.T) {
	good := []string{
		"db_550e8400-e29b-41d4-a716-446655440000",
		"db_550e8400e29b41d4a716446655440000",
		"db_pool-abc123",
		"db_tok",
		"db_e2e.cohort_42",
		"db_AbCdEf012345", // mixed-case token (e2e/CI tokens may carry A-Z) — exercises the uppercase char-class branch
	}
	for _, n := range good {
		if err := CheckDatabaseName(n); err != nil {
			t.Fatalf("CheckDatabaseName(%q) unexpected error: %v", n, err)
		}
	}

	bad := []struct {
		name string
		want string // substring of the refusal
	}{
		{"", "per-tenant prefix"},
		{"postgres", "protected system identifier"},
		{"instant_customers", "protected system identifier"},
		{"instant_platform", "protected system identifier"},
		{"template1", "protected system identifier"},
		{"admin", "protected system identifier"}, // mongo system db
		{"usr_abc", "per-tenant prefix"},         // wrong prefix
		{"db_", "empty token"},
		{"db_bad;DROP", "outside [A-Za-z0-9._-]"},
		{"db_with space", "outside [A-Za-z0-9._-]"},
		{"db_*", "outside [A-Za-z0-9._-]"},
		{"db_postgres", "reserved system identifier"}, // reserved token after prefix
		{"db_" + strings.Repeat("a", maxIdentifierLen), "exceeds"},
	}
	for _, c := range bad {
		t.Run("bad/"+c.name, func(t *testing.T) {
			err := CheckDatabaseName(c.name)
			if err == nil {
				t.Fatalf("CheckDatabaseName(%q) = nil; want refusal", c.name)
			}
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("CheckDatabaseName(%q) error %v not ErrRefused", c.name, err)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("CheckDatabaseName(%q) = %v; want substring %q", c.name, err, c.want)
			}
		})
	}
}

func TestCheckUserName(t *testing.T) {
	if err := CheckUserName("usr_550e8400e29b41d4a716446655440000"); err != nil {
		t.Fatalf("valid user name rejected: %v", err)
	}

	bad := []struct {
		name string
		want string
	}{
		{"", "per-tenant prefix"},
		{"instanode_admin", "protected system identifier"},
		{"doadmin", "protected system identifier"},
		{"postgres", "protected system identifier"},
		{"instant_cust", "protected system identifier"},
		{"root", "protected system identifier"},
		{"default", "protected system identifier"},
		{"db_abc", "per-tenant prefix"}, // wrong prefix for a user
		{"usr_", "empty token"},
		{"usr_a*b", "outside [A-Za-z0-9._-]"},
		{"usr_doadmin", "reserved system identifier"},
		{"usr_" + strings.Repeat("z", maxIdentifierLen), "exceeds"},
	}
	for _, c := range bad {
		t.Run("bad/"+c.name, func(t *testing.T) {
			err := CheckUserName(c.name)
			if err == nil {
				t.Fatalf("CheckUserName(%q) = nil; want refusal", c.name)
			}
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("CheckUserName(%q) error %v not ErrRefused", c.name, err)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("CheckUserName(%q) = %v; want %q", c.name, err, c.want)
			}
		})
	}
}

// ─── GuardDrop ────────────────────────────────────────────────────────────────

func TestGuardDrop_RefusesProduction(t *testing.T) {
	// Capture audit calls so we can assert the audit is NOT emitted on refusal.
	rec := newRecordingSink()
	SetAuditSink(rec)
	t.Cleanup(func() { SetAuditSink(nil) })

	err := GuardDrop(context.Background(), DropParams{
		Provider:     "db.local",
		Env:          EnvDevelopment, // even dev env refuses a prod host
		DSNHost:      "postgres://admin:pw@pg.instanode.dev:25060/instant_customers?sslmode=require",
		Token:        "tok",
		DatabaseName: "db_tok",
		UserName:     "usr_tok",
	})
	if err == nil || !errors.Is(err, ErrRefused) {
		t.Fatalf("GuardDrop against prod host must refuse; got %v", err)
	}
	if !strings.Contains(err.Error(), "pg.instanode.dev") || !strings.Contains(err.Error(), "db.local") {
		t.Fatalf("refusal should name host + provider; got %v", err)
	}
	if rec.count() != 0 {
		t.Fatalf("no audit must be emitted on a refused drop; got %d", rec.count())
	}
}

func TestGuardDrop_RefusesBadDatabaseName(t *testing.T) {
	rec := newRecordingSink()
	SetAuditSink(rec)
	t.Cleanup(func() { SetAuditSink(nil) })

	err := GuardDrop(context.Background(), DropParams{
		Provider:     "db.local",
		Env:          EnvDevelopment,
		DSNHost:      "postgres://u:p@localhost:5432/d",
		Token:        "postgres",
		DatabaseName: "postgres", // system DB — must refuse
		UserName:     "usr_x",
	})
	if err == nil || !errors.Is(err, ErrRefused) {
		t.Fatalf("system DB name must refuse; got %v", err)
	}
	if rec.count() != 0 {
		t.Fatalf("no audit on refused drop; got %d", rec.count())
	}
}

func TestGuardDrop_RefusesBadUserName(t *testing.T) {
	rec := newRecordingSink()
	SetAuditSink(rec)
	t.Cleanup(func() { SetAuditSink(nil) })

	err := GuardDrop(context.Background(), DropParams{
		Provider:     "nosql.mongo",
		Env:          EnvDevelopment,
		DSNHost:      "mongodb://root:root@localhost:27017",
		Token:        "instanode_admin",
		DatabaseName: "db_tok",
		UserName:     "instanode_admin", // admin role — must refuse
	})
	if err == nil || !errors.Is(err, ErrRefused) {
		t.Fatalf("admin role name must refuse; got %v", err)
	}
	if rec.count() != 0 {
		t.Fatalf("no audit on refused drop; got %d", rec.count())
	}
}

func TestGuardDrop_AllowsDevAndAudits(t *testing.T) {
	rec := newRecordingSink()
	SetAuditSink(rec)
	t.Cleanup(func() { SetAuditSink(nil) })

	err := GuardDrop(context.Background(), DropParams{
		Provider:     "db.local",
		Env:          EnvDevelopment,
		DSNHost:      "postgres://u:p@postgres-customers:5432/d",
		Token:        "tok",
		DatabaseName: "db_tok",
		UserName:     "usr_tok",
	})
	if err != nil {
		t.Fatalf("dev host + valid names must pass; got %v", err)
	}
	if rec.count() != 1 {
		t.Fatalf("a sanctioned drop must emit exactly one audit; got %d", rec.count())
	}
	got := rec.last()
	if got.Kind != AuditKindCustomerDBDirectDrop {
		t.Fatalf("audit kind = %q; want %q", got.Kind, AuditKindCustomerDBDirectDrop)
	}
	if got.DSNHost != "postgres-customers" {
		t.Fatalf("audit dsn_host = %q; want bare host", got.DSNHost)
	}
	if got.DatabaseName != "db_tok" || got.UserName != "usr_tok" {
		t.Fatalf("audit names wrong: %+v", got)
	}
}

// TestGuardDrop_AllowsDevNoUser covers the UserName=="" skip path.
func TestGuardDrop_AllowsDevNoUser(t *testing.T) {
	rec := newRecordingSink()
	SetAuditSink(rec)
	t.Cleanup(func() { SetAuditSink(nil) })

	err := GuardDrop(context.Background(), DropParams{
		Provider:     "db.local",
		Env:          EnvTest,
		DSNHost:      "postgres://u:p@localhost:5432/d",
		Token:        "tok",
		DatabaseName: "db_tok",
		UserName:     "", // skip user check
	})
	if err != nil {
		t.Fatalf("empty user must skip the user check; got %v", err)
	}
	if rec.count() != 1 {
		t.Fatalf("want one audit; got %d", rec.count())
	}
}
