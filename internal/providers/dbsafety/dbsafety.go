// Package dbsafety hardens the api's DEV-FALLBACK customer-data providers
// (internal/providers/db/local.go + internal/providers/nosql/mongo.go) against
// the truehomie-db DROP incident (2026-06-03).
//
// # Why this package exists
//
// Those two providers are reached ONLY when PROVISIONER_ADDR is unset — the
// explicitly DEV-ONLY fallback path. When reached, they connect as the
// customer-DB superuser (CUSTOMER_DATABASE_URL / MONGO_ADMIN_URI) and run
// direct `DROP DATABASE` / `DROP USER` (Postgres) and dropDatabase / dropUser
// (Mongo) with ZERO audit trail. An api process started WITHOUT
// PROVISIONER_ADDR but WITH a prod customer-DB DSN (a laptop/.env/E2E run
// pointed at a public admin host) would CREATE/DROP real customer databases as
// the superuser, unlogged — exactly the truehomie pattern (an active Pro
// customer's DB + role dropped by an unidentified, non-audited path).
//
// # Defense in depth (three layers, smallest blast radius first)
//
//  1. Production refusal. The fallback is DEV-ONLY, so it must FAIL CLOSED when
//     the process is effectively in production. "Production" is defined
//     robustly as: ENVIRONMENT is not development/test AND the target DSN host
//     is not a clearly-local/in-cluster/dev host. A public or managed host
//     (*.instanode.dev, *.ondigitalocean.com, any routable non-RFC1918,
//     non-loopback host) is refused regardless of ENVIRONMENT, because a
//     misconfigured laptop may not set ENVIRONMENT at all. Localhost,
//     127/8, ::1, RFC1918 ranges, and in-cluster service short-names (no dot)
//     stay dev-safe so local dev, CI (TEST_* DBs on localhost), and the
//     port-forwarded full-stack E2E flow keep working.
//
//  2. Name-convention + denylist guard. Mirrors the provisioner-side
//     internal/dropguard D3 guard: every per-tenant identifier carries a fixed
//     prefix (db_ / usr_) plus a platform-issued token in the charset
//     [A-Za-z0-9._-]; system names (postgres, template0/1, instant_customers,
//     instant_platform, instanode_admin, doadmin, admin/local/config, …) are
//     denylisted. A bug that constructs an empty, wildcard, or system name can
//     never reach the DROP.
//
//  3. Audit. Before any DROP, an audit_log row is emitted via an injected sink
//     (models.WireDBSafetyAuditSink installs a *sql.DB-backed writer at handler
//     construction; provider unit tests fall back to a structured-slog sink) so
//     even if layers 1+2 pass there is a forensic trail. The truehomie incident
//     had none.
package dbsafety

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ErrRefused is the sentinel wrapped by every refusal so callers and tests can
// errors.Is() a dbsafety refusal regardless of message text.
var ErrRefused = errors.New("dbsafety: destructive operation refused")

// maxIdentifierLen is an absurdity bound on validated identifiers — looser than
// Postgres's 63-byte truncation (which is applied consistently on CREATE and
// DROP, so long-token CI resources round-trip) and Mongo's 64-byte db-name
// limit. Refusing at 63 would wedge legitimate long-token deprovisions; only a
// name far beyond any naming scheme is refused.
const maxIdentifierLen = 128

// EnvDevelopment / EnvTest are the only ENVIRONMENT values that, on their own,
// relax the production refusal. Every other value (including the empty string a
// laptop might leave unset) is treated as "maybe production" — the host check
// then decides.
const (
	EnvDevelopment = "development"
	EnvTest        = "test"
)

// dbPrefixes / userPrefixes are the only prefixes a destroyable per-tenant
// identifier may carry. These match the api's local/mongo providers, which name
// every resource db_<token> / usr_<token>.
var (
	dbPrefixes   = []string{"db_"}
	userPrefixes = []string{"usr_"}
)

// reservedTokens are tokens that must never appear as the per-tenant token even
// when the charset would allow them — e.g. a bug flowing a system database or
// admin role name INTO the token field. Compared case-insensitively.
var reservedTokens = map[string]bool{
	"postgres":          true,
	"template0":         true,
	"template1":         true,
	"admin":             true,
	"local":             true,
	"config":            true,
	"default":           true,
	"root":              true,
	"instant_customers": true,
	"instant_platform":  true,
	"instant_cust":      true,
	"instanode_admin":   true,
	"doadmin":           true,
}

// systemDatabases must never be dropped. The per-tenant prefix requirement
// already excludes them; this denylist is belt-and-suspenders.
var systemDatabases = map[string]bool{
	"postgres":          true,
	"template0":         true,
	"template1":         true,
	"instant_customers": true,
	"instant_platform":  true,
	// Mongo system databases.
	"admin":  true,
	"local":  true,
	"config": true,
}

// systemRoles must never be dropped or dropUser'd.
var systemRoles = map[string]bool{
	"postgres":        true,
	"instant_cust":    true,
	"instanode_admin": true,
	"doadmin":         true,
	"admin":           true,
	"root":            true,
	"default":         true,
}

// validTokenChars reports whether every byte of tok is in [A-Za-z0-9._-].
// UUIDs (dashed or dashless), pool- forms, and e2e cohort tokens all fit; SQL
// metacharacters, quotes, spaces, '%' and '*' wildcards do not.
func validTokenChars(tok string) bool {
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.':
		default:
			return false
		}
	}
	return true
}

// CheckDatabaseName validates a database name about to be passed to
// DROP DATABASE / Mongo dropDatabase: it must carry a per-tenant db_ prefix,
// have a valid non-reserved token, and never be a system database.
func CheckDatabaseName(name string) error {
	return checkPrefixed("database", name, dbPrefixes, systemDatabases)
}

// CheckUserName validates a role/user name about to be passed to DROP USER /
// Mongo dropUser: it must carry a per-tenant usr_ prefix, have a valid
// non-reserved token, and never be a system role.
func CheckUserName(name string) error {
	return checkPrefixed("user", name, userPrefixes, systemRoles)
}

// checkPrefixed is the shared prefix + token + denylist validation.
func checkPrefixed(kind, name string, prefixes []string, denylist map[string]bool) error {
	if denylist[strings.ToLower(name)] {
		return fmt.Errorf("%w: %s %q is a protected system identifier", ErrRefused, kind, name)
	}
	if len(name) > maxIdentifierLen {
		return fmt.Errorf("%w: %s %q exceeds %d bytes", ErrRefused, kind, name, maxIdentifierLen)
	}
	for _, p := range prefixes {
		tail, ok := strings.CutPrefix(name, p)
		if !ok {
			continue
		}
		if tail == "" {
			return fmt.Errorf("%w: %s %q has an empty token after prefix %q", ErrRefused, kind, name, p)
		}
		if !validTokenChars(tail) {
			return fmt.Errorf("%w: %s %q has characters outside [A-Za-z0-9._-] after prefix %q", ErrRefused, kind, name, p)
		}
		if reservedTokens[strings.ToLower(tail)] {
			return fmt.Errorf("%w: %s %q embeds a reserved system identifier", ErrRefused, kind, name)
		}
		return nil
	}
	return fmt.Errorf("%w: %s %q does not carry a per-tenant prefix (%s)", ErrRefused, kind, name, strings.Join(prefixes, ", "))
}

// HostFromDSN extracts the bare host (no port) from a postgres:// or mongodb://
// DSN. It tolerates URLs the stdlib parser rejects (raw host:port, multiple
// mongo hosts) by falling back to a manual scan. Returns "" only when no host
// can be found — which IsDevHost treats as NON-dev (fail closed).
func HostFromDSN(dsn string) string {
	if dsn == "" {
		return ""
	}
	// url.Parse handles the common single-host case cleanly. A multi-host mongo
	// DSN (host-a:port,host-b:port) leaves a comma in u.Host that Hostname()
	// mishandles, so it falls through to the manual scan, which splits on the
	// comma to take the FIRST host (every host in the set shares the same
	// trust class for the dev/prod decision).
	if u, err := url.Parse(dsn); err == nil && u.Host != "" && !strings.Contains(u.Host, ",") {
		if h := u.Hostname(); h != "" {
			return h
		}
	}
	// Manual fallback: strip scheme, strip userinfo, take up to the first
	// '/', '?', or ',' (mongo multi-host), then strip the port.
	s := dsn
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if at := strings.LastIndex(s, "@"); at >= 0 {
		s = s[at+1:]
	}
	for _, sep := range []byte{'/', '?', ','} {
		if i := strings.IndexByte(s, sep); i >= 0 {
			s = s[:i]
		}
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return s
}

// IsDevHost reports whether host is a clearly-local / in-cluster / dev target
// that the dev-fallback providers are SAFE to mutate. Dev-safe hosts:
//   - empty-after-trim is NOT dev (fail closed)
//   - "localhost"
//   - loopback IPs (127/8, ::1)
//   - RFC1918 / RFC4193 private IPs (10/8, 172.16/12, 192.168/16, fc00::/7)
//   - link-local (169.254/16, fe80::/10)
//   - in-cluster service short-names (no dot, not an IP) — e.g.
//     "postgres-customers", "mongodb". A dot makes it a routable FQDN
//     (pg.instanode.dev, *.ondigitalocean.com) → NOT dev.
//
// Anything else (public FQDN, routable public IP) is NOT dev → the production
// refusal fires.
func IsDevHost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}
	// Non-IP, non-localhost hostname. A dot means a routable FQDN → not dev.
	// A bare short-name (no dot) is an in-cluster service name → dev-safe.
	return !strings.Contains(host, ".")
}

// IsProductionTarget reports whether a destructive op against dsnHost under the
// given ENVIRONMENT should be refused as "effectively production". Two
// independent signals, EITHER of which refuses:
//
//   - The ENVIRONMENT is production-class (anything that is NOT development or
//     test). The dev-fallback providers are reached ONLY when PROVISIONER_ADDR
//     is unset, which must NEVER be the case in prod — so a prod-class
//     ENVIRONMENT on this path is itself the truehomie misconfiguration, even
//     when the host happens to be an in-cluster short-name (which in prod IS
//     the real customer cluster, e.g. postgres-customers / mongodb).
//   - The target host is NOT clearly local/dev (a public FQDN, managed host
//     such as *.instanode.dev / *.ondigitalocean.com, or a routable public IP).
//     This refuses regardless of ENVIRONMENT — a dev .env that still points at a
//     prod DSN must not drop prod data.
//
// A clearly-dev host under a development/test ENVIRONMENT (or an unset
// ENVIRONMENT, treated as non-prod here only because the host vouches for it)
// is allowed, so local dev, CI (TEST_* DBs on localhost), and the
// port-forwarded full-stack E2E flow keep working.
func IsProductionTarget(env, dsnHost string) bool {
	if !isDevEnv(env) {
		return true
	}
	return !IsDevHost(HostFromDSN(dsnHost))
}

// isDevEnv reports whether env is one of the non-production ENVIRONMENT values
// that, combined with a dev host, permits the fallback path. The empty string
// is treated as dev-env here: a laptop that never set ENVIRONMENT must still
// run local dev / CI, where the HOST check (the stronger signal) is what guards
// against a prod DSN.
func isDevEnv(env string) bool {
	switch strings.ToLower(strings.TrimSpace(env)) {
	case "", EnvDevelopment, EnvTest:
		return true
	default:
		return false
	}
}

// GuardDrop is the single entry point each dev-fallback provider calls BEFORE
// any DROP DATABASE / DROP USER / dropDatabase / dropUser. It runs all three
// layers in order:
//
//  1. production refusal (env + dsnHost)
//  2. name-convention + denylist guard (dbName, and userName when non-empty)
//  3. audit emission (best-effort, via the configured sink) of the now-vetted op
//
// On a layer-1 or layer-2 refusal it returns a wrapped ErrRefused and NO DROP
// must run. The audit row is written only AFTER the op is vetted, so the trail
// records sanctioned drops; refusals are surfaced by the caller's error log +
// the structured slog line dbsafety itself does not own.
//
// userName may be empty when only a database is being dropped; pass "" to skip
// the user-name check.
func GuardDrop(ctx context.Context, p DropParams) error {
	if IsProductionTarget(p.Env, p.DSNHost) {
		return fmt.Errorf("%w: direct %s provider refused — PROVISIONER_ADDR unset against a non-dev customer DB host %q; use the provisioner",
			ErrRefused, p.Provider, HostFromDSN(p.DSNHost))
	}
	if err := CheckDatabaseName(p.DatabaseName); err != nil {
		return err
	}
	if p.UserName != "" {
		if err := CheckUserName(p.UserName); err != nil {
			return err
		}
	}
	emitAudit(ctx, p)
	return nil
}

// DropParams bundles everything GuardDrop needs to vet + audit one destructive
// customer-data operation.
type DropParams struct {
	// Provider is the resolved fallback path, e.g. "db.local" or "nosql.mongo".
	Provider string
	// Env is the process ENVIRONMENT (cfg.Environment).
	Env string
	// DSNHost is the admin DSN whose host is classified for the production
	// refusal — CUSTOMER_DATABASE_URL/POSTGRES_CUSTOMERS_URL for Postgres,
	// MONGO_ADMIN_URI for Mongo. The full DSN is accepted; only the host is
	// used, and credentials are never logged.
	DSNHost string
	// Token is the platform-issued naming token (for the audit summary).
	Token string
	// DatabaseName is the db_<token> name about to be dropped.
	DatabaseName string
	// UserName is the usr_<token> role about to be dropped; "" to skip.
	UserName string
}
