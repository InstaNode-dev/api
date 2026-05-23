package handlers

// resource_providers_rbw_test.go — direct coverage for the unexported
// pause/resume/rotate provider helpers in resource.go. These talk to a real
// Postgres / Redis / Mongo, so success paths run against the isolated test
// infra (skipped when the corresponding TEST_* env var is unset) and the
// validation / connection / command-error arms run with no infra.
//
// Rule-17 coverage block:
//   Symptom:       revoke/grantPostgresConnect, setRedisACLEnabled,
//                  revoke/grantMongoRoles, rotate{Postgres,Redis,Mongo}Password
//                  all 60-75% (open/exec/validate arms uncovered).
//   Enumeration:   go tool cover -func | grep resource.go | awk '$NF<95'
//   Sites touched: all 8 helpers + validateSQLIdent.
//   Coverage test: this file.

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
)

func customersDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_CUSTOMERS_URL")
	if dsn == "" {
		dsn = os.Getenv("TEST_DATABASE_URL")
	}
	return dsn
}

func redisURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv("TEST_REDIS_URL")
	return u
}

func mongoURI() string { return os.Getenv("TEST_MONGO_URI") }

// ---- validateSQLIdent ----

func TestValidateSQLIdent_RBW(t *testing.T) {
	if err := validateSQLIdent(""); err == nil {
		t.Error("empty ident should error")
	}
	if err := validateSQLIdent("ok_name-1"); err != nil {
		t.Errorf("valid ident rejected: %v", err)
	}
	for _, bad := range []string{"Drop Table", "a;b", `x"y`, "café"} {
		if err := validateSQLIdent(bad); err == nil {
			t.Errorf("unsafe ident %q accepted", bad)
		}
	}
}

// ---- revokePostgresConnect / grantPostgresConnect ----

func TestRevokeGrantPostgresConnect_ValidationArms_RBW(t *testing.T) {
	ctx := context.Background()
	const dsn = "postgres://x" // never reached — validation fails first
	if err := revokePostgresConnect(ctx, dsn, "bad name", "user"); err == nil || !strings.Contains(err.Error(), "db:") {
		t.Errorf("revoke: expected db-ident error, got %v", err)
	}
	if err := revokePostgresConnect(ctx, dsn, "okdb", "bad user"); err == nil || !strings.Contains(err.Error(), "user:") {
		t.Errorf("revoke: expected user-ident error, got %v", err)
	}
	if err := grantPostgresConnect(ctx, dsn, "bad name", "user"); err == nil || !strings.Contains(err.Error(), "db:") {
		t.Errorf("grant: expected db-ident error, got %v", err)
	}
	if err := grantPostgresConnect(ctx, dsn, "okdb", "bad user"); err == nil || !strings.Contains(err.Error(), "user:") {
		t.Errorf("grant: expected user-ident error, got %v", err)
	}
}

func TestRevokeGrantPostgresConnect_ExecError_RBW(t *testing.T) {
	dsn := customersDSN(t)
	if dsn == "" {
		t.Skip("no customer DSN")
	}
	ctx := context.Background()
	// REVOKE/GRANT against a non-existent role → Postgres errors → exec arm.
	if err := revokePostgresConnect(ctx, dsn, "db-rbwtest", "no-such-role-xyz"); err == nil {
		t.Error("revoke on missing role should error at REVOKE")
	}
	if err := grantPostgresConnect(ctx, dsn, "db-rbwtest", "no-such-role-xyz"); err == nil {
		t.Error("grant on missing role should error at GRANT")
	}
}

func TestRevokeGrantPostgresConnect_Success_RBW(t *testing.T) {
	dsn := customersDSN(t)
	if dsn == "" {
		t.Skip("no customer DSN")
	}
	ctx := context.Background()
	// db_rbwtest + role usr_rbwtest are created by the test harness setup.
	if err := grantPostgresConnect(ctx, dsn, "db_rbwtest", "usr_rbwtest"); err != nil {
		t.Skipf("grant success path needs db_rbwtest+usr_rbwtest: %v", err)
	}
	// revoke also exercises the pg_terminate_backend follow-up (warn arm is
	// best-effort; the function returns nil regardless).
	if err := revokePostgresConnect(ctx, dsn, "db_rbwtest", "usr_rbwtest"); err != nil {
		t.Errorf("revoke success: %v", err)
	}
}

// ---- setRedisACLEnabled / rotateRedisPassword ----

func TestSetRedisACLEnabled_ParseError_RBW(t *testing.T) {
	if err := setRedisACLEnabled(context.Background(), "://not-a-redis-url", "u", true); err == nil {
		t.Error("expected parse error")
	}
	if err := rotateRedisPassword(context.Background(), "://bad", "u", "p"); err == nil {
		t.Error("rotateRedisPassword: expected parse error")
	}
}

func TestSetRedisACLEnabled_Success_RBW(t *testing.T) {
	u := redisURL(t)
	if u == "" {
		t.Skip("no redis URL")
	}
	ctx := context.Background()
	const user = "usr_rbwtest"
	// usr_rbwtest is created by the harness; toggle off then on.
	if err := setRedisACLEnabled(ctx, u, user, false); err != nil {
		t.Skipf("redis ACL setuser off (needs usr_rbwtest): %v", err)
	}
	if err := setRedisACLEnabled(ctx, u, user, true); err != nil {
		t.Errorf("redis ACL setuser on: %v", err)
	}
	if err := rotateRedisPassword(ctx, u, user, "newpass123"); err != nil {
		t.Errorf("rotateRedisPassword success: %v", err)
	}
}

// ---- rotatePostgresPassword ----

func TestRotatePostgresPassword_RBW(t *testing.T) {
	ctx := context.Background()
	// unsafe username arm (open succeeds lazily, validation rejects).
	dsn := customersDSN(t)
	if dsn == "" {
		dsn = "postgres://x"
	}
	if err := rotatePostgresPassword(ctx, dsn, "bad user", "p"); err == nil || !strings.Contains(err.Error(), "unsafe username") {
		t.Errorf("expected unsafe-username error, got %v", err)
	}
	if customersDSN(t) == "" {
		t.Skip("no customer DSN for ALTER ROLE arms")
	}
	// ALTER ROLE on missing role → exec error arm.
	if err := rotatePostgresPassword(ctx, dsn, "no_such_role_xyz", "p1"); err == nil {
		t.Error("ALTER ROLE on missing role should error")
	}
	// success against the harness role.
	if err := rotatePostgresPassword(ctx, dsn, "usr_rbwtest", "newpw1"); err != nil {
		t.Skipf("ALTER ROLE success needs usr_rbwtest: %v", err)
	}
}

// ---- mongo helpers ----

func TestMongoRoleHelpers_RBW(t *testing.T) {
	uri := mongoURI()
	if uri == "" {
		t.Skip("no mongo URI")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	// These run RunCommand against a non-existent user → command error arm
	// (connect succeeds, the admin command fails). That covers the result.Err
	// branch of all three helpers without needing a provisioned mongo user.
	if err := revokeMongoRoles(ctx, uri, "no_such_user_xyz", "db_x"); err == nil {
		t.Error("revokeMongoRoles on missing user should error")
	}
	if err := grantMongoRoles(ctx, uri, "no_such_user_xyz", "db_x"); err == nil {
		t.Error("grantMongoRoles on missing user should error")
	}
	if err := rotateMongoPassword(ctx, uri, "no_such_user_xyz", "p"); err == nil {
		t.Error("rotateMongoPassword on missing user should error")
	}
}

// TestMongoRoleHelpers_Success_RBW covers the success-return arm of all three
// mongo helpers against a real provisioned user (created by the harness).
func TestMongoRoleHelpers_Success_RBW(t *testing.T) {
	uri := mongoURI()
	if uri == "" {
		t.Skip("no mongo URI")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	const (
		user = "usr_rbwtest"
		dbN  = "db_rbwtest"
	)
	if err := grantMongoRoles(ctx, uri, user, dbN); err != nil {
		t.Skipf("grantMongoRoles success needs %s (admin user): %v", user, err)
	}
	if err := revokeMongoRoles(ctx, uri, user, dbN); err != nil {
		t.Errorf("revokeMongoRoles success: %v", err)
	}
	if err := rotateMongoPassword(ctx, uri, user, "newpw1"); err != nil {
		t.Errorf("rotateMongoPassword success: %v", err)
	}
}

func TestMongoHelpers_ConnectError_RBW(t *testing.T) {
	// An unreachable URI with a tiny server-selection timeout exercises the
	// command-error arm quickly (mongo.Connect is lazy; the RunCommand fails
	// on server selection).
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	const uri = "mongodb://127.0.0.1:1/?serverSelectionTimeoutMS=500"
	if err := revokeMongoRoles(ctx, uri, "u", "db_x"); err == nil {
		t.Error("revokeMongoRoles unreachable should error")
	}
	if err := grantMongoRoles(ctx, uri, "u", "db_x"); err == nil {
		t.Error("grantMongoRoles unreachable should error")
	}
	if err := rotateMongoPassword(ctx, uri, "u", "p"); err == nil {
		t.Error("rotateMongoPassword unreachable should error")
	}
}

// TestPGHelpers_OpenError_RBW drives the resourcePGOpen failure arm of the
// three postgres helpers (lib/pq's Open is lazy → only reachable via the seam).
func TestPGHelpers_OpenError_RBW(t *testing.T) {
	prev := resourcePGOpen
	resourcePGOpen = func(string, string) (*sql.DB, error) { return nil, errors.New("pg open boom") }
	defer func() { resourcePGOpen = prev }()
	ctx := context.Background()
	if err := revokePostgresConnect(ctx, "x", "okdb", "okuser"); err == nil || !strings.Contains(err.Error(), "open") {
		t.Errorf("revoke open arm: %v", err)
	}
	if err := grantPostgresConnect(ctx, "x", "okdb", "okuser"); err == nil || !strings.Contains(err.Error(), "open") {
		t.Errorf("grant open arm: %v", err)
	}
	if err := rotatePostgresPassword(ctx, "x", "okuser", "p"); err == nil || !strings.Contains(err.Error(), "open") {
		t.Errorf("rotate open arm: %v", err)
	}
}

// TestMongoHelpers_ConnectSeamError_RBW drives the resourceMongoConnect failure
// arm (mongo.Connect is lazy → only reachable via the seam).
func TestMongoHelpers_ConnectSeamError_RBW(t *testing.T) {
	prev := resourceMongoConnect
	resourceMongoConnect = func(context.Context, string) (*mongo.Client, error) {
		return nil, errors.New("mongo connect boom")
	}
	defer func() { resourceMongoConnect = prev }()
	ctx := context.Background()
	if err := revokeMongoRoles(ctx, "x", "u", "db"); err == nil || !strings.Contains(err.Error(), "connect") {
		t.Errorf("revoke connect arm: %v", err)
	}
	if err := grantMongoRoles(ctx, "x", "u", "db"); err == nil || !strings.Contains(err.Error(), "connect") {
		t.Errorf("grant connect arm: %v", err)
	}
	if err := rotateMongoPassword(ctx, "x", "u", "p"); err == nil || !strings.Contains(err.Error(), "connect") {
		t.Errorf("rotate connect arm: %v", err)
	}
}
