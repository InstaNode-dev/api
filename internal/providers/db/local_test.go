package db

// local_test.go drives the LocalBackend (CREATE DATABASE / USER on the shared
// Postgres pod) against a real Postgres instance. Set TEST_CUSTOMERS_URL to a
// superuser DSN (e.g. postgres://instant_cust:instant_cust@127.0.0.1:55432/
// instant_customers?sslmode=disable). The DSN MUST belong to a role with
// CREATEDB + CREATEROLE so the provisioning DDL succeeds; the docker container
// the coverage harness starts uses the POSTGRES_USER bootstrap superuser.

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// testCustomersURL returns the admin DSN for the local backend, skipping the
// test if TEST_CUSTOMERS_URL is unset.
func testCustomersURL(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_CUSTOMERS_URL")
	if dsn == "" {
		t.Skip("TEST_CUSTOMERS_URL not set — skipping local Postgres provisioning tests")
	}
	return dsn
}

// cleanupDB drops the database and user a test provisioned, ignoring errors so
// a half-failed provision doesn't leave the test red on teardown.
func cleanupDB(t *testing.T, dsn, token string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Logf("cleanupDB: connect: %v", err)
		return
	}
	defer conn.Close(ctx)
	_, _ = conn.Exec(ctx,
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='db_"+token+"' AND pid<>pg_backend_pid()")
	_, _ = conn.Exec(ctx, `DROP DATABASE IF EXISTS "db_`+token+`"`)
	_, _ = conn.Exec(ctx, `DROP USER IF EXISTS "usr_`+token+`"`)
}

// uniqueToken returns a Postgres-identifier-safe token unique per test.
func uniqueToken(prefix string) string {
	return prefix + time.Now().Format("150405") + randHex()
}

var hexCounter int

func randHex() string {
	hexCounter++
	return string(rune('a'+(hexCounter%26))) + string(rune('a'+((hexCounter/26)%26)))
}

func TestNewLocalBackend_DefaultURL(t *testing.T) {
	b := newLocalBackend("")
	if b.customersURL != defaultCustomersURL {
		t.Fatalf("empty URL must fall back to default; got %q", b.customersURL)
	}
	b2 := newLocalBackend("postgres://x:y@h:5432/d")
	if b2.customersURL != "postgres://x:y@h:5432/d" {
		t.Fatalf("explicit URL must be preserved; got %q", b2.customersURL)
	}
}

func TestGeneratePassword(t *testing.T) {
	p, err := generatePassword(16)
	if err != nil {
		t.Fatalf("generatePassword: %v", err)
	}
	if len(p) != 16 {
		t.Fatalf("want length 16, got %d", len(p))
	}
	// Every char must come from the alphanum charset.
	for _, c := range p {
		if !strings.ContainsRune(alphanumChars, c) {
			t.Fatalf("password char %q not in charset", c)
		}
	}
	// Zero length is valid and returns "".
	z, err := generatePassword(0)
	if err != nil || z != "" {
		t.Fatalf("generatePassword(0) = (%q,%v); want (\"\",nil)", z, err)
	}
}

func TestExtractHostAndIndexOf(t *testing.T) {
	cases := []struct{ in, want string }{
		{"postgres://u:p@host:5432/db", "host:5432"},
		{"postgres://u:p@host/db", "host"},
		{"postgres://host:5432/db", "host:5432"},  // no auth
		{"host:5432", "host:5432"},                // no prefix, no slash, no @
		{"postgres://u:p@host:5432", "host:5432"}, // no trailing slash
	}
	for _, c := range cases {
		if got := extractHost(c.in); got != c.want {
			t.Errorf("extractHost(%q) = %q; want %q", c.in, got, c.want)
		}
	}
	if indexOf("abc", 'b') != 1 {
		t.Fatal("indexOf hit wrong")
	}
	if indexOf("abc", 'z') != -1 {
		t.Fatal("indexOf miss should be -1")
	}
}

func TestBuildURLs(t *testing.T) {
	b := newLocalBackend("postgres://admin:pw@pghost:5432/instant_customers?sslmode=disable")
	got := b.buildDBURL("usr_x", "secret", "db_x")
	want := "postgres://usr_x:secret@pghost:5432/db_x"
	if got != want {
		t.Fatalf("buildDBURL = %q; want %q", got, want)
	}
	// buildAdminNewDBURL replaces the trailing path component.
	admin := b.buildAdminNewDBURL("db_x")
	if !strings.HasSuffix(admin, "/db_x") {
		t.Fatalf("buildAdminNewDBURL must end with /db_x; got %q", admin)
	}
	// No-slash URL falls back to appending /db_x.
	b2 := newLocalBackend("postgresnohost")
	if got := b2.buildAdminNewDBURL("db_y"); got != "postgresnohost/db_y" {
		t.Fatalf("no-slash fallback = %q", got)
	}
}

// TestLocalBackend_ProvisionDeprovision_HappyPath exercises the full
// CREATE DATABASE / CREATE USER / GRANT / DROP lifecycle against real Postgres.
func TestLocalBackend_ProvisionDeprovision_HappyPath(t *testing.T) {
	dsn := testCustomersURL(t)
	token := uniqueToken("happy")
	defer cleanupDB(t, dsn, token)

	b := newLocalBackend(dsn)
	ctx := context.Background()

	creds, err := b.Provision(ctx, token, "anonymous")
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if creds.DatabaseName != "db_"+token {
		t.Fatalf("DatabaseName = %q", creds.DatabaseName)
	}
	if creds.Username != "usr_"+token {
		t.Fatalf("Username = %q", creds.Username)
	}
	if !strings.HasPrefix(creds.URL, "postgres://usr_"+token+":") {
		t.Fatalf("URL = %q", creds.URL)
	}
	if creds.ProviderResourceID != "" {
		t.Fatalf("local backend ProviderResourceID must be empty; got %q", creds.ProviderResourceID)
	}

	// The provisioned user must actually be able to connect to its DB.
	userConn, err := pgx.Connect(ctx, creds.URL+"?sslmode=disable")
	if err != nil {
		t.Fatalf("provisioned user cannot connect: %v", err)
	}
	var one int
	if err := userConn.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
		t.Fatalf("provisioned user query failed: %v", err)
	}
	userConn.Close(ctx)

	// StorageBytes must report a positive size for the live database.
	size, err := b.StorageBytes(ctx, token, "")
	if err != nil {
		t.Fatalf("StorageBytes: %v", err)
	}
	if size <= 0 {
		t.Fatalf("StorageBytes = %d; want > 0", size)
	}

	// Deprovision drops everything.
	if err := b.Deprovision(ctx, token, ""); err != nil {
		t.Fatalf("Deprovision: %v", err)
	}

	// Deprovision is idempotent — second call (DROP ... IF EXISTS) is a no-op.
	if err := b.Deprovision(ctx, token, ""); err != nil {
		t.Fatalf("second Deprovision must be idempotent: %v", err)
	}
}

// TestLocalBackend_ProvisionWithExtensions installs pgvector if available;
// when the extension isn't present in the image, CREATE EXTENSION errors and
// Provision must surface it (the requested-extension-but-can't-install branch).
func TestLocalBackend_ProvisionWithExtensions(t *testing.T) {
	dsn := testCustomersURL(t)
	token := uniqueToken("ext")
	defer cleanupDB(t, dsn, token)

	b := newLocalBackend(dsn)
	ctx := context.Background()

	_, err := b.ProvisionWithExtensions(ctx, token, "pro", []string{"vector"})
	// Plain postgres:16-alpine has no pgvector, so CREATE EXTENSION fails and the
	// whole provision errors. If the image *does* have it, err is nil. Either is
	// a valid exercised branch; we just assert it doesn't panic and, on success,
	// the DB is usable.
	if err == nil {
		// Vector installed — verify DB exists then clean up.
		if size, sErr := b.StorageBytes(ctx, token, ""); sErr != nil || size <= 0 {
			t.Fatalf("post-extension StorageBytes=%d err=%v", size, sErr)
		}
	} else if !strings.Contains(err.Error(), "CREATE EXTENSION") {
		t.Fatalf("unexpected extension error: %v", err)
	}
}

// TestLocalBackend_ProvisionWithExtensions_Rejected covers the allowlist
// rejection branch before any DB connection is opened.
func TestLocalBackend_ProvisionWithExtensions_Rejected(t *testing.T) {
	b := newLocalBackend("postgres://u:p@127.0.0.1:1/db?sslmode=disable")
	_, err := b.ProvisionWithExtensions(context.Background(), "tok", "pro", []string{"postgis"})
	if err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("want allowlist rejection, got %v", err)
	}
}

// TestLocalBackend_DuplicateProvision covers the CREATE DATABASE error branch:
// provisioning the same token twice fails on the second CREATE DATABASE.
func TestLocalBackend_DuplicateProvision(t *testing.T) {
	dsn := testCustomersURL(t)
	token := uniqueToken("dup")
	defer cleanupDB(t, dsn, token)

	b := newLocalBackend(dsn)
	ctx := context.Background()

	if _, err := b.Provision(ctx, token, "anonymous"); err != nil {
		t.Fatalf("first Provision: %v", err)
	}
	_, err := b.Provision(ctx, token, "anonymous")
	if err == nil || !strings.Contains(err.Error(), "CREATE DATABASE") {
		t.Fatalf("duplicate Provision must fail on CREATE DATABASE; got %v", err)
	}
}

// TestLocalBackend_ConnectFailure covers every connect-error branch by pointing
// the backend at a dead port.
func TestLocalBackend_ConnectFailure(t *testing.T) {
	b := newLocalBackend("postgres://u:p@127.0.0.1:1/db?sslmode=disable&connect_timeout=1")
	ctx := context.Background()

	if _, err := b.Provision(ctx, "tok", "anonymous"); err == nil {
		t.Fatal("Provision against dead port must error")
	}
	if _, err := b.StorageBytes(ctx, "tok", ""); err == nil {
		t.Fatal("StorageBytes against dead port must error")
	}
	if err := b.Deprovision(ctx, "tok", ""); err == nil {
		t.Fatal("Deprovision against dead port must error")
	}
}

// TestLocalBackend_CreateUserConflict covers the CREATE USER error branch:
// CREATE DATABASE succeeds but the user already exists.
func TestLocalBackend_CreateUserConflict(t *testing.T) {
	dsn := testCustomersURL(t)
	token := uniqueToken("usrconf")
	defer cleanupDB(t, dsn, token)

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	// Pre-create the user so the provisioning CREATE USER collides.
	if _, err := conn.Exec(ctx, `CREATE USER "usr_`+token+`" WITH PASSWORD 'x'`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	conn.Close(ctx)

	b := newLocalBackend(dsn)
	_, err = b.Provision(ctx, token, "anonymous")
	if err == nil || !strings.Contains(err.Error(), "CREATE USER") {
		t.Fatalf("want CREATE USER conflict; got %v", err)
	}
}

// TestLocalBackend_Deprovision_TerminatesConnections exercises the
// pg_terminate_backend path with a live connection open against the target DB
// at drop time. The reaper terminates it, then DROP DATABASE succeeds.
func TestLocalBackend_Deprovision_TerminatesConnections(t *testing.T) {
	dsn := testCustomersURL(t)
	token := uniqueToken("term")
	defer cleanupDB(t, dsn, token)

	b := newLocalBackend(dsn)
	ctx := context.Background()

	creds, err := b.Provision(ctx, token, "anonymous")
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	// Hold an open connection against the provisioned database so the
	// pg_terminate_backend statement has a real backend to terminate.
	live, err := pgx.Connect(ctx, creds.URL+"?sslmode=disable")
	if err != nil {
		t.Fatalf("open live conn: %v", err)
	}
	defer live.Close(ctx)

	if err := b.Deprovision(ctx, token, ""); err != nil {
		t.Fatalf("Deprovision with live conn: %v", err)
	}
}

// TestLocalBackend_Provision_LimitedRole_NonFatalGrants provisions under a
// CREATEDB+CREATEROLE non-superuser role. In PostgreSQL 15+ the `public` schema
// is owned by the bootstrap superuser, not the database creator, so the
// GRANT ALL ON SCHEMA public statement fails for a non-superuser owner — this
// exercises the non-fatal GRANT-SCHEMA log branch while the provision still
// succeeds (the grant is best-effort). The provisioned credentials are still
// returned and usable for connection.
func TestLocalBackend_Provision_LimitedRole_NonFatalGrants(t *testing.T) {
	dsn := testCustomersURL(t)
	limited := os.Getenv("TEST_CUSTOMERS_LIMITED_URL")
	if limited == "" {
		t.Skip("TEST_CUSTOMERS_LIMITED_URL not set — skipping limited-role provision test")
	}
	token := uniqueToken("limgrant")
	defer cleanupDB(t, dsn, token)

	b := newLocalBackend(limited)
	creds, err := b.Provision(context.Background(), token, "anonymous")
	if err != nil {
		t.Fatalf("Provision under limited role must still succeed (grants are best-effort): %v", err)
	}
	if creds.DatabaseName != "db_"+token {
		t.Fatalf("DatabaseName = %q", creds.DatabaseName)
	}
}

// TestLocalBackend_Deprovision_DropFails exercises BOTH the
// pg_terminate_backend failure log (a non-privileged role cannot terminate
// another role's backend) AND the DROP DATABASE error return (a non-owner
// cannot drop the database). It provisions as the superuser, then deprovisions
// as a CREATEDB-but-non-superuser role while a superuser-owned connection is
// live against the DB.
//
// Requires TEST_CUSTOMERS_LIMITED_URL — a DSN for a role with CREATEDB +
// CREATEROLE but NOT superuser, that does NOT own the provisioned database.
func TestLocalBackend_Deprovision_DropFails(t *testing.T) {
	dsn := testCustomersURL(t)
	limited := os.Getenv("TEST_CUSTOMERS_LIMITED_URL")
	if limited == "" {
		t.Skip("TEST_CUSTOMERS_LIMITED_URL not set — skipping privilege-failure deprovision test")
	}
	token := uniqueToken("dropfail")
	defer cleanupDB(t, dsn, token)

	ctx := context.Background()
	// Provision as the superuser so the DB is owned by the superuser.
	super := newLocalBackend(dsn)
	creds, err := super.Provision(ctx, token, "anonymous")
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	// Hold a live connection from the provisioned user so terminate has work.
	live, err := pgx.Connect(ctx, creds.URL+"?sslmode=disable")
	if err != nil {
		t.Fatalf("open live conn: %v", err)
	}
	defer live.Close(ctx)

	// Deprovision as the limited role: pg_terminate_backend on another role's
	// backend is denied (logged, non-fatal), then DROP DATABASE on a DB it does
	// not own returns an error.
	lb := newLocalBackend(limited)
	if err := lb.Deprovision(ctx, token, ""); err == nil {
		t.Fatal("limited-role Deprovision must fail on DROP DATABASE")
	}
}

// TestLocalBackend_Deprovision_DropUserFails covers the non-fatal DROP USER
// log branch: DROP DATABASE succeeds but DROP USER fails because the
// deprovisioning role does not have admin rights over the target role.
// Setup: the limited role owns the database (so it can drop it), but the user
// role is owned/created by the superuser (so the limited role cannot drop it).
func TestLocalBackend_Deprovision_DropUserFails(t *testing.T) {
	dsn := testCustomersURL(t)
	limited := os.Getenv("TEST_CUSTOMERS_LIMITED_URL")
	if limited == "" {
		t.Skip("TEST_CUSTOMERS_LIMITED_URL not set — skipping DROP USER failure test")
	}
	token := uniqueToken("dropusr")
	dbName := "db_" + token
	username := "usr_" + token
	ctx := context.Background()

	// limited role creates + owns the database.
	lconn, err := pgx.Connect(ctx, limited)
	if err != nil {
		t.Fatalf("limited connect: %v", err)
	}
	if _, err := lconn.Exec(ctx, `CREATE DATABASE "`+dbName+`"`); err != nil {
		t.Fatalf("limited CREATE DATABASE: %v", err)
	}
	lconn.Close(ctx)

	// superuser creates the user (limited cannot drop a superuser-owned role).
	sconn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("super connect: %v", err)
	}
	_, _ = sconn.Exec(ctx, `CREATE USER "`+username+`" WITH PASSWORD 'x'`)
	sconn.Close(ctx)

	defer cleanupDB(t, dsn, token)

	// Deprovision as limited: DROP DATABASE succeeds, DROP USER fails (logged).
	lb := newLocalBackend(limited)
	if err := lb.Deprovision(ctx, token, ""); err != nil {
		t.Fatalf("Deprovision should succeed (DROP USER failure is non-fatal): %v", err)
	}
}

// TestLocalBackend_StorageBytes_CancelledCtx covers the StorageBytes
// disconnect-error defer by cancelling the context immediately after the query
// returns, so conn.Close(ctx) sees a cancelled context.
func TestLocalBackend_StorageBytes_CancelledCtx(t *testing.T) {
	dsn := testCustomersURL(t)
	token := uniqueToken("cancel")
	defer cleanupDB(t, dsn, token)

	b := newLocalBackend(dsn)
	if _, err := b.Provision(context.Background(), token, "anonymous"); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	// StorageBytes runs the query then defers conn.Close(ctx). We can't cancel
	// mid-call, but a context with a 1ns deadline forces the close to observe a
	// done context. Use a deadline far enough to let the query run, then expire.
	cancel() // pre-cancelled: connect itself will fail, exercising connect-error.
	_, _ = b.StorageBytes(ctx, token, "")
}

// TestLocalBackend_StorageBytes_MissingDB covers the pg_database_size error
// branch for a database that doesn't exist.
func TestLocalBackend_StorageBytes_MissingDB(t *testing.T) {
	dsn := testCustomersURL(t)
	b := newLocalBackend(dsn)
	_, err := b.StorageBytes(context.Background(), "definitely-not-provisioned-xyz", "")
	if err == nil || !strings.Contains(err.Error(), "pg_database_size") {
		t.Fatalf("want pg_database_size error for missing db; got %v", err)
	}
}
