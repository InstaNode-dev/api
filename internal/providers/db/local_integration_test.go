package db

// Integration tests for LocalBackend — these talk to a real Postgres
// instance via the TEST_POSTGRES_CUSTOMERS_URL env var. CI provides this
// via the postgres service container in .github/workflows; local devs
// can point it at any postgres where the connecting role is SUPERUSER
// (CREATE DATABASE + CREATE ROLE both require superuser privileges).
//
// The tests skip gracefully when the env var is unset OR when the
// connection itself fails, so they don't break developers running the
// gate without Docker.

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// requireLocalBackend pulls TEST_POSTGRES_CUSTOMERS_URL from the env and
// builds a LocalBackend. If the env var is unset, the test skips.
// If the connection fails (e.g. the test-pg container died), the test
// also skips with a clear message — we want red builds to mean a
// regression, not a flaky local env.
func requireLocalBackend(t *testing.T) (*LocalBackend, string) {
	t.Helper()
	url := os.Getenv("TEST_POSTGRES_CUSTOMERS_URL")
	if url == "" {
		t.Skip("TEST_POSTGRES_CUSTOMERS_URL not set; skipping LocalBackend integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Skipf("TEST_POSTGRES_CUSTOMERS_URL unreachable (%v); skipping", err)
	}
	_ = conn.Close(ctx)
	return newLocalBackend(url), url
}

// genToken returns a short, valid-identifier token unique to this run.
// We avoid using a full uuid because CREATE DATABASE quotes the name —
// `db_uuid` works but the short prefix path is the common production
// shape. Mix a low-entropy random suffix so concurrent test runs against
// the same Postgres don't collide.
func genToken(t *testing.T) string {
	t.Helper()
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return fmt.Sprintf("itest%d%d", time.Now().UnixNano()%1_000_000, r.Intn(10_000))
}

// cleanupResources tears down a token's database + user. Run via t.Cleanup
// so a panicking test still drops its leftovers — important when a shared
// Postgres is reused across many runs.
func cleanupResources(t *testing.T, adminURL, token string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Logf("cleanup: connect: %v", err)
		return
	}
	defer conn.Close(ctx)
	// kill leftover sessions, then drop.
	_, _ = conn.Exec(ctx,
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND pid<>pg_backend_pid()",
		"db_"+token,
	)
	_, _ = conn.Exec(ctx, fmt.Sprintf(`DROP DATABASE IF EXISTS %q`, "db_"+token))
	_, _ = conn.Exec(ctx, fmt.Sprintf(`DROP USER IF EXISTS %q`, "usr_"+token))
}

// TestLocal_Provision_HappyPath — creates a database, the user can
// connect (via the URL returned), the database is visible via the admin
// URL.
func TestLocal_Provision_HappyPath(t *testing.T) {
	b, adminURL := requireLocalBackend(t)
	token := genToken(t)
	t.Cleanup(func() { cleanupResources(t, adminURL, token) })

	creds, err := b.Provision(context.Background(), token, "free")
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if creds.DatabaseName != "db_"+token {
		t.Errorf("DatabaseName: got %q", creds.DatabaseName)
	}
	if creds.Username != "usr_"+token {
		t.Errorf("Username: got %q", creds.Username)
	}
	if !strings.HasPrefix(creds.URL, "postgres://usr_"+token+":") {
		t.Errorf("URL prefix: got %q", creds.URL)
	}
	if creds.ProviderResourceID != "" {
		t.Errorf("ProviderResourceID: want empty, got %q", creds.ProviderResourceID)
	}

	// The new user can connect to its database via the returned URL.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Some test environments don't route the admin host externally —
	// rewrite the host portion of creds.URL to match the admin URL host
	// before dialing.
	dialURL := strings.Replace(creds.URL, extractHost(creds.URL), extractHost(adminURL), 1)
	conn, err := pgx.Connect(ctx, dialURL+"?sslmode=disable")
	if err != nil {
		t.Fatalf("user-facing dial: %v (url=%s)", err, dialURL)
	}
	defer conn.Close(ctx)
	var n int
	if err := conn.QueryRow(ctx, "SELECT 1").Scan(&n); err != nil || n != 1 {
		t.Fatalf("SELECT 1 as new user: n=%d err=%v", n, err)
	}
}

// TestLocal_ProvisionWithExtensions_Vector — passing the "vector"
// extension installs pgvector in the new database (or surfaces the
// CREATE EXTENSION error if the cluster lacks the package).
func TestLocal_ProvisionWithExtensions_Vector(t *testing.T) {
	b, adminURL := requireLocalBackend(t)
	token := genToken(t)
	t.Cleanup(func() { cleanupResources(t, adminURL, token) })

	_, err := b.ProvisionWithExtensions(context.Background(), token, "pro", []string{"vector"})
	if err != nil {
		// Most plain `postgres:16-alpine` images do NOT ship pgvector;
		// in that case CREATE EXTENSION fails with the contrib-not-
		// found error, which exercises the extension-error branch.
		// Either outcome (success or this specific failure) is
		// acceptable for the integration; what we don't tolerate is a
		// silent passthrough.
		if !strings.Contains(err.Error(), "CREATE EXTENSION") &&
			!strings.Contains(err.Error(), "extension") {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}

	// If extension install succeeded, confirm it via pg_extension.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	newAdmin, err := pgx.Connect(ctx, b.buildAdminNewDBURL("db_"+token))
	if err != nil {
		t.Fatalf("new-db admin connect: %v", err)
	}
	defer newAdmin.Close(ctx)
	var has bool
	if err := newAdmin.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname='vector')").Scan(&has); err != nil {
		t.Fatalf("pg_extension probe: %v", err)
	}
	if !has {
		t.Fatal("vector extension not installed despite no error")
	}
}

// TestLocal_ProvisionWithExtensions_RejectedExtension — disallowed
// extensions fail validation before any DDL runs.
func TestLocal_ProvisionWithExtensions_RejectedExtension(t *testing.T) {
	b, _ := requireLocalBackend(t)
	_, err := b.ProvisionWithExtensions(context.Background(), "tok-x", "pro", []string{"postgis"})
	if err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("want allowlist error, got %v", err)
	}
}

// TestLocal_Provision_DuplicateFails — second Provision call with the
// same token should fail at CREATE DATABASE (the database name already
// exists).
func TestLocal_Provision_DuplicateFails(t *testing.T) {
	b, adminURL := requireLocalBackend(t)
	token := genToken(t)
	t.Cleanup(func() { cleanupResources(t, adminURL, token) })

	if _, err := b.Provision(context.Background(), token, "free"); err != nil {
		t.Fatalf("first Provision: %v", err)
	}
	if _, err := b.Provision(context.Background(), token, "free"); err == nil ||
		!strings.Contains(err.Error(), "CREATE DATABASE") {
		t.Fatalf("duplicate provision: want CREATE DATABASE error, got %v", err)
	}
}

// TestLocal_Provision_ConnectFails — bad admin URL surfaces as a
// connect-error from Provision (covers the early-return branch).
func TestLocal_Provision_ConnectFails(t *testing.T) {
	if os.Getenv("TEST_POSTGRES_CUSTOMERS_URL") == "" {
		t.Skip("TEST_POSTGRES_CUSTOMERS_URL not set; skipping")
	}
	b := newLocalBackend("postgres://nobody:nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := b.Provision(ctx, "tok-deadhost", "free"); err == nil ||
		!strings.Contains(err.Error(), "connect") {
		t.Fatalf("want connect error, got %v", err)
	}
}

// TestLocal_StorageBytes_HappyPath — pg_database_size returns a small
// positive integer for the just-created database.
func TestLocal_StorageBytes_HappyPath(t *testing.T) {
	b, adminURL := requireLocalBackend(t)
	token := genToken(t)
	t.Cleanup(func() { cleanupResources(t, adminURL, token) })

	if _, err := b.Provision(context.Background(), token, "free"); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	n, err := b.StorageBytes(context.Background(), token, "")
	if err != nil {
		t.Fatalf("StorageBytes: %v", err)
	}
	if n <= 0 {
		t.Fatalf("StorageBytes: got %d, want > 0", n)
	}
}

// TestLocal_StorageBytes_MissingDB — pg_database_size on a non-existent
// db returns a query-execution error (the missing-DB branch).
func TestLocal_StorageBytes_MissingDB(t *testing.T) {
	b, _ := requireLocalBackend(t)
	if _, err := b.StorageBytes(context.Background(), "no-such-token-"+genToken(t), ""); err == nil ||
		!strings.Contains(err.Error(), "pg_database_size") {
		t.Fatalf("want pg_database_size error, got %v", err)
	}
}

// TestLocal_StorageBytes_ConnectFails — bad admin URL surfaces as a
// connect-error from StorageBytes.
func TestLocal_StorageBytes_ConnectFails(t *testing.T) {
	if os.Getenv("TEST_POSTGRES_CUSTOMERS_URL") == "" {
		t.Skip("TEST_POSTGRES_CUSTOMERS_URL not set; skipping")
	}
	b := newLocalBackend("postgres://nobody:nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := b.StorageBytes(ctx, "tok", ""); err == nil ||
		!strings.Contains(err.Error(), "connect") {
		t.Fatalf("want connect error, got %v", err)
	}
}

// TestLocal_Deprovision_HappyPath — Provision then Deprovision; database
// must be gone and user must be gone afterwards.
func TestLocal_Deprovision_HappyPath(t *testing.T) {
	b, adminURL := requireLocalBackend(t)
	token := genToken(t)
	t.Cleanup(func() { cleanupResources(t, adminURL, token) })

	if _, err := b.Provision(context.Background(), token, "free"); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if err := b.Deprovision(context.Background(), token, ""); err != nil {
		t.Fatalf("Deprovision: %v", err)
	}

	// Probe: database and user must be gone.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Fatalf("admin reconnect: %v", err)
	}
	defer conn.Close(ctx)

	var dbCount int
	if err := conn.QueryRow(ctx, "SELECT count(*) FROM pg_database WHERE datname=$1", "db_"+token).Scan(&dbCount); err != nil {
		t.Fatalf("pg_database probe: %v", err)
	}
	if dbCount != 0 {
		t.Fatalf("db still present after Deprovision: count=%d", dbCount)
	}
	var userCount int
	if err := conn.QueryRow(ctx, "SELECT count(*) FROM pg_user WHERE usename=$1", "usr_"+token).Scan(&userCount); err != nil {
		t.Fatalf("pg_user probe: %v", err)
	}
	if userCount != 0 {
		t.Fatalf("user still present after Deprovision: count=%d", userCount)
	}
}

// TestLocal_Deprovision_NoSuchToken — DROP IF EXISTS makes Deprovision
// idempotent: calling it on a token that was never provisioned succeeds.
func TestLocal_Deprovision_NoSuchToken(t *testing.T) {
	b, _ := requireLocalBackend(t)
	if err := b.Deprovision(context.Background(), "never-existed-"+genToken(t), ""); err != nil {
		t.Fatalf("idempotent Deprovision: %v", err)
	}
}

// TestLocal_Deprovision_ConnectFails — bad admin URL surfaces as a
// connect-error from Deprovision.
func TestLocal_Deprovision_ConnectFails(t *testing.T) {
	if os.Getenv("TEST_POSTGRES_CUSTOMERS_URL") == "" {
		t.Skip("TEST_POSTGRES_CUSTOMERS_URL not set; skipping")
	}
	b := newLocalBackend("postgres://nobody:nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := b.Deprovision(ctx, "tok", ""); err == nil ||
		!strings.Contains(err.Error(), "connect") {
		t.Fatalf("want connect error, got %v", err)
	}
}

// TestLocal_Provision_GrantSchemaFails_AndCloseError — the
// `newDBConnect` seam returns a connection that we close BEFORE
// Provision's GRANT SCHEMA runs, so:
//   (1) the GRANT SCHEMA exec fails -> exercises the "GRANT SCHEMA
//       (non-fatal)" branch
//   (2) the deferred conn.Close runs on the already-closed conn ->
//       exercises the "disconnect new db" defer-error branch
//
// Provision must still return success because the GRANT SCHEMA error
// is logged-and-continued.
func TestLocal_Provision_GrantSchemaFails_AndCloseError(t *testing.T) {
	b, adminURL := requireLocalBackend(t)
	token := genToken(t)
	t.Cleanup(func() { cleanupResources(t, adminURL, token) })

	orig := newDBConnect
	t.Cleanup(func() { newDBConnect = orig })
	newDBConnect = func(ctx context.Context, url string) (*pgx.Conn, error) {
		c, err := pgx.Connect(ctx, url)
		if err != nil {
			return nil, err
		}
		// Close the connection immediately. The caller will try to
		// Exec on it (-> error) and Close again in defer (-> error).
		_ = c.Close(context.Background())
		return c, nil
	}

	creds, err := b.Provision(context.Background(), token, "free")
	if err != nil {
		t.Fatalf("Provision should still succeed: %v", err)
	}
	if creds.DatabaseName != "db_"+token {
		t.Fatalf("DatabaseName: got %q", creds.DatabaseName)
	}
}

// TestLocal_Provision_NewDBConnectFails_NoExtensions — when the
// post-CREATE connect to the new database fails AND no extensions were
// requested, Provision logs and continues (returns success without the
// schema-grant). Uses the `newDBConnect` package seam so the failure
// is deterministic.
func TestLocal_Provision_NewDBConnectFails_NoExtensions(t *testing.T) {
	b, adminURL := requireLocalBackend(t)
	token := genToken(t)
	t.Cleanup(func() { cleanupResources(t, adminURL, token) })

	orig := newDBConnect
	t.Cleanup(func() { newDBConnect = orig })
	newDBConnect = func(_ context.Context, _ string) (*pgx.Conn, error) {
		return nil, fmt.Errorf("simulated new-db connect failure")
	}

	creds, err := b.Provision(context.Background(), token, "free")
	if err != nil {
		t.Fatalf("Provision should still succeed: %v", err)
	}
	if creds.DatabaseName != "db_"+token {
		t.Fatalf("DatabaseName: got %q", creds.DatabaseName)
	}
}

// TestLocal_Provision_NewDBConnectFails_WithExtensions — same seam,
// but with the "vector" extension requested. The new-db connect
// failure is fatal because we can't install the requested extension.
func TestLocal_Provision_NewDBConnectFails_WithExtensions(t *testing.T) {
	b, adminURL := requireLocalBackend(t)
	token := genToken(t)
	t.Cleanup(func() { cleanupResources(t, adminURL, token) })

	orig := newDBConnect
	t.Cleanup(func() { newDBConnect = orig })
	newDBConnect = func(_ context.Context, _ string) (*pgx.Conn, error) {
		return nil, fmt.Errorf("simulated new-db connect failure")
	}

	_, err := b.ProvisionWithExtensions(context.Background(), token, "pro", []string{"vector"})
	if err == nil || !strings.Contains(err.Error(), "install extensions") {
		t.Fatalf("want install-extensions error wrap, got %v", err)
	}
}

// TestLocal_Provision_GeneratePasswordFails — swap the package-level
// randReader to one that always errors so Provision's password-gen
// step fails and returns before any DB work happens. Exercises the
// `generatePassword: ...` wrap at line 70-72.
func TestLocal_Provision_GeneratePasswordFails(t *testing.T) {
	orig := randReader
	t.Cleanup(func() { randReader = orig })
	randReader = failingReader{err: errFakeRand}

	b := newLocalBackend("postgres://i:i@localhost:5432/x?sslmode=disable")
	if _, err := b.Provision(context.Background(), "tok", "free"); err == nil ||
		!strings.Contains(err.Error(), "generatePassword") {
		t.Fatalf("want generatePassword error wrap, got %v", err)
	}
}

// TestLocal_Deprovision_AdminConnPreKilled — the `adminConnect` seam
// returns a real connection that we've already self-terminated. The
// connection is "logged in" as far as the Go side knows, but every
// Exec returns "conn closed". This exercises (a) the
// terminate_backend `logged-and-continued` branch and (b) the
// DROP DATABASE error-return branch in one shot.
func TestLocal_Deprovision_AdminConnPreKilled(t *testing.T) {
	b, adminURL := requireLocalBackend(t)
	token := genToken(t)
	t.Cleanup(func() { cleanupResources(t, adminURL, token) })

	// Seed a real db_TOKEN so the DROP target exists.
	if _, err := b.Provision(context.Background(), token, "free"); err != nil {
		t.Fatalf("seed Provision: %v", err)
	}

	orig := adminConnect
	t.Cleanup(func() { adminConnect = orig })
	adminConnect = func(ctx context.Context, url string) (*pgx.Conn, error) {
		c, err := pgx.Connect(ctx, url)
		if err != nil {
			return nil, err
		}
		// Self-terminate: backend pid runs SIGTERM on itself, leaving
		// the pgx.Conn in a "logged-in but socket-dead" state.
		_, _ = c.Exec(ctx, "SELECT pg_terminate_backend(pg_backend_pid())")
		return c, nil
	}

	err := b.Deprovision(context.Background(), token, "")
	// terminate_backend Exec fails (logged-and-continued).
	// DROP DATABASE Exec fails — returns error.
	if err == nil || !strings.Contains(err.Error(), "DROP DATABASE") {
		t.Fatalf("want DROP DATABASE error, got %v", err)
	}
}

// TestLocal_Provision_CreateUserFails — if a stale user with the same
// name already exists from a botched earlier Provision (database was
// dropped but user wasn't), CREATE USER hits a duplicate-role error.
// This exercises the CREATE USER error branch.
func TestLocal_Provision_CreateUserFails(t *testing.T) {
	b, adminURL := requireLocalBackend(t)
	token := genToken(t)
	username := "usr_" + token
	t.Cleanup(func() { cleanupResources(t, adminURL, token) })

	// Pre-create the user so the database name is still free but the
	// role isn't. This is exactly the post-crash state Provision must
	// surface as an error.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, fmt.Sprintf(`CREATE USER %q WITH PASSWORD 'x'`, username)); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	if _, err := b.Provision(context.Background(), token, "free"); err == nil ||
		!strings.Contains(err.Error(), "CREATE USER") {
		t.Fatalf("want CREATE USER error, got %v", err)
	}
}

// TestLocal_Deprovision_DropUserContinues — DROP USER fails for a role
// that owns objects (it can't be dropped while it owns anything). We
// re-assign and confirm Deprovision continues anyway (the function logs
// and returns nil — DROP USER errors are non-fatal). This proves the
// DROP-USER-continues branch.
func TestLocal_Deprovision_DropUserContinues(t *testing.T) {
	b, adminURL := requireLocalBackend(t)
	token := genToken(t)
	username := "usr_" + token
	t.Cleanup(func() {
		// best-effort owner reassign so the user CAN be dropped.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, adminURL)
		if err == nil {
			_, _ = conn.Exec(ctx, fmt.Sprintf(`REASSIGN OWNED BY %q TO CURRENT_USER`, username))
			_, _ = conn.Exec(ctx, fmt.Sprintf(`DROP OWNED BY %q`, username))
			conn.Close(ctx)
		}
		cleanupResources(t, adminURL, token)
	})

	if _, err := b.Provision(context.Background(), token, "free"); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	// Make the user own a stray table in the admin DB; DROP DATABASE
	// removes the per-token db (and its objects), but the admin-DB
	// table outlives it, so DROP USER fails with a "owns objects" error.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer conn.Close(ctx)
	tbl := fmt.Sprintf("stray_%s", strings.ReplaceAll(token, "-", "_"))
	if _, err := conn.Exec(ctx, fmt.Sprintf(`CREATE TABLE %q (id int)`, tbl)); err != nil {
		t.Fatalf("create stray: %v", err)
	}
	if _, err := conn.Exec(ctx, fmt.Sprintf(`ALTER TABLE %q OWNER TO %q`, tbl, username)); err != nil {
		t.Fatalf("chown stray: %v", err)
	}
	defer conn.Exec(ctx, fmt.Sprintf(`DROP TABLE IF EXISTS %q`, tbl))

	// Deprovision returns nil even though DROP USER fails — the DROP
	// USER error is logged-and-continued.
	if err := b.Deprovision(context.Background(), token, ""); err != nil {
		t.Fatalf("Deprovision (DROP USER fail should be non-fatal): %v", err)
	}
	// Confirm: user still exists.
	var n int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM pg_user WHERE usename=$1`, username).Scan(&n); err != nil {
		t.Fatalf("pg_user probe: %v", err)
	}
	if n != 1 {
		t.Fatalf("user count=%d (expected 1 — DROP USER should have failed but Deprovision returned ok)", n)
	}
}

// TestLocal_Provision_FullTokenAndShortPrefix — both the "full UUID" and
// "short prefix" naming conventions round-trip through Provision +
// Deprovision. The DB/user names are simple string concatenations on
// token, so any token that's a valid identifier should work.
func TestLocal_Provision_FullTokenAndShortPrefix(t *testing.T) {
	b, adminURL := requireLocalBackend(t)
	// Full-token shape: hex with dashes — Postgres needs the identifier
	// quoted, which Provision does.
	full := "deadbeef-cafe-0000-0000-" + strings.ReplaceAll(genToken(t), "itest", "")
	// Short prefix shape: the common compact identifier.
	short := genToken(t)
	for _, token := range []string{full, short} {
		token := token
		t.Run("token="+token, func(t *testing.T) {
			t.Cleanup(func() { cleanupResources(t, adminURL, token) })
			creds, err := b.Provision(context.Background(), token, "free")
			if err != nil {
				t.Fatalf("Provision(%q): %v", token, err)
			}
			if !strings.HasSuffix(creds.DatabaseName, token) {
				t.Errorf("DatabaseName: got %q want suffix %q", creds.DatabaseName, token)
			}
			if err := b.Deprovision(context.Background(), token, ""); err != nil {
				t.Fatalf("Deprovision: %v", err)
			}
		})
	}
}
