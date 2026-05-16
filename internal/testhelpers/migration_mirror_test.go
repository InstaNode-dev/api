package testhelpers

// Anti-drift guard for the hand-maintained schema mirror in runMigrations.
//
// WHY THIS EXISTS
// ---------------
// runMigrations() hand-mirrors the production schema as a list of DDL
// statements. It does NOT apply the real internal/db/migrations/*.sql files.
// That keeps test setup fast and lets the test schema deliberately diverge
// from prod in a few documented spots — but it has one sharp failure mode:
// when a new migration adds a table, someone must ALSO add it to the mirror.
//
// When they forget, `make test-db-up` still passes locally (it applies the
// real .sql files), so the gap is invisible — until CI's deploy.yml, which
// runs against a BARE Postgres with only the mirror, fails on
// `relation "<table>" does not exist`. That is exactly how email_events (025),
// pending_deletions (044) and deployment_events (050) silently broke the api
// auto-deploy gate.
//
// This test closes the loop: it enumerates every CREATE TABLE in the real
// migration files and asserts each table exists after SetupTestDB. A new
// unmirrored migration now fails HERE — in the same PR that adds it — instead
// of weeks later in CI. Per CLAUDE.md rule 18, it iterates the real registry
// (the migration files) rather than a hand-typed table list.

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"testing"
)

// migrationTablesNotMirrored lists tables created by migrations that are
// intentionally absent from the runMigrations mirror, each with a reason.
// Keep this list SHORT and justified — it is an escape hatch, not a dumping
// ground. A table belongs here only if it genuinely cannot or should not be
// part of the fast test schema.
var migrationTablesNotMirrored = map[string]string{
	// schema_migrations is the migration-runner's own bookkeeping table.
	// runMigrations does not run the migration runner, so there is no such
	// table — and no test needs it.
	"schema_migrations": "migration-runner bookkeeping; not a domain table",
}

var createTableRe = regexp.MustCompile(
	`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z_][a-zA-Z0-9_]*)`)

// migrationsDir resolves internal/db/migrations relative to this source file,
// so the test is independent of the `go test` working directory.
func migrationsDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed; cannot locate migrations dir")
	}
	// thisFile = .../api/internal/testhelpers/migration_mirror_test.go
	dir := filepath.Join(filepath.Dir(thisFile), "..", "db", "migrations")
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("migrations dir not found at %s: %v", dir, err)
	}
	return dir
}

// migrationTables returns every table name created by a migration file,
// mapped to the file that creates it.
func migrationTables(t *testing.T) map[string]string {
	t.Helper()
	dir := migrationsDir(t)
	files, err := filepath.Glob(filepath.Join(dir, "*.sql"))
	if err != nil {
		t.Fatalf("glob migrations: %v", err)
	}
	if len(files) == 0 {
		t.Fatalf("no migration files found in %s", dir)
	}
	sort.Strings(files)
	tables := map[string]string{}
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, m := range createTableRe.FindAllStringSubmatch(string(body), -1) {
			name := m[1]
			if _, seen := tables[name]; !seen {
				tables[name] = filepath.Base(f)
			}
		}
	}
	return tables
}

// TestRunMigrationsMirrorsEveryMigrationTable fails the moment a migration
// adds a table that runMigrations does not mirror. The fix when it fails is
// NEVER to add the table to migrationTablesNotMirrored without a real reason —
// it is to mirror the table's DDL into runMigrations.
func TestRunMigrationsMirrorsEveryMigrationTable(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	tables := migrationTables(t)
	if len(tables) == 0 {
		t.Fatal("no CREATE TABLE statements parsed from migrations")
	}

	var missing []string
	for name, srcFile := range tables {
		if reason, skip := migrationTablesNotMirrored[name]; skip {
			t.Logf("skipping %-22s (%s) — %s", name, srcFile, reason)
			continue
		}
		var reg *string
		// to_regclass returns NULL when the relation does not exist.
		if err := db.QueryRow(`SELECT to_regclass($1)::text`, "public."+name).Scan(&reg); err != nil {
			t.Fatalf("to_regclass(%s): %v", name, err)
		}
		if reg == nil {
			missing = append(missing, name+" (from "+srcFile+")")
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("runMigrations is missing %d migration table(s) — CI's bare-Postgres "+
			"deploy gate will fail on these:\n  %s\n\n"+
			"FIX: mirror each table's DDL into runMigrations() in testhelpers.go. "+
			"Do NOT add it to migrationTablesNotMirrored unless it genuinely is not a "+
			"domain table.", len(missing), join(missing, "\n  "))
	}
}

func join(ss []string, sep string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += sep
		}
		out += s
	}
	return out
}
