package models_test

// stack_test.go — unit tests for the stack_services.image_ref column added
// in migration 017_stack_image_ref.sql. Covers the round-trip the /promote
// endpoint relies on:
//
//   1. CreateStackService with an empty ImageRef stores NULL (the standard
//      /stacks/new path; the build pipeline back-fills via Update).
//   2. CreateStackService with a non-empty ImageRef stores the value (the
//      /promote copy path: target row is pre-stamped with the source's
//      cached image so the deploy goroutine can skip the build entirely).
//   3. UpdateStackServiceImageRef back-fills the column and a subsequent
//      GetStackServicesByStack returns the value verbatim.
//   4. NULL persistence: services created without an image_ref read back
//      ImageRef=="" so callers can branch cleanly.
//
// These tests skip when TEST_DATABASE_URL is not set so CI without a DB
// sidecar (or local devs running `go test ./...` standalone) doesn't fail.

import (
	"context"
	"database/sql"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

func requireDBStack(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
}

// ensureStackTablesModels is the models-package mirror of the handler-side
// ensureStackTables helper. We can't import the handlers package from models
// (cycle), so the SQL is duplicated. Kept idempotent so back-to-back test
// runs against the same DB work.
func ensureStackTablesModels(t *testing.T, db *sql.DB) {
	t.Helper()
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS stacks (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			team_id         UUID REFERENCES teams(id) ON DELETE CASCADE,
			name            TEXT,
			slug            TEXT UNIQUE NOT NULL,
			namespace       TEXT UNIQUE NOT NULL,
			status          TEXT NOT NULL DEFAULT 'building',
			tier            TEXT NOT NULL DEFAULT 'hobby',
			env             TEXT NOT NULL DEFAULT 'production',
			parent_stack_id UUID,
			expires_at      TIMESTAMPTZ,
			fingerprint     TEXT,
			created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`ALTER TABLE stacks ADD COLUMN IF NOT EXISTS env TEXT NOT NULL DEFAULT 'production'`,
		`ALTER TABLE stacks ADD COLUMN IF NOT EXISTS parent_stack_id UUID`,
		`CREATE TABLE IF NOT EXISTS stack_services (
			id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			stack_id    UUID NOT NULL REFERENCES stacks(id) ON DELETE CASCADE,
			name        TEXT NOT NULL,
			image_tag   TEXT,
			image_ref   TEXT,
			status      TEXT NOT NULL DEFAULT 'building',
			expose      BOOLEAN NOT NULL DEFAULT FALSE,
			port        INT NOT NULL DEFAULT 8080,
			app_url     TEXT,
			error_msg   TEXT,
			created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE(stack_id, name)
		)`,
		`ALTER TABLE stack_services ADD COLUMN IF NOT EXISTS image_ref TEXT`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("ensureStackTablesModels: %v\n  SQL: %.120s", err, s)
		}
	}
}

// seedStack inserts a parent stack row owned by the test team and returns
// its id. The fresh slug + namespace per call avoids UNIQUE collisions when
// the same test DB hosts multiple parallel test runs.
func seedStack(t *testing.T, db *sql.DB, teamID string) uuid.UUID {
	t.Helper()
	slug := "stk-model-" + uuid.NewString()[:8]
	var id uuid.UUID
	err := db.QueryRowContext(context.Background(), `
		INSERT INTO stacks (team_id, name, slug, namespace, status, tier, env)
		VALUES ($1::uuid, 'modeltest', $2, $3, 'building', 'pro', 'staging')
		RETURNING id
	`, teamID, slug, "instant-stack-"+slug).Scan(&id)
	require.NoError(t, err)
	return id
}

// TestCreateStackService_EmptyImageRef_StoresNull is the /stacks/new path
// round-trip: the standard creator doesn't know the image_ref yet, so it
// must store NULL and a read-back must return "".
func TestCreateStackService_EmptyImageRef_StoresNull(t *testing.T) {
	requireDBStack(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTablesModels(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	stackID := seedStack(t, db, teamID)

	ss, err := models.CreateStackService(context.Background(), db, models.CreateStackServiceParams{
		StackID: stackID,
		Name:    "api",
		Expose:  true,
		Port:    8080,
		// ImageRef intentionally empty
	})
	require.NoError(t, err)
	assert.Equal(t, "", ss.ImageRef, "freshly-created services have no image_ref")

	// Verify the column is actually NULL (not the empty string) so the
	// partial index stays lean and pre-017 rows look identical on read.
	var refNull sql.NullString
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT image_ref FROM stack_services WHERE id = $1`, ss.ID,
	).Scan(&refNull))
	assert.False(t, refNull.Valid, "empty ImageRef must persist as SQL NULL")
}

// TestCreateStackService_WithImageRef_StoresValue is the /promote copy path:
// CreateStackServiceParams.ImageRef is set so the target row is created
// pre-stamped with the source's cached image — the deploy goroutine then
// hands it to the provider with SkipBuild=true.
func TestCreateStackService_WithImageRef_StoresValue(t *testing.T) {
	requireDBStack(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTablesModels(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	stackID := seedStack(t, db, teamID)

	ref := "registry.local/instant-stack-modeltest-api:sha-abc123"
	ss, err := models.CreateStackService(context.Background(), db, models.CreateStackServiceParams{
		StackID:  stackID,
		Name:     "api",
		Expose:   true,
		Port:     8080,
		ImageRef: ref,
	})
	require.NoError(t, err)
	assert.Equal(t, ref, ss.ImageRef, "ImageRef passed to Create must round-trip on the returned row")

	// And the SELECT-by-stack path returns the same value.
	got, err := models.GetStackServicesByStack(context.Background(), db, stackID)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, ref, got[0].ImageRef)
}

// TestUpdateStackServiceImageRef_BackfillsColumn is the build-pipeline
// round-trip: a service starts with no image_ref and gets one written after
// kaniko completes. Re-reads return the new value.
func TestUpdateStackServiceImageRef_BackfillsColumn(t *testing.T) {
	requireDBStack(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTablesModels(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	stackID := seedStack(t, db, teamID)

	ss, err := models.CreateStackService(context.Background(), db, models.CreateStackServiceParams{
		StackID: stackID,
		Name:    "worker",
		Expose:  false,
		Port:    8080,
	})
	require.NoError(t, err)
	require.Equal(t, "", ss.ImageRef)

	ref := "registry.local/instant-stack-modeltest-worker:sha-def456"
	require.NoError(t, models.UpdateStackServiceImageRef(context.Background(), db, ss.ID, ref))

	got, err := models.GetStackServicesByStack(context.Background(), db, stackID)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, ref, got[0].ImageRef,
		"UpdateStackServiceImageRef must back-fill the column for subsequent reads")
}

// TestMergeStackEnvVars_ConcurrentPatchesNoLostUpdate is the bug-bash #10
// regression: PATCH /stacks/:slug/env used to load-merge-save non-atomically
// (GetStackEnvVars → merge-in-Go → UpdateStackEnvVars), so two concurrent
// PATCHes with disjoint keys both read the same snapshot and the second
// blind-overwrote the first — silently dropping a key. MergeStackEnvVars does
// the whole merge inside ONE row-locked transaction (SELECT ... FOR UPDATE), so
// the two PATCHes serialize and BOTH keys must survive.
//
// We fire N concurrent disjoint-key merges against a real seeded row and assert
// every key is present afterwards. With the old non-atomic path this fails
// (lost updates); with the row lock it passes deterministically.
func TestMergeStackEnvVars_ConcurrentPatchesNoLostUpdate(t *testing.T) {
	requireDBStack(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTablesModels(t, db)
	// env_vars (migration 062) is not in ensureStackTablesModels' base DDL.
	_, err := db.Exec(`ALTER TABLE stacks ADD COLUMN IF NOT EXISTS env_vars JSONB NOT NULL DEFAULT '{}'::jsonb`)
	require.NoError(t, err)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	stackID := seedStack(t, db, teamID)

	// 16 goroutines, each upserting a unique key. Under a lost-update race some
	// of these writes would be clobbered; under the row lock all 16 survive.
	const n = 16
	keys := make([]string, n)
	for i := range keys {
		keys[i] = "KEY_" + uuid.NewString()[:8]
	}

	var wg sync.WaitGroup
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // release all at once to maximize contention
			_, _, e := models.MergeStackEnvVars(context.Background(), db, stackID,
				map[string]string{keys[i]: "v"})
			errs[i] = e
		}(i)
	}
	close(start)
	wg.Wait()

	for i, e := range errs {
		require.NoErrorf(t, e, "merge %d (%s) errored", i, keys[i])
	}

	final, err := models.GetStackEnvVars(context.Background(), db, stackID)
	require.NoError(t, err)
	for _, k := range keys {
		assert.Equalf(t, "v", final[k],
			"key %s was lost — concurrent PATCH dropped it (lost-update regression)", k)
	}
	assert.Len(t, final, n, "all %d concurrent disjoint keys must survive", n)
}
