package models_test

// resource_env_test.go — env-column unit tests for the Resource model.
//
// The integration cases (TestResourceEnv_*) require a real Postgres; they
// skip when TEST_DATABASE_URL is unset. The pure-unit cases
// (TestNormalizeEnv_*) run anywhere.

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

func TestNormalizeEnv_DefaultsToDevelopment(t *testing.T) {
	// Migration 026 (2026-05-13) flipped the empty-input default from
	// "production" → "development" so accidental no-env provisions land in
	// the lowest-stakes bucket. This regression guards that flip.
	got, ok := models.NormalizeEnv("")
	assert.True(t, ok)
	assert.Equal(t, models.EnvDevelopment, got, "empty env must normalise to EnvDevelopment, not EnvProduction")
	assert.Equal(t, "development", got)
	assert.Equal(t, models.EnvDefault, got, "EnvDefault must alias EnvDevelopment")
}

func TestNormalizeEnv_AcceptsValidValues(t *testing.T) {
	cases := []string{
		"production",
		"staging",
		"dev",
		"preview-42",
		"a",
		strings.Repeat("a", 32),
		"my-feature-branch",
		"qa1",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			got, ok := models.NormalizeEnv(in)
			assert.True(t, ok, "expected %q to be valid", in)
			assert.Equal(t, in, got)
		})
	}
}

func TestNormalizeEnv_RejectsInvalidValues(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"contains space", "prod ction"},
		{"contains uppercase", "Production"},
		{"contains exclamation", "prod!"},
		{"contains underscore", "my_env"},
		{"too long", strings.Repeat("a", 33)},
		{"unicode", "stagé"},
		{"slash", "dev/01"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := models.NormalizeEnv(tc.input)
			assert.False(t, ok, "expected %q to be rejected", tc.input)
		})
	}
}

// requireDB skips the test when TEST_DATABASE_URL isn't reachable.
// We can't just call testhelpers.SetupTestDB because it t.Fatalf's on connect
// errors, which we don't want for env-tests that should remain green on a
// laptop without postgres running.
func requireDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
}

func TestResourceEnv_CreateDefaultsToDevelopment(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	r, err := models.CreateResource(context.Background(), db, models.CreateResourceParams{
		TeamID:       &teamID,
		ResourceType: "redis",
		Tier:         "hobby",
		// Env intentionally empty — must default to "development"
		// post-migration-026 (was "production" before).
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM resources WHERE id = $1`, r.ID)

	assert.Equal(t, models.EnvDevelopment, r.Env,
		"empty Env on CreateResource must default to 'development' (migration 026)")
	assert.Equal(t, "development", r.Env)
}

func TestResourceEnv_CreateRoundTrips(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	for _, env := range []string{"dev", "staging", "production", "preview-42"} {
		t.Run(env, func(t *testing.T) {
			r, err := models.CreateResource(context.Background(), db, models.CreateResourceParams{
				TeamID:       &teamID,
				ResourceType: "redis",
				Tier:         "hobby",
				Env:          env,
			})
			require.NoError(t, err)
			defer db.Exec(`DELETE FROM resources WHERE id = $1`, r.ID)
			assert.Equal(t, env, r.Env)

			// GetResourceByToken must return the same env.
			got, err := models.GetResourceByToken(context.Background(), db, r.Token)
			require.NoError(t, err)
			assert.Equal(t, env, got.Env)
		})
	}
}

func TestResourceEnv_ListByTeamAndEnv_Isolates(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	mk := func(env string) *models.Resource {
		r, err := models.CreateResource(context.Background(), db, models.CreateResourceParams{
			TeamID:       &teamID,
			ResourceType: "redis",
			Tier:         "hobby",
			Env:          env,
		})
		require.NoError(t, err)
		return r
	}

	dev := mk("dev")
	staging := mk("staging")
	prod := mk("production")
	development := mk("development")
	defer db.Exec(`DELETE FROM resources WHERE id IN ($1, $2, $3, $4)`,
		dev.ID, staging.ID, prod.ID, development.ID)

	// Listing by env="dev" must only see the dev row.
	devList, err := models.ListResourcesByTeamAndEnv(context.Background(), db, teamID, "dev")
	require.NoError(t, err)
	assert.Len(t, devList, 1)
	assert.Equal(t, dev.ID, devList[0].ID)

	// Empty env defaults to "development" (post-migration 026 — was
	// "production" before). The dashboard's "default env view" now lands
	// callers in the lowest-stakes bucket.
	defaultList, err := models.ListResourcesByTeamAndEnv(context.Background(), db, teamID, "")
	require.NoError(t, err)
	assert.Len(t, defaultList, 1)
	assert.Equal(t, development.ID, defaultList[0].ID)
	assert.Equal(t, "development", defaultList[0].Env)

	// Explicit "production" still works (backward compat).
	prodList, err := models.ListResourcesByTeamAndEnv(context.Background(), db, teamID, "production")
	require.NoError(t, err)
	assert.Len(t, prodList, 1)
	assert.Equal(t, prod.ID, prodList[0].ID)

	// ListResourcesByTeam (no env filter) must see all four.
	all, err := models.ListResourcesByTeam(context.Background(), db, teamID)
	require.NoError(t, err)
	assert.Len(t, all, 4)
}

// TestResourceEnv_MigrationIdempotent verifies that the columns + indexes are
// already present on a SetupTestDB instance and that re-applying the column-add
// + default-flip statements is a no-op (no error, schema unchanged). We mimic
// the migration SQL (009 + 026) directly rather than re-running the embed.FS
// chain to keep this test independent of the migration runner.
func TestResourceEnv_MigrationIdempotent(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	stmts := []string{
		// 009 — column + indexes.
		`ALTER TABLE resources   ADD COLUMN IF NOT EXISTS env TEXT NOT NULL DEFAULT 'production'`,
		`ALTER TABLE deployments ADD COLUMN IF NOT EXISTS env TEXT NOT NULL DEFAULT 'production'`,
		`CREATE INDEX IF NOT EXISTS idx_resources_team_env   ON resources   (team_id, env)`,
		`CREATE INDEX IF NOT EXISTS idx_deployments_team_env ON deployments (team_id, env)`,
		// 026 — flip the column DEFAULT to 'development'.
		`ALTER TABLE resources   ALTER COLUMN env SET DEFAULT 'development'`,
		`ALTER TABLE deployments ALTER COLUMN env SET DEFAULT 'development'`,
	}
	// Run twice; second run must not error.
	for i := 0; i < 2; i++ {
		for _, s := range stmts {
			_, err := db.Exec(s)
			require.NoError(t, err, "iteration %d: %s", i, s)
		}
	}

	// New rows inserted without env get 'development' from the column DEFAULT
	// (post-migration 026, was 'production' before).
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	var rid uuid.UUID
	err := db.QueryRow(`
		INSERT INTO resources (team_id, resource_type, tier)
		VALUES ($1, 'redis', 'hobby')
		RETURNING id
	`, teamID).Scan(&rid)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM resources WHERE id = $1`, rid)

	var env string
	require.NoError(t, db.QueryRow(`SELECT env FROM resources WHERE id = $1`, rid).Scan(&env))
	assert.Equal(t, "development", env,
		"DEFAULT must populate env='development' when caller omits it (migration 026)")
}
