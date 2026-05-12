package models_test

// resource_family_test.go — slice 2 of env-aware deployments.
//
// Covers:
//  - Migration 018: parent_resource_id + partial indexes apply cleanly +
//    re-applying is a no-op
//  - GetResourceFamily: root + multiple env siblings round-trip
//  - GetResourceFamily walking from a child returns root + siblings
//  - Orphan (no parent, no children) returns single-member family
//  - Cross-type linking refused (ValidateFamilyParent → cross_type)
//  - Cross-team linking refused (ValidateFamilyParent → cross_team)
//  - Duplicate twin refused (ValidateFamilyParent → duplicate_twin)
//  - Schema unique index actually rejects an end-run that bypasses the
//    handler validation (defence-in-depth)
//  - ListResourceFamiliesByTeam buckets correctly into per-env maps

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// requireFamilyDB skips the test if no real Postgres is reachable. Local copy
// of the pattern in resource_env_test.go so this file is self-contained.
func requireFamilyDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
}

// TestResourceFamily_MigrationIdempotent verifies the 018 statements can be
// applied twice without error and that the partial unique index actually
// blocks duplicate-twin inserts that bypass the handler validation.
func TestResourceFamily_MigrationIdempotent(t *testing.T) {
	requireFamilyDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	stmts := []string{
		`ALTER TABLE resources ADD COLUMN IF NOT EXISTS parent_resource_id UUID REFERENCES resources(id) ON DELETE SET NULL`,
		`CREATE INDEX IF NOT EXISTS idx_resources_family ON resources (parent_resource_id) WHERE parent_resource_id IS NOT NULL`,
		`CREATE UNIQUE INDEX IF NOT EXISTS uq_resources_family_env ON resources (parent_resource_id, env) WHERE parent_resource_id IS NOT NULL`,
	}
	for i := 0; i < 2; i++ {
		for _, s := range stmts {
			_, err := db.Exec(s)
			require.NoError(t, err, "iteration %d: %s", i, s)
		}
	}

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	root := mustCreateResource(t, db, teamID, models.ResourceTypePostgres, "production", nil)
	staging := mustCreateResource(t, db, teamID, models.ResourceTypePostgres, "staging", &root.ID)
	defer db.Exec(`DELETE FROM resources WHERE id IN ($1, $2)`, root.ID, staging.ID)

	// Bypass handler validation — go straight to SQL. The partial unique
	// index must reject the duplicate (parent_resource_id, env) tuple.
	var dummyID uuid.UUID
	err := db.QueryRow(`
		INSERT INTO resources (team_id, resource_type, tier, env, parent_resource_id)
		VALUES ($1, 'postgres', 'pro', 'staging', $2)
		RETURNING id
	`, teamID, root.ID).Scan(&dummyID)
	require.Error(t, err, "uq_resources_family_env must reject duplicate (parent, env) row")
	assert.True(t,
		strings.Contains(err.Error(), "uq_resources_family_env") ||
			strings.Contains(err.Error(), "duplicate key"),
		"unique violation error must mention the index or duplicate key: got %v", err)
}

// TestResourceFamily_ThreeMembers_RoundTrip walks from the root and from a
// child; both lookups must return the same 3-member family with the root
// first.
func TestResourceFamily_ThreeMembers_RoundTrip(t *testing.T) {
	requireFamilyDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	root := mustCreateResource(t, db, teamID, models.ResourceTypePostgres, "production", nil)
	staging := mustCreateResource(t, db, teamID, models.ResourceTypePostgres, "staging", &root.ID)
	dev := mustCreateResource(t, db, teamID, models.ResourceTypePostgres, "dev", &root.ID)
	defer db.Exec(`DELETE FROM resources WHERE team_id = $1`, teamID)

	// From the root.
	got, err := models.GetResourceFamily(context.Background(), db, root.ID)
	require.NoError(t, err)
	require.Len(t, got, 3, "family must include root + 2 children")
	assert.Equal(t, root.ID, got[0].ID, "root must be first")
	envs := []string{got[0].Env, got[1].Env, got[2].Env}
	assert.ElementsMatch(t, []string{"production", "staging", "dev"}, envs)

	// From a child (staging) — same family, same shape.
	gotFromChild, err := models.GetResourceFamily(context.Background(), db, staging.ID)
	require.NoError(t, err)
	require.Len(t, gotFromChild, 3, "walking from a child must still resolve the full family")
	assert.Equal(t, root.ID, gotFromChild[0].ID, "walk-from-child must still order root first")

	// From the other child (dev) — same root resolution.
	gotFromDev, err := models.GetResourceFamily(context.Background(), db, dev.ID)
	require.NoError(t, err)
	require.Len(t, gotFromDev, 3)
	assert.Equal(t, root.ID, gotFromDev[0].ID)
}

// TestResourceFamily_Orphan_SingleMember covers a resource that has no parent
// and no children — common case for every legacy row before slice 2 shipped.
func TestResourceFamily_Orphan_SingleMember(t *testing.T) {
	requireFamilyDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	r := mustCreateResource(t, db, teamID, models.ResourceTypeRedis, "production", nil)
	defer db.Exec(`DELETE FROM resources WHERE id = $1`, r.ID)

	got, err := models.GetResourceFamily(context.Background(), db, r.ID)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, r.ID, got[0].ID)
	assert.Nil(t, got[0].ParentResourceID, "orphan must have parent_resource_id = NULL")
}

// TestValidateFamilyParent_CrossType refuses linking when the parent is a
// different resource_type.
func TestValidateFamilyParent_CrossType(t *testing.T) {
	requireFamilyDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	pgParent := mustCreateResource(t, db, teamID, models.ResourceTypePostgres, "production", nil)
	defer db.Exec(`DELETE FROM resources WHERE id = $1`, pgParent.ID)

	// Caller wants to provision a REDIS child off a POSTGRES parent → rejected.
	_, err := models.ValidateFamilyParent(context.Background(), db,
		pgParent.ID, teamID, models.ResourceTypeRedis, "staging")
	require.Error(t, err)
	var linkErr *models.FamilyLinkError
	require.True(t, errors.As(err, &linkErr), "must be FamilyLinkError, got %T (%v)", err, err)
	assert.Equal(t, "cross_type", linkErr.Reason)
}

// TestValidateFamilyParent_CrossTeam refuses linking when the parent is owned
// by another team.
func TestValidateFamilyParent_CrossTeam(t *testing.T) {
	requireFamilyDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamA := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	teamB := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	defer db.Exec(`DELETE FROM teams WHERE id IN ($1,$2)`, teamA, teamB)

	parent := mustCreateResource(t, db, teamA, models.ResourceTypePostgres, "production", nil)
	defer db.Exec(`DELETE FROM resources WHERE id = $1`, parent.ID)

	// Team B tries to link a new postgres off team A's row → rejected.
	_, err := models.ValidateFamilyParent(context.Background(), db,
		parent.ID, teamB, models.ResourceTypePostgres, "staging")
	require.Error(t, err)
	var linkErr *models.FamilyLinkError
	require.True(t, errors.As(err, &linkErr))
	assert.Equal(t, "cross_team", linkErr.Reason)
}

// TestValidateFamilyParent_DuplicateTwin refuses a second twin in the same env.
func TestValidateFamilyParent_DuplicateTwin(t *testing.T) {
	requireFamilyDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	root := mustCreateResource(t, db, teamID, models.ResourceTypePostgres, "production", nil)
	staging := mustCreateResource(t, db, teamID, models.ResourceTypePostgres, "staging", &root.ID)
	defer db.Exec(`DELETE FROM resources WHERE id IN ($1,$2)`, root.ID, staging.ID)

	// Try to create ANOTHER staging twin in the same family → rejected before
	// the schema unique index gets a chance to fire.
	_, err := models.ValidateFamilyParent(context.Background(), db,
		root.ID, teamID, models.ResourceTypePostgres, "staging")
	require.Error(t, err)
	var linkErr *models.FamilyLinkError
	require.True(t, errors.As(err, &linkErr))
	assert.Equal(t, "duplicate_twin", linkErr.Reason)
}

// TestValidateFamilyParent_ResolvesToRoot validates that linking off a CHILD
// returns the root id — keeps the family chain depth ≤1.
func TestValidateFamilyParent_ResolvesToRoot(t *testing.T) {
	requireFamilyDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	root := mustCreateResource(t, db, teamID, models.ResourceTypePostgres, "production", nil)
	staging := mustCreateResource(t, db, teamID, models.ResourceTypePostgres, "staging", &root.ID)
	defer db.Exec(`DELETE FROM resources WHERE id IN ($1,$2)`, root.ID, staging.ID)

	// Linking off the staging child for a new "dev" env must resolve to
	// the root.ID (not staging.ID).
	got, err := models.ValidateFamilyParent(context.Background(), db,
		staging.ID, teamID, models.ResourceTypePostgres, "dev")
	require.NoError(t, err)
	assert.Equal(t, root.ID, got, "ValidateFamilyParent must return the family root, not the parent passed in")
}

// TestListResourceFamiliesByTeam groups multiple families correctly.
func TestListResourceFamiliesByTeam(t *testing.T) {
	requireFamilyDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	// Family A: postgres production + staging
	pgRoot := mustCreateResource(t, db, teamID, models.ResourceTypePostgres, "production", nil)
	pgStaging := mustCreateResource(t, db, teamID, models.ResourceTypePostgres, "staging", &pgRoot.ID)

	// Family B: redis production only (orphan / single-member family)
	redisOnly := mustCreateResource(t, db, teamID, models.ResourceTypeRedis, "production", nil)
	defer db.Exec(`DELETE FROM resources WHERE id IN ($1,$2,$3)`, pgRoot.ID, pgStaging.ID, redisOnly.ID)

	got, err := models.ListResourceFamiliesByTeam(context.Background(), db, teamID)
	require.NoError(t, err)
	require.Len(t, got, 2, "should see two family roots: pg + redis")

	byRoot := map[uuid.UUID]models.FamilySummary{}
	for _, s := range got {
		byRoot[s.FamilyRootID] = s
	}

	pgFamily, ok := byRoot[pgRoot.ID]
	require.True(t, ok, "postgres family root missing from response")
	assert.Equal(t, models.ResourceTypePostgres, pgFamily.ResourceType)
	require.Len(t, pgFamily.MembersByEnv, 2)
	prodMember, hasProd := pgFamily.MembersByEnv["production"]
	require.True(t, hasProd, "production env missing in pg family")
	assert.Equal(t, pgRoot.ID, prodMember.ID)
	assert.True(t, prodMember.IsRoot)
	stagingMember, hasStaging := pgFamily.MembersByEnv["staging"]
	require.True(t, hasStaging)
	assert.Equal(t, pgStaging.ID, stagingMember.ID)
	assert.False(t, stagingMember.IsRoot)

	redisFamily, ok := byRoot[redisOnly.ID]
	require.True(t, ok, "redis family root missing from response")
	assert.Equal(t, models.ResourceTypeRedis, redisFamily.ResourceType)
	require.Len(t, redisFamily.MembersByEnv, 1)
}

// mustCreateResource is a thin wrapper around models.CreateResource that
// fails the test on error. Uses the public CreateResourceParams so this is
// the same code path the handlers exercise — guarantees the columns and
// the ParentResourceID round-trip work identically here and in production.
func mustCreateResource(
	t *testing.T, db *sql.DB,
	teamID uuid.UUID, resourceType, env string, parentID *uuid.UUID,
) *models.Resource {
	t.Helper()
	r, err := models.CreateResource(context.Background(), db, models.CreateResourceParams{
		TeamID:           &teamID,
		ResourceType:     resourceType,
		Tier:             "pro",
		Env:              env,
		ParentResourceID: parentID,
	})
	require.NoError(t, err, "mustCreateResource(team=%s, type=%s, env=%s)", teamID, resourceType, env)
	return r
}
