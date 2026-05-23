package handlers_test

// resolve_family_parent_provarms_test.go — drives every branch of
// resolveFamilyParent (provision_helper.go) through the authenticated
// /db/new path using the bufconn gRPC fixture (so the provision actually
// succeeds on the success branch). Covers:
//   - invalid UUID                → 400 invalid_parent_resource_id
//   - cross-team parent           → 403 forbidden_parent_resource
//   - cross-type parent           → 400 type_mismatch
//   - duplicate twin in env       → 409 twin_exists
//   - deleted / missing parent    → 404 parent_not_found
//   - valid parent                → 201 (family link applied)

import (
	"context"
	"database/sql"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// seedResourceFull inserts a resource with explicit env + parent so the
// duplicate-twin path (an existing child in target env) can be set up.
func seedResourceFull(t *testing.T, db *sql.DB, teamID, resourceType, tier, env string, parentRootID *string) (id, token string) {
	t.Helper()
	if parentRootID == nil {
		require.NoError(t, db.QueryRowContext(context.Background(), `
			INSERT INTO resources (team_id, resource_type, tier, env, status)
			VALUES ($1::uuid, $2, $3, $4, 'active')
			RETURNING id::text, token::text
		`, teamID, resourceType, tier, env).Scan(&id, &token))
	} else {
		require.NoError(t, db.QueryRowContext(context.Background(), `
			INSERT INTO resources (team_id, resource_type, tier, env, status, parent_resource_id)
			VALUES ($1::uuid, $2, $3, $4, 'active', $5::uuid)
			RETURNING id::text, token::text
		`, teamID, resourceType, tier, env, *parentRootID).Scan(&id, &token))
	}
	return id, token
}

func TestResolveFamilyParent_InvalidUUID_Returns400(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)

	resp, body := doProvision(t, fx, "/db/new", "10.130.0.1", jwt,
		map[string]any{"name": "fp-baduuid", "parent_resource_id": "not-a-uuid"})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_parent_resource_id", body.Error)
}

func TestResolveFamilyParent_CrossTeam_Returns403(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	myTeam := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	otherTeam := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, myTeam)
	// Parent belongs to a DIFFERENT team.
	parentID, _ := seedResourceFull(t, fx.db, otherTeam, "postgres", "pro", "production", nil)

	resp, body := doProvision(t, fx, "/db/new", "10.131.0.1", jwt,
		map[string]any{"name": "fp-crossteam", "env": "staging", "parent_resource_id": parentID})
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, "forbidden_parent_resource", body.Error)
}

func TestResolveFamilyParent_CrossType_Returns400(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)
	// Parent is a redis resource; we POST /db/new (postgres) → cross_type.
	parentID, _ := seedResourceFull(t, fx.db, teamID, "redis", "pro", "production", nil)

	resp, body := doProvision(t, fx, "/db/new", "10.132.0.1", jwt,
		map[string]any{"name": "fp-crosstype", "env": "staging", "parent_resource_id": parentID})
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "type_mismatch", body.Error)
}

func TestResolveFamilyParent_DuplicateTwin_Returns409(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)
	// Root parent in production; an existing twin already in staging.
	parentID, _ := seedResourceFull(t, fx.db, teamID, "postgres", "pro", "production", nil)
	_, _ = seedResourceFull(t, fx.db, teamID, "postgres", "pro", "staging", &parentID)

	resp, body := doProvision(t, fx, "/db/new", "10.133.0.1", jwt,
		map[string]any{"name": "fp-dup", "env": "staging", "parent_resource_id": parentID})
	defer resp.Body.Close()
	require.Equal(t, http.StatusConflict, resp.StatusCode)
	assert.Equal(t, "twin_exists", body.Error)
}

func TestResolveFamilyParent_MissingParent_Returns404(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)

	resp, body := doProvision(t, fx, "/db/new", "10.134.0.1", jwt,
		map[string]any{"name": "fp-missing", "env": "staging", "parent_resource_id": uuid.NewString()})
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Equal(t, "parent_not_found", body.Error)
}

func TestResolveFamilyParent_ValidParent_Returns201(t *testing.T) {
	fake := &fakeProvisioner{}
	fx := setupGRPCProvFixture(t, fake, false)
	teamID := testhelpers.MustCreateTeamDB(t, fx.db, "pro")
	jwt := authSessionJWT(t, fx.db, teamID)
	parentID, _ := seedResourceFull(t, fx.db, teamID, "postgres", "pro", "production", nil)

	resp, body := doProvision(t, fx, "/db/new", "10.135.0.1", jwt,
		map[string]any{"name": "fp-valid", "env": "staging", "parent_resource_id": parentID})
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.True(t, body.OK)
	assert.Equal(t, "staging", body.Env)
}
