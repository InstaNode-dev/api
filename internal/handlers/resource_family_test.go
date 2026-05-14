package handlers_test

// resource_family_test.go — handler-layer tests for slice 2 of env-aware
// deployments. Exercises GET /api/v1/resources/:id/family and
// GET /api/v1/resources/families through the actual Fiber router stack,
// so route ordering, auth middleware, and JSON shapes are all covered.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// seedFamilyMember inserts a resource owned by `teamID` at the given env.
// parentID == nil ⇒ family root. Returns the resource id + token (both
// as strings) for downstream URL/assertion use. The handler-test layer
// builds rows via direct SQL rather than calling models.CreateResource
// because it gives the test cleaner control over the column set without
// being coupled to that helper's signature changes.
func seedFamilyMember(t *testing.T, db *sql.DB, teamID, resourceType, env string, parentID *string) (id, token string) {
	t.Helper()
	var parent interface{}
	if parentID != nil {
		parent = *parentID
	}
	err := db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, env, parent_resource_id)
		VALUES ($1::uuid, $2, 'pro', $3, $4)
		RETURNING id::text, token::text
	`, teamID, resourceType, env, parent).Scan(&id, &token)
	require.NoError(t, err, "seedFamilyMember(team=%s, type=%s, env=%s)", teamID, resourceType, env)
	return id, token
}

// makeAuthedJWT seeds a user + signs the session JWT used by the handlers'
// auth middleware. Reused across every test below.
func makeAuthedJWT(t *testing.T, db *sql.DB, teamID string) string {
	t.Helper()
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email,
	).Scan(&userID))
	return testhelpers.MustSignSessionJWT(t, userID, teamID, email)
}

// TestResourceFamily_RequiresAuth_Returns401 covers the auth middleware
// pre-condition for both endpoints — a missing Authorization header must
// not reveal whether the path exists.
func TestResourceFamily_RequiresAuth_Returns401(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	t.Run("families list", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/resources/families", nil)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("single family", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet,
			"/api/v1/resources/00000000-0000-0000-0000-000000000001/family", nil)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

// TestResourceFamily_ThreeMembers_ReturnedInOrder seeds a 3-env family then
// reads it back through both the by-id and by-token paths to ensure either
// kind of identifier resolves the same family.
func TestResourceFamily_ThreeMembers_ReturnedInOrder(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := makeAuthedJWT(t, db, teamID)

	rootID, rootToken := seedFamilyMember(t, db, teamID, "postgres", "production", nil)
	_, stagingToken := seedFamilyMember(t, db, teamID, "postgres", "staging", &rootID)
	_, devToken := seedFamilyMember(t, db, teamID, "postgres", "dev", &rootID)

	// Read via the ROOT token.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources/"+rootToken+"/family", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		OK            bool   `json:"ok"`
		FamilyRootID  string `json:"family_root_id"`
		Total         int    `json:"total"`
		Members       []struct {
			ID               string `json:"id"`
			Token            string `json:"token"`
			Env              string `json:"env"`
			ResourceType     string `json:"resource_type"`
			IsRoot           bool   `json:"is_root"`
			ParentResourceID string `json:"parent_resource_id"`
		} `json:"members"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.True(t, body.OK)
	assert.Equal(t, 3, body.Total, "3 members in the family")
	assert.Equal(t, rootID, body.FamilyRootID)
	require.Len(t, body.Members, 3)
	assert.Equal(t, rootID, body.Members[0].ID, "root must come first")
	assert.True(t, body.Members[0].IsRoot)
	assert.Empty(t, body.Members[0].ParentResourceID, "root's parent_resource_id is empty string")

	envs := []string{body.Members[0].Env, body.Members[1].Env, body.Members[2].Env}
	assert.ElementsMatch(t, []string{"production", "staging", "dev"}, envs)

	tokens := []string{body.Members[0].Token, body.Members[1].Token, body.Members[2].Token}
	assert.ElementsMatch(t, []string{rootToken, stagingToken, devToken}, tokens)

	// Cache-Control must be private + short.
	assert.Equal(t, "private, max-age=30", resp.Header.Get("Cache-Control"))

	// Walking from a CHILD token returns the same family.
	reqChild := httptest.NewRequest(http.MethodGet, "/api/v1/resources/"+stagingToken+"/family", nil)
	reqChild.Header.Set("Authorization", "Bearer "+jwt)
	respChild, err := app.Test(reqChild, 5000)
	require.NoError(t, err)
	defer respChild.Body.Close()
	require.Equal(t, http.StatusOK, respChild.StatusCode)

	var childBody struct {
		Total        int    `json:"total"`
		FamilyRootID string `json:"family_root_id"`
	}
	require.NoError(t, json.NewDecoder(respChild.Body).Decode(&childBody))
	assert.Equal(t, 3, childBody.Total, "walking from child must surface the same 3 members")
	assert.Equal(t, rootID, childBody.FamilyRootID, "root id must match the parent's id")
}

// TestResourceFamily_Orphan_ReturnsSingleMember covers the case for legacy
// rows or freshly-provisioned standalone resources.
func TestResourceFamily_Orphan_ReturnsSingleMember(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	jwt := makeAuthedJWT(t, db, teamID)

	id, token := seedFamilyMember(t, db, teamID, "redis", "production", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources/"+token+"/family", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		Total        int    `json:"total"`
		FamilyRootID string `json:"family_root_id"`
		Members      []struct {
			ID     string `json:"id"`
			IsRoot bool   `json:"is_root"`
		} `json:"members"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, 1, body.Total)
	assert.Equal(t, id, body.FamilyRootID)
	require.Len(t, body.Members, 1)
	assert.True(t, body.Members[0].IsRoot)
}

// TestResourceFamily_CrossTeam_Returns404 mirrors the rotate-credentials
// cross-team test — the response must NOT leak any family metadata, and
// must NOT confirm existence either (404 not 403).
func TestResourceFamily_CrossTeam_Returns404(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamAID := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamBID := testhelpers.MustCreateTeamDB(t, db, "pro")

	// Team A owns the family.
	_, rootToken := seedFamilyMember(t, db, teamAID, "postgres", "production", nil)
	// Team B authenticates.
	jwtB := makeAuthedJWT(t, db, teamBID)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources/"+rootToken+"/family", nil)
	req.Header.Set("Authorization", "Bearer "+jwtB)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode,
		"cross-team /family must be 404 — never confirm the resource's existence to a non-owner")
}

// TestResourceFamily_InvalidUUID_Returns400 covers the path-param parse error.
func TestResourceFamily_InvalidUUID_Returns400(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	jwt := makeAuthedJWT(t, db, teamID)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources/not-a-uuid/family", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestResourceFamily_NotFound covers the lookup-miss path.
func TestResourceFamily_NotFound(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	jwt := makeAuthedJWT(t, db, teamID)

	// Random UUID that does not exist.
	missing := uuid.New().String()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources/"+missing+"/family", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestResourceFamilies_ListGroupsCorrectly verifies the /families endpoint
// surfaces one entry per family root with members keyed by env.
func TestResourceFamilies_ListGroupsCorrectly(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := makeAuthedJWT(t, db, teamID)

	// Family A: postgres prod + staging
	pgRootID, _ := seedFamilyMember(t, db, teamID, "postgres", "production", nil)
	seedFamilyMember(t, db, teamID, "postgres", "staging", &pgRootID)

	// Family B: redis prod only (orphan)
	redisRootID, _ := seedFamilyMember(t, db, teamID, "redis", "production", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources/families", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "private, max-age=30", resp.Header.Get("Cache-Control"))

	var body struct {
		OK       bool `json:"ok"`
		Total    int  `json:"total"`
		Families []struct {
			FamilyRootID  string                    `json:"family_root_id"`
			ResourceType  string                    `json:"resource_type"`
			MembersPerEnv map[string]map[string]any `json:"members_per_env"`
		} `json:"families"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.True(t, body.OK)
	assert.Equal(t, 2, body.Total, "exactly two family roots — postgres + redis")

	byRoot := map[string]struct {
		resourceType string
		members      map[string]map[string]any
	}{}
	for _, f := range body.Families {
		byRoot[f.FamilyRootID] = struct {
			resourceType string
			members      map[string]map[string]any
		}{f.ResourceType, f.MembersPerEnv}
	}

	pg, ok := byRoot[pgRootID]
	require.True(t, ok, "postgres family root missing from /families response")
	assert.Equal(t, "postgres", pg.resourceType)
	require.Len(t, pg.members, 2)
	assert.Contains(t, pg.members, "production")
	assert.Contains(t, pg.members, "staging")
	prodMember := pg.members["production"]
	assert.Equal(t, true, prodMember["is_root"], "production row IS the root")
	stagingMember := pg.members["staging"]
	assert.Equal(t, false, stagingMember["is_root"], "staging row is not the root")

	redis, ok := byRoot[redisRootID]
	require.True(t, ok, "redis family root missing from /families response")
	assert.Equal(t, "redis", redis.resourceType)
	require.Len(t, redis.members, 1)
}

// TestResourceFamilies_EmptyTeam covers the green-field UX state.
func TestResourceFamilies_EmptyTeam(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	jwt := makeAuthedJWT(t, db, teamID)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources/families", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		OK       bool          `json:"ok"`
		Total    int           `json:"total"`
		Families []interface{} `json:"families"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.True(t, body.OK)
	assert.Equal(t, 0, body.Total)
	assert.Empty(t, body.Families, "fresh team must see an empty families array")
}
