package handlers_test

// resource_family_arms_final3_test.go — FINAL serial pass #3. Closes the
// ResourceHandler.Family arms the existing resource_final suite leaves open:
//   - not_found: a well-formed id matching no resource (token + id lookups both
//     miss) → 404                                          (resource_family.go:86-88)
//   - cross_team: anchor resolves but belongs to another team → 404
//                                                           (resource_family.go:99-100)

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// TestResourceFamilyFinal3_NotFound — a random valid UUID matches no resource by
// token OR id → 404 not_found (resource_family.go:86-88).
func TestResourceFamilyFinal3_NotFound(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	app := resourceFaultApp(t, db, teamID)
	resp := rfGet(t, app, "/r/"+uuid.NewString()+"/family")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Equal(t, "not_found", rfErr(t, resp))
}

// TestResourceFamilyFinal3_CrossTeam — the anchor resolves (by token) but belongs
// to a DIFFERENT team → 404 not_found (resource_family.go:99-100). The handler's
// Locals-pinned team is `teamID`; the resource is owned by `otherTeam`.
func TestResourceFamilyFinal3_CrossTeam(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	otherTeam := testhelpers.MustCreateTeamDB(t, db, "pro")

	var token string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO resources (team_id, resource_type, tier, status, connection_url)
		 VALUES ($1::uuid, 'postgres', 'pro', 'active', 'ciphertext')
		 RETURNING token::text`, otherTeam).Scan(&token))

	app := resourceFaultApp(t, db, teamID) // caller is teamID, resource is otherTeam's
	resp := rfGet(t, app, "/r/"+token+"/family")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Equal(t, "not_found", rfErr(t, resp))
}
