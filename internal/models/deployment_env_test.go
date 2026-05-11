package models_test

// deployment_env_test.go — env-column tests for the Deployment model.
// Skips when TEST_DATABASE_URL is unset (see requireDB in resource_env_test.go).

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

func TestDeploymentEnv_CreateDefaultsToProduction(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	d, err := models.CreateDeployment(context.Background(), db, models.CreateDeploymentParams{
		TeamID: teamID,
		AppID:  "app-test-" + uuid.NewString()[:8],
		Tier:   "hobby",
		// Env intentionally empty → must default.
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, d.ID)

	assert.Equal(t, models.EnvProduction, d.Env)
}

func TestDeploymentEnv_CreateRoundTrips(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	for _, env := range []string{"dev", "staging", "production"} {
		t.Run(env, func(t *testing.T) {
			d, err := models.CreateDeployment(context.Background(), db, models.CreateDeploymentParams{
				TeamID: teamID,
				AppID:  "app-" + env + "-" + uuid.NewString()[:8],
				Tier:   "hobby",
				Env:    env,
			})
			require.NoError(t, err)
			defer db.Exec(`DELETE FROM deployments WHERE id = $1`, d.ID)
			assert.Equal(t, env, d.Env)

			got, err := models.GetDeploymentByAppID(context.Background(), db, d.AppID)
			require.NoError(t, err)
			assert.Equal(t, env, got.Env)
		})
	}
}

// TestDeploymentEnv_AppNameIsolation: same logical app deployed to dev and prod
// must produce two distinct rows. (app_id itself is unique per row — the
// handler generates fresh ones — so we confirm the env column makes them
// distinguishable from the model's POV.)
func TestDeploymentEnv_AppNameIsolation(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	dev, err := models.CreateDeployment(context.Background(), db, models.CreateDeploymentParams{
		TeamID:  teamID,
		AppID:   "myapp-dev-" + uuid.NewString()[:8],
		Tier:    "hobby",
		Env:     "dev",
		EnvVars: map[string]string{"_name": "myapp"},
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, dev.ID)

	prod, err := models.CreateDeployment(context.Background(), db, models.CreateDeploymentParams{
		TeamID:  teamID,
		AppID:   "myapp-prod-" + uuid.NewString()[:8],
		Tier:    "hobby",
		Env:     "production",
		EnvVars: map[string]string{"_name": "myapp"},
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, prod.ID)

	assert.NotEqual(t, dev.ID, prod.ID, "two envs must produce two rows")
	assert.Equal(t, "dev", dev.Env)
	assert.Equal(t, "production", prod.Env)

	devList, err := models.GetDeploymentsByTeamAndEnv(context.Background(), db, teamID, "dev")
	require.NoError(t, err)
	assert.Len(t, devList, 1)
	assert.Equal(t, dev.ID, devList[0].ID)

	prodList, err := models.GetDeploymentsByTeamAndEnv(context.Background(), db, teamID, "")
	require.NoError(t, err)
	// Filter out unrelated rows from concurrent tests.
	var matched int
	for _, d := range prodList {
		if d.ID == prod.ID {
			matched++
		}
	}
	assert.Equal(t, 1, matched)
}
