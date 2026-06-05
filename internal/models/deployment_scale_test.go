package models_test

// deployment_scale_test.go — scale-to-zero model coverage (migration 068,
// Task #54). Covers: CreateDeployment seeds last_activity_at + defaults
// scaled_to_zero/always_on=false; MarkDeploymentScaledToZero CAS (only a
// healthy, not-already-zeroed, not-always-on row is descheduled);
// WakeDeployment clears the flag + bumps activity; SetDeploymentAlwaysOn
// toggles the opt-out; MarkDeploymentBuilding (redeploy) clears scaled_to_zero.
//
// Skips when TEST_DATABASE_URL is unset (see requireDB).

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

func TestCreateDeployment_SeedsScaleToZeroDefaults(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	ctx := context.Background()
	d, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID:    teamID,
		AppID:     "app-s2z-defaults-" + uuid.NewString()[:8],
		Tier:      "hobby",
		TTLPolicy: models.DeployTTLPolicyPermanent,
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, d.ID)

	assert.False(t, d.ScaledToZero, "new deploy must not be scaled_to_zero")
	assert.False(t, d.AlwaysOn, "new deploy must default always_on=false")
	require.True(t, d.LastActivityAt.Valid, "new deploy must seed last_activity_at")
	assert.WithinDuration(t, time.Now(), d.LastActivityAt.Time, 60*time.Second,
		"last_activity_at must be ≈ now() at create time")
}

func TestMarkDeploymentScaledToZero_CAS(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)
	ctx := context.Background()

	d, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID: teamID, AppID: "app-s2z-cas-" + uuid.NewString()[:8],
		Tier: "hobby", TTLPolicy: models.DeployTTLPolicyPermanent,
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, d.ID)

	// Force healthy (the only descheduable status).
	_, err = db.Exec(`UPDATE deployments SET status='healthy' WHERE id=$1`, d.ID)
	require.NoError(t, err)

	// Healthy + not-zeroed + not-always-on → descheduled (1 row).
	n, err := models.MarkDeploymentScaledToZero(ctx, db, d.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n, "healthy row must be descheduled")

	got, err := models.GetDeploymentByID(ctx, db, d.ID)
	require.NoError(t, err)
	assert.True(t, got.ScaledToZero, "row must now be scaled_to_zero")

	// Second call → already zeroed → CAS skips (0 rows).
	n, err = models.MarkDeploymentScaledToZero(ctx, db, d.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), n, "already-zeroed row must be skipped")
}

func TestMarkDeploymentScaledToZero_SkipsAlwaysOn(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)
	ctx := context.Background()

	d, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID: teamID, AppID: "app-s2z-pin-" + uuid.NewString()[:8],
		Tier: "hobby", TTLPolicy: models.DeployTTLPolicyPermanent,
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, d.ID)

	_, err = db.Exec(`UPDATE deployments SET status='healthy', always_on=true WHERE id=$1`, d.ID)
	require.NoError(t, err)

	n, err := models.MarkDeploymentScaledToZero(ctx, db, d.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), n, "always_on (pinned) row must NOT be descheduled")
}

func TestMarkDeploymentScaledToZero_SkipsNonHealthy(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)
	ctx := context.Background()

	d, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID: teamID, AppID: "app-s2z-building-" + uuid.NewString()[:8],
		Tier: "hobby", TTLPolicy: models.DeployTTLPolicyPermanent,
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, d.ID)

	// Leaves status at the create default (building) — not descheduable.
	n, err := models.MarkDeploymentScaledToZero(ctx, db, d.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), n, "a non-healthy (building) row must NOT be descheduled")
}

func TestWakeDeployment_ClearsFlagAndBumpsActivity(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)
	ctx := context.Background()

	d, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID: teamID, AppID: "app-s2z-wake-" + uuid.NewString()[:8],
		Tier: "hobby", TTLPolicy: models.DeployTTLPolicyPermanent,
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, d.ID)

	// Put it to sleep with a stale last_activity_at.
	stale := time.Now().Add(-90 * time.Minute)
	_, err = db.Exec(`UPDATE deployments SET status='healthy', scaled_to_zero=true, last_activity_at=$2 WHERE id=$1`,
		d.ID, stale)
	require.NoError(t, err)

	n, err := models.WakeDeployment(ctx, db, d.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)

	got, err := models.GetDeploymentByID(ctx, db, d.ID)
	require.NoError(t, err)
	assert.False(t, got.ScaledToZero, "wake must clear scaled_to_zero")
	require.True(t, got.LastActivityAt.Valid)
	assert.WithinDuration(t, time.Now(), got.LastActivityAt.Time, 60*time.Second,
		"wake must bump last_activity_at to ≈ now()")
}

func TestSetDeploymentAlwaysOn_Toggle(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)
	ctx := context.Background()

	d, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID: teamID, AppID: "app-s2z-pin-toggle-" + uuid.NewString()[:8],
		Tier: "hobby", TTLPolicy: models.DeployTTLPolicyPermanent,
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, d.ID)

	n, err := models.SetDeploymentAlwaysOn(ctx, db, d.ID, true)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
	got, err := models.GetDeploymentByID(ctx, db, d.ID)
	require.NoError(t, err)
	assert.True(t, got.AlwaysOn, "always_on must be set true")

	_, err = models.SetDeploymentAlwaysOn(ctx, db, d.ID, false)
	require.NoError(t, err)
	got, err = models.GetDeploymentByID(ctx, db, d.ID)
	require.NoError(t, err)
	assert.False(t, got.AlwaysOn, "always_on must toggle back false")
}

func TestMarkDeploymentBuilding_ClearsScaledToZero(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)
	ctx := context.Background()

	d, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID: teamID, AppID: "app-s2z-redeploy-" + uuid.NewString()[:8],
		Tier: "hobby", TTLPolicy: models.DeployTTLPolicyPermanent,
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, d.ID)

	// Asleep + healthy → a redeploy (MarkDeploymentBuilding) must wake it.
	_, err = db.Exec(`UPDATE deployments SET status='healthy', scaled_to_zero=true WHERE id=$1`, d.ID)
	require.NoError(t, err)

	n, err := models.MarkDeploymentBuilding(ctx, db, d.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)

	got, err := models.GetDeploymentByID(ctx, db, d.ID)
	require.NoError(t, err)
	assert.False(t, got.ScaledToZero, "redeploy must clear scaled_to_zero")
	assert.Equal(t, "building", got.Status)
}
