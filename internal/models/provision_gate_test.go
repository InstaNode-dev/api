package models_test

// provision_gate_test.go — P5 coverage: the deployment + stack tier-cap
// TOCTOU fix.
//
// Before P5 the handlers did CountActive*ByTeam then a separate Create* —
// two concurrent provisions for one team both read a stale count and both
// created, bypassing the per-tier cap. CreateDeploymentWithCap /
// CreateStackWithCap now run count+create in ONE team-row-locked tx.
//
// These tests assert (a) the cap is enforced sequentially and (b) — the
// real bug — N concurrent provisions against a cap of K create exactly K
// rows, never K+1+. Skips when TEST_DATABASE_URL is unset.

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// TestCreateDeploymentWithCap_EnforcesCapSequentially: with a cap of 2, the
// 3rd sequential create must be rejected with ErrDeploymentCapReached.
func TestCreateDeploymentWithCap_EnforcesCapSequentially(t *testing.T) {
	requireDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)
	defer db.Exec(`DELETE FROM deployments WHERE team_id = $1`, teamID)

	const cap = 2
	for i := 0; i < cap; i++ {
		_, err := models.CreateDeploymentWithCap(ctx, db, cap, models.CreateDeploymentParams{
			TeamID: teamID,
			AppID:  "app-seq-" + uuid.NewString()[:8],
			Tier:   "hobby",
		})
		require.NoErrorf(t, err, "create %d within cap must succeed", i+1)
	}

	_, err := models.CreateDeploymentWithCap(ctx, db, cap, models.CreateDeploymentParams{
		TeamID: teamID,
		AppID:  "app-seq-over-" + uuid.NewString()[:8],
		Tier:   "hobby",
	})
	require.ErrorIs(t, err, models.ErrDeploymentCapReached,
		"the create that exceeds the cap must return ErrDeploymentCapReached")

	n, err := models.CountActiveDeploymentsByTeam(ctx, db, teamID)
	require.NoError(t, err)
	assert.Equal(t, cap, n, "exactly cap deployments must exist")
}

// TestCreateDeploymentWithCap_ConcurrentRaceCannotBypassCap is THE P5
// regression test: 8 concurrent CreateDeploymentWithCap calls against a
// cap of 3 must create EXACTLY 3 rows. Before the FOR UPDATE team-row lock
// all 8 could pass a stale count and create 8.
func TestCreateDeploymentWithCap_ConcurrentRaceCannotBypassCap(t *testing.T) {
	requireDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)
	defer db.Exec(`DELETE FROM deployments WHERE team_id = $1`, teamID)

	const (
		cap         = 3
		concurrency = 8
	)
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded int
		capErrors int
	)
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := models.CreateDeploymentWithCap(ctx, db, cap, models.CreateDeploymentParams{
				TeamID: teamID,
				AppID:  "app-race-" + uuid.NewString()[:8],
				Tier:   "pro",
			})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				succeeded++
			case assert.ErrorIs(t, err, models.ErrDeploymentCapReached):
				capErrors++
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, cap, succeeded, "exactly cap concurrent creates may succeed")
	assert.Equal(t, concurrency-cap, capErrors, "the rest must be rejected with the cap error")

	n, err := models.CountActiveDeploymentsByTeam(ctx, db, teamID)
	require.NoError(t, err)
	assert.Equal(t, cap, n, "the DB must hold exactly cap deployments — no race bypass")
}

// TestCreateDeploymentWithCap_UnlimitedTier: limit < 0 (team tier) skips
// the cap check entirely.
func TestCreateDeploymentWithCap_UnlimitedTier(t *testing.T) {
	requireDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "team"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)
	defer db.Exec(`DELETE FROM deployments WHERE team_id = $1`, teamID)

	for i := 0; i < 5; i++ {
		_, err := models.CreateDeploymentWithCap(ctx, db, -1, models.CreateDeploymentParams{
			TeamID: teamID,
			AppID:  "app-unl-" + uuid.NewString()[:8],
			Tier:   "team",
		})
		require.NoError(t, err, "unlimited tier (limit < 0) must never hit a cap")
	}
}

// TestCreateStackWithCap_ConcurrentRaceCannotBypassCap mirrors the
// deployment race test for stacks + their service rows.
func TestCreateStackWithCap_ConcurrentRaceCannotBypassCap(t *testing.T) {
	requireDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)
	defer db.Exec(`DELETE FROM stacks WHERE team_id = $1`, teamID)

	const (
		cap         = 2
		concurrency = 6
	)
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded int
		capErrors int
	)
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tid := teamID
			out, err := models.CreateStackWithCap(ctx, db, cap, models.CreateStackParams{
				TeamID: &tid,
				Name:   "race-stack",
				Slug:   "rs-" + uuid.NewString()[:10],
				Tier:   "pro",
				Env:    "production",
			}, []models.CreateStackServiceParams{
				{Name: "web", Expose: true, Port: 8080},
			})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				succeeded++
				assert.Len(t, out.Services, 1, "the stack's service row must be created in the same tx")
			case assert.ErrorIs(t, err, models.ErrStackCapReached):
				capErrors++
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, cap, succeeded, "exactly cap concurrent stack creates may succeed")
	assert.Equal(t, concurrency-cap, capErrors, "the rest must be rejected with the stack cap error")

	n, err := models.CountActiveStacksByTeam(ctx, db, teamID)
	require.NoError(t, err)
	assert.Equal(t, cap, n, "the DB must hold exactly cap stacks — no race bypass")
}
