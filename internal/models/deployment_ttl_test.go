package models_test

// deployment_ttl_test.go — Wave FIX-J coverage for the deploy TTL model.
// Covers: default 24h TTL on CreateDeployment, MakeDeploymentPermanent,
// SetDeploymentTTL, GetDeploymentsExpiringSoon, AdvanceDeploymentReminder
// (CAS guard), GetExpiredDeployments, MarkDeploymentExpired.
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

// TestCreateDeployment_DefaultTTLIsAuto24h: by default, /deploy/new produces
// an auto_24h deploy with expires_at ≈ now()+24h. Critical fixture for the
// rest of FIX-J — every downstream test assumes this default.
func TestCreateDeployment_DefaultTTLIsAuto24h(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	ctx := context.Background()
	d, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID: teamID,
		AppID:  "app-ttl-default-" + uuid.NewString()[:8],
		Tier:   "hobby",
		// No TTLPolicy supplied — should default to auto_24h.
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, d.ID)

	assert.Equal(t, models.DeployTTLPolicyAuto24h, d.TTLPolicy,
		"empty TTLPolicy must default to auto_24h")
	require.True(t, d.ExpiresAt.Valid, "auto_24h must set expires_at")

	// expires_at should be approximately 24h from now. We accept a 60s skew
	// to absorb the test-run latency between QueryRow and assertion.
	delta := time.Until(d.ExpiresAt.Time)
	assert.InDelta(t, (24 * time.Hour).Seconds(), delta.Seconds(), 60,
		"auto_24h must set expires_at ≈ now()+24h")
}

// TestCreateDeployment_PermanentPolicySetsNullExpiry: an explicit
// permanent policy → no expires_at.
func TestCreateDeployment_PermanentPolicySetsNullExpiry(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	ctx := context.Background()
	d, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID:    teamID,
		AppID:     "app-ttl-perm-" + uuid.NewString()[:8],
		Tier:      "hobby",
		TTLPolicy: models.DeployTTLPolicyPermanent,
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, d.ID)

	assert.Equal(t, models.DeployTTLPolicyPermanent, d.TTLPolicy)
	assert.False(t, d.ExpiresAt.Valid, "permanent policy must leave expires_at NULL")
}

// TestMakeDeploymentPermanent_FlipsExpiresAtToNull is the canonical
// "user opted in to keeping it" code path.
func TestMakeDeploymentPermanent_FlipsExpiresAtToNull(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	ctx := context.Background()
	d, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID: teamID,
		AppID:  "app-ttl-mkperm-" + uuid.NewString()[:8],
		Tier:   "hobby",
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, d.ID)
	require.True(t, d.ExpiresAt.Valid, "fixture: starts with TTL set")

	require.NoError(t, models.MakeDeploymentPermanent(ctx, db, d.ID))

	refreshed, err := models.GetDeploymentByID(ctx, db, d.ID)
	require.NoError(t, err)
	assert.Equal(t, models.DeployTTLPolicyPermanent, refreshed.TTLPolicy)
	assert.False(t, refreshed.ExpiresAt.Valid, "expires_at must be NULL after make-permanent")
}

// TestMakeDeploymentPermanent_IsIdempotent: calling twice is a no-op
// (no error, second-call state matches first).
func TestMakeDeploymentPermanent_IsIdempotent(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	ctx := context.Background()
	d, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID:    teamID,
		AppID:     "app-ttl-idem-" + uuid.NewString()[:8],
		Tier:      "hobby",
		TTLPolicy: models.DeployTTLPolicyPermanent,
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, d.ID)

	require.NoError(t, models.MakeDeploymentPermanent(ctx, db, d.ID))
	require.NoError(t, models.MakeDeploymentPermanent(ctx, db, d.ID))

	refreshed, err := models.GetDeploymentByID(ctx, db, d.ID)
	require.NoError(t, err)
	assert.Equal(t, models.DeployTTLPolicyPermanent, refreshed.TTLPolicy)
	assert.False(t, refreshed.ExpiresAt.Valid)
}

// TestSetDeploymentTTL_SetsCustomExpiryAndResetsReminders: extending the TTL
// MUST reset reminders_sent + last_reminder_at so the full 6-email cycle
// fires again. Catches the regression where a customer extends from
// 1h-to-go to 48h-to-go and gets zero reminders.
func TestSetDeploymentTTL_SetsCustomExpiryAndResetsReminders(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	ctx := context.Background()
	d, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID: teamID,
		AppID:  "app-ttl-set-" + uuid.NewString()[:8],
		Tier:   "hobby",
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, d.ID)

	// Pre-state: pretend we already sent 4 reminders.
	_, err = db.ExecContext(ctx, `
		UPDATE deployments
		SET reminders_sent = 4, last_reminder_at = now() - interval '1 hour'
		WHERE id = $1
	`, d.ID)
	require.NoError(t, err)

	require.NoError(t, models.SetDeploymentTTL(ctx, db, d.ID, 72))

	refreshed, err := models.GetDeploymentByID(ctx, db, d.ID)
	require.NoError(t, err)
	assert.Equal(t, models.DeployTTLPolicyCustom, refreshed.TTLPolicy)
	assert.True(t, refreshed.ExpiresAt.Valid)
	delta := time.Until(refreshed.ExpiresAt.Time)
	assert.InDelta(t, (72 * time.Hour).Seconds(), delta.Seconds(), 60,
		"custom TTL must set expires_at ≈ now()+hours")
	assert.Equal(t, 0, refreshed.RemindersSent,
		"SetDeploymentTTL MUST reset reminders_sent so the 6-email cycle fires again")
	assert.False(t, refreshed.LastReminderAt.Valid,
		"SetDeploymentTTL MUST reset last_reminder_at")
}

// TestGetDeploymentsExpiringSoon_HonoursWindowAndCooldown is the worker's
// candidate query. Asserts only rows inside the lookahead AND outside the
// reminder cooldown surface.
func TestGetDeploymentsExpiringSoon_HonoursWindowAndCooldown(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	ctx := context.Background()

	// Inside-window, never reminded → expected to surface.
	inWindow, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID: teamID, AppID: "app-in-" + uuid.NewString()[:8], Tier: "hobby",
		TTLPolicy: models.DeployTTLPolicyCustom, TTLHours: 6,
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, inWindow.ID)

	// Outside-window (24h from now) → expected to NOT surface inside a 12h window.
	outOfWindow, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID: teamID, AppID: "app-out-" + uuid.NewString()[:8], Tier: "hobby",
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, outOfWindow.ID)

	// Recently-reminded (inside window) → expected to NOT surface due to cooldown.
	recentlyReminded, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID: teamID, AppID: "app-rec-" + uuid.NewString()[:8], Tier: "hobby",
		TTLPolicy: models.DeployTTLPolicyCustom, TTLHours: 6,
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, recentlyReminded.ID)
	_, err = db.ExecContext(ctx, `
		UPDATE deployments SET last_reminder_at = now() - interval '30 minutes'
		WHERE id = $1
	`, recentlyReminded.ID)
	require.NoError(t, err)

	// Permanent → expected to NEVER surface (no expires_at).
	perm, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID: teamID, AppID: "app-perm-" + uuid.NewString()[:8], Tier: "hobby",
		TTLPolicy: models.DeployTTLPolicyPermanent,
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, perm.ID)

	got, err := models.GetDeploymentsExpiringSoon(ctx, db, 12*time.Hour, 2*time.Hour)
	require.NoError(t, err)

	ids := make(map[uuid.UUID]bool, len(got))
	for _, d := range got {
		ids[d.ID] = true
	}
	assert.True(t, ids[inWindow.ID], "inside-window deploy must surface")
	assert.False(t, ids[outOfWindow.ID], "out-of-window deploy must NOT surface")
	assert.False(t, ids[recentlyReminded.ID], "cooldown-blocked deploy must NOT surface")
	assert.False(t, ids[perm.ID], "permanent deploy must NEVER surface")
}

// TestAdvanceDeploymentReminder_CASGuardPreventsDoubleSend: two concurrent
// workers reading reminders_sent=N must not both fire — only the first
// AdvanceDeploymentReminder call returns true.
func TestAdvanceDeploymentReminder_CASGuardPreventsDoubleSend(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	ctx := context.Background()
	d, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID: teamID, AppID: "app-cas-" + uuid.NewString()[:8], Tier: "hobby",
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, d.ID)

	first, err := models.AdvanceDeploymentReminder(ctx, db, d.ID, 0, 2*time.Hour)
	require.NoError(t, err)
	assert.True(t, first, "first call from reminders_sent=0 must advance")

	// Second call from the SAME expected value (0) must fail — the row was
	// already advanced to 1.
	second, err := models.AdvanceDeploymentReminder(ctx, db, d.ID, 0, 2*time.Hour)
	require.NoError(t, err)
	assert.False(t, second, "second call from reminders_sent=0 must NOT advance (CAS)")

	// Call from the new expected value (1) — should still be blocked by the
	// cooldown gate because last_reminder_at is now.
	cooldownBlocked, err := models.AdvanceDeploymentReminder(ctx, db, d.ID, 1, 2*time.Hour)
	require.NoError(t, err)
	assert.False(t, cooldownBlocked, "second advance inside the cooldown window must NOT fire")

	refreshed, err := models.GetDeploymentByID(ctx, db, d.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, refreshed.RemindersSent, "reminders_sent must be exactly 1 after the single CAS")
}

// TestAdvanceDeploymentReminder_StopsAtSix: after 6 reminders we must
// never advance again — the worker stops sending.
func TestAdvanceDeploymentReminder_StopsAtSix(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	ctx := context.Background()
	d, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID: teamID, AppID: "app-six-" + uuid.NewString()[:8], Tier: "hobby",
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, d.ID)

	// Force pre-state to 6 reminders + cooldown elapsed.
	_, err = db.ExecContext(ctx, `
		UPDATE deployments
		SET reminders_sent = 6, last_reminder_at = now() - interval '6 hours'
		WHERE id = $1
	`, d.ID)
	require.NoError(t, err)

	advanced, err := models.AdvanceDeploymentReminder(ctx, db, d.ID, 6, 2*time.Hour)
	require.NoError(t, err)
	assert.False(t, advanced, "must NOT advance past reminders_sent=6")
}

// TestGetExpiredDeployments_ReturnsOnlyExpiredNonPermanent verifies the
// expirer's candidate query.
func TestGetExpiredDeployments_ReturnsOnlyExpiredNonPermanent(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	ctx := context.Background()

	// Expired auto_24h → expected to surface.
	expired, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID: teamID, AppID: "app-exp-" + uuid.NewString()[:8], Tier: "hobby",
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, expired.ID)
	_, err = db.ExecContext(ctx, `UPDATE deployments SET expires_at = now() - interval '1 hour' WHERE id = $1`, expired.ID)
	require.NoError(t, err)

	// Still-valid auto_24h → expected NOT to surface.
	stillValid, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID: teamID, AppID: "app-val-" + uuid.NewString()[:8], Tier: "hobby",
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, stillValid.ID)

	// Permanent → never surface even with stale expires_at (defensive).
	perm, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID: teamID, AppID: "app-perm-exp-" + uuid.NewString()[:8], Tier: "hobby",
		TTLPolicy: models.DeployTTLPolicyPermanent,
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, perm.ID)
	_, err = db.ExecContext(ctx, `UPDATE deployments SET expires_at = now() - interval '1 hour' WHERE id = $1`, perm.ID)
	require.NoError(t, err)

	got, err := models.GetExpiredDeployments(ctx, db, 100)
	require.NoError(t, err)
	ids := make(map[uuid.UUID]bool, len(got))
	for _, d := range got {
		ids[d.ID] = true
	}
	assert.True(t, ids[expired.ID], "expired auto_24h must surface")
	assert.False(t, ids[stillValid.ID], "still-valid deploy must NOT surface")
	assert.False(t, ids[perm.ID], "permanent deploy must NEVER surface even with stale expires_at")
}

// TestMarkDeploymentExpired_FlipsStatus verifies the soft-delete transition.
func TestMarkDeploymentExpired_FlipsStatus(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	ctx := context.Background()
	d, err := models.CreateDeployment(ctx, db, models.CreateDeploymentParams{
		TeamID: teamID, AppID: "app-mark-" + uuid.NewString()[:8], Tier: "hobby",
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, d.ID)

	require.NoError(t, models.MarkDeploymentExpired(ctx, db, d.ID))
	refreshed, err := models.GetDeploymentByID(ctx, db, d.ID)
	require.NoError(t, err)
	assert.Equal(t, "expired", refreshed.Status)
}
