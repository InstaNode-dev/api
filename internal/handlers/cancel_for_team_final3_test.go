package handlers_test

// cancel_for_team_final3_test.go — FINAL serial pass #3. Covers the
// PortalSubscriptionCanceler.CancelForTeam arms (team_deletion.go):
//   - "no subscription" (free team, no stripe_customer_id) → nil  (line 84-86)
//   - other DB error (fault DB) → returns the error               (line 88)

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/testhelpers"
)

// TestCancelForTeamFinal3_NoSubscription — a real team with no subscription →
// SubscriptionID returns "no subscription" → CancelForTeam swallows it (nil).
func TestCancelForTeamFinal3_NoSubscription(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "free"))

	c := &handlers.PortalSubscriptionCanceler{DB: db, Cfg: &config.Config{}}
	err := c.CancelForTeam(context.Background(), teamID)
	require.NoError(t, err, "no-subscription must be treated as success (nil)")
}

// TestCancelForTeamFinal3_DBError — a fault DB makes the SubscriptionID query
// error with a non-"no subscription" message → CancelForTeam bubbles the error
// (team_deletion.go:88).
func TestCancelForTeamFinal3_DBError(t *testing.T) {
	faultDB := openFaultDB(t, 0)
	c := &handlers.PortalSubscriptionCanceler{DB: faultDB, Cfg: &config.Config{}}
	err := c.CancelForTeam(context.Background(), uuid.New())
	assert.Error(t, err, "a non-no-subscription DB error must bubble up")
}
