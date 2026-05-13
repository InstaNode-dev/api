package models_test

// payment_grace_periods_test.go — covers the dunning state-machine
// model contract: create-with-idempotency, GetActive, MarkRecovered,
// MarkTerminated, and the cross-team isolation invariant.
//
// All tests run against the real test Postgres (the same path as
// audit_log_test.go etc.) because the partial-unique index that enforces
// the one-active-row invariant only fires under real Postgres semantics
// — a mock or in-memory sqlite would silently let two active rows coexist
// and the test would pass while the production guarantee broke.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// freshGraceParams builds a CreatePaymentGracePeriodParams pre-shaped
// for the happy path. Callers override individual fields as the test
// requires (e.g. setting a past ExpiresAt to simulate an already-expired
// row for the terminator job).
func freshGraceParams(t *testing.T, teamID uuid.UUID) models.CreatePaymentGracePeriodParams {
	t.Helper()
	now := time.Now().UTC()
	return models.CreatePaymentGracePeriodParams{
		TeamID:         teamID,
		SubscriptionID: "sub_test_" + uuid.NewString(),
		StartedAt:      now,
		ExpiresAt:      now.Add(7 * 24 * time.Hour),
	}
}

// TestCreatePaymentGracePeriod_HappyPath asserts the basic INSERT
// returns a fully-hydrated row with status='active' and the three
// outcome timestamps unset.
func TestCreatePaymentGracePeriod_HappyPath(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamUUID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamUUID)

	g, err := models.CreatePaymentGracePeriod(context.Background(), db, freshGraceParams(t, teamUUID))
	require.NoError(t, err)
	require.NotNil(t, g)
	assert.Equal(t, teamUUID, g.TeamID)
	assert.Equal(t, models.PaymentGraceStatusActive, g.Status)
	assert.Equal(t, 0, g.RemindersSent)
	assert.Nil(t, g.LastReminderAt, "no reminders sent yet")
	assert.Nil(t, g.RecoveredAt, "not recovered yet")
	assert.Nil(t, g.TerminatedAt, "not terminated yet")
	assert.False(t, g.ExpiresAt.IsZero())
	assert.True(t, g.ExpiresAt.After(g.StartedAt), "expires_at must be after started_at")
}

// TestCreatePaymentGracePeriod_RejectsDuplicateActive verifies the
// idempotency contract: a second Create call for a team that already
// has an active grace row returns ErrPaymentGraceAlreadyActive and does
// NOT mutate the existing row. This is the core guarantee that
// Razorpay webhook redeliveries don't double-trigger.
func TestCreatePaymentGracePeriod_RejectsDuplicateActive(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamUUID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamUUID)

	first, err := models.CreatePaymentGracePeriod(context.Background(), db, freshGraceParams(t, teamUUID))
	require.NoError(t, err)
	require.NotNil(t, first)

	// Second call MUST fail with the sentinel error.
	second, err := models.CreatePaymentGracePeriod(context.Background(), db, freshGraceParams(t, teamUUID))
	assert.Nil(t, second)
	assert.True(t, errors.Is(err, models.ErrPaymentGraceAlreadyActive),
		"expected ErrPaymentGraceAlreadyActive, got: %v", err)

	// And exactly one row must exist.
	var count int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM payment_grace_periods WHERE team_id = $1::uuid AND status = 'active'`,
		teamUUID).Scan(&count))
	assert.Equal(t, 1, count, "redelivery must not create a second active row")
}

// TestCreatePaymentGracePeriod_AfterRecoveredAllowsNewActive verifies
// that a team that previously had a grace period (now status='recovered'
// or 'terminated') can open a fresh active grace row. The partial-unique
// index uses WHERE status='active' so historical rows do not block.
//
// This is the failed-recovered-failed-again scenario: customer's card
// failed in May, recovered, paid for June, card failed again in July.
// July should get its own grace row, not be blocked by May's history.
func TestCreatePaymentGracePeriod_AfterRecoveredAllowsNewActive(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamUUID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamUUID)

	// First grace, then recover it.
	first, err := models.CreatePaymentGracePeriod(context.Background(), db, freshGraceParams(t, teamUUID))
	require.NoError(t, err)
	flipped, err := models.MarkPaymentGraceRecovered(context.Background(), db, teamUUID, time.Now().UTC())
	require.NoError(t, err)
	require.True(t, flipped)

	// Second grace must succeed.
	second, err := models.CreatePaymentGracePeriod(context.Background(), db, freshGraceParams(t, teamUUID))
	require.NoError(t, err, "after recovery the next grace must be allowed")
	require.NotNil(t, second)
	assert.NotEqual(t, first.ID, second.ID, "must be a new grace row, not a reactivation")
}

// TestCreatePaymentGracePeriod_RejectsMissingRequiredFields exercises
// the input-validation guards that fire before the INSERT — these
// catch programming errors (e.g. a handler forgetting to populate the
// subscription_id) without round-tripping the DB.
func TestCreatePaymentGracePeriod_RejectsMissingRequiredFields(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamUUID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamUUID)
	now := time.Now().UTC()

	// Missing team_id.
	_, err := models.CreatePaymentGracePeriod(context.Background(), db, models.CreatePaymentGracePeriodParams{
		SubscriptionID: "sub_x",
		ExpiresAt:      now.Add(time.Hour),
	})
	assert.Error(t, err, "missing team_id must error")

	// Missing subscription_id.
	_, err = models.CreatePaymentGracePeriod(context.Background(), db, models.CreatePaymentGracePeriodParams{
		TeamID:    teamUUID,
		ExpiresAt: now.Add(time.Hour),
	})
	assert.Error(t, err, "missing subscription_id must error")

	// Missing expires_at.
	_, err = models.CreatePaymentGracePeriod(context.Background(), db, models.CreatePaymentGracePeriodParams{
		TeamID:         teamUUID,
		SubscriptionID: "sub_x",
	})
	assert.Error(t, err, "missing expires_at must error")
}

// TestGetActivePaymentGracePeriod_NoRowReturnsNilNil verifies the
// not-found ergonomic: callers don't need to import sql.ErrNoRows; a
// team with no grace row gets (nil, nil) and can branch on the nil
// directly.
func TestGetActivePaymentGracePeriod_NoRowReturnsNilNil(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamUUID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamUUID)

	g, err := models.GetActivePaymentGracePeriod(context.Background(), db, teamUUID)
	require.NoError(t, err)
	assert.Nil(t, g, "no grace row must return (nil, nil)")
}

// TestGetActivePaymentGracePeriod_IgnoresTerminatedRows verifies that
// only status='active' rows are returned. A team that hit termination
// should look like a clean slate from the model's perspective — the
// recovery / re-grace path lives elsewhere.
func TestGetActivePaymentGracePeriod_IgnoresTerminatedRows(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamUUID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamUUID)

	_, err := models.CreatePaymentGracePeriod(context.Background(), db, freshGraceParams(t, teamUUID))
	require.NoError(t, err)
	flipped, err := models.MarkPaymentGraceTerminated(context.Background(), db, teamUUID, time.Now().UTC())
	require.NoError(t, err)
	require.True(t, flipped)

	g, err := models.GetActivePaymentGracePeriod(context.Background(), db, teamUUID)
	require.NoError(t, err)
	assert.Nil(t, g, "terminated rows must not appear in GetActive")
}

// TestMarkPaymentGraceRecovered_HappyPath asserts the flip + stamp +
// rows-affected contract: a single active row becomes recovered, the
// recovered_at column populates, and the function returns (true, nil).
func TestMarkPaymentGraceRecovered_HappyPath(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamUUID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamUUID)

	_, err := models.CreatePaymentGracePeriod(context.Background(), db, freshGraceParams(t, teamUUID))
	require.NoError(t, err)

	flipped, err := models.MarkPaymentGraceRecovered(context.Background(), db, teamUUID, time.Time{})
	require.NoError(t, err)
	assert.True(t, flipped, "first flip must return true (row affected)")

	// Verify the row state.
	var status string
	var recoveredAt *time.Time
	require.NoError(t, db.QueryRow(`
		SELECT status, recovered_at FROM payment_grace_periods WHERE team_id = $1::uuid`,
		teamUUID).Scan(&status, &recoveredAt))
	assert.Equal(t, models.PaymentGraceStatusRecovered, status)
	require.NotNil(t, recoveredAt, "recovered_at must be set after flip")
}

// TestMarkPaymentGraceRecovered_NoActiveReturnsFalse covers the
// happy-path renewal case: subscription.charged arrives without a prior
// failed-charge event. MarkRecovered finds no active row, returns
// (false, nil), and the webhook handler treats it as "no grace was in
// flight, normal renewal." No error surfaced.
func TestMarkPaymentGraceRecovered_NoActiveReturnsFalse(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamUUID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamUUID)

	flipped, err := models.MarkPaymentGraceRecovered(context.Background(), db, teamUUID, time.Time{})
	require.NoError(t, err)
	assert.False(t, flipped, "no active row must return (false, nil)")
}

// TestMarkPaymentGraceRecovered_IdempotentOnRedelivery covers the
// race: two concurrent subscription.charged webhook deliveries both
// call MarkRecovered. The first wins (returns true), the second sees
// no active row and returns false. Neither errors.
func TestMarkPaymentGraceRecovered_IdempotentOnRedelivery(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamUUID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamUUID)

	_, err := models.CreatePaymentGracePeriod(context.Background(), db, freshGraceParams(t, teamUUID))
	require.NoError(t, err)

	flipped1, err := models.MarkPaymentGraceRecovered(context.Background(), db, teamUUID, time.Time{})
	require.NoError(t, err)
	assert.True(t, flipped1, "first call must flip")

	flipped2, err := models.MarkPaymentGraceRecovered(context.Background(), db, teamUUID, time.Time{})
	require.NoError(t, err)
	assert.False(t, flipped2, "redelivery must be a no-op (already recovered)")
}

// TestMarkPaymentGraceTerminated_HappyPath mirrors the recovered test
// but for the terminal end-state. Same predicate (only active rows
// transition) so the test shape is identical.
func TestMarkPaymentGraceTerminated_HappyPath(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamUUID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamUUID)

	_, err := models.CreatePaymentGracePeriod(context.Background(), db, freshGraceParams(t, teamUUID))
	require.NoError(t, err)

	flipped, err := models.MarkPaymentGraceTerminated(context.Background(), db, teamUUID, time.Time{})
	require.NoError(t, err)
	assert.True(t, flipped)

	var status string
	var terminatedAt *time.Time
	require.NoError(t, db.QueryRow(`
		SELECT status, terminated_at FROM payment_grace_periods WHERE team_id = $1::uuid`,
		teamUUID).Scan(&status, &terminatedAt))
	assert.Equal(t, models.PaymentGraceStatusTerminated, status)
	require.NotNil(t, terminatedAt)
}

// TestMarkPaymentGraceTerminated_RecoveredStaysRecovered guards the
// transition-immutability rule: once a row is recovered, the
// terminator must NOT flip it to terminated. The WHERE status='active'
// predicate enforces this — a previously-recovered customer must never
// be auto-suspended by a misfiring terminator.
func TestMarkPaymentGraceTerminated_RecoveredStaysRecovered(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamUUID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamUUID)

	_, err := models.CreatePaymentGracePeriod(context.Background(), db, freshGraceParams(t, teamUUID))
	require.NoError(t, err)
	flipped, err := models.MarkPaymentGraceRecovered(context.Background(), db, teamUUID, time.Now().UTC())
	require.NoError(t, err)
	require.True(t, flipped)

	// Terminator must be a no-op.
	flipped, err = models.MarkPaymentGraceTerminated(context.Background(), db, teamUUID, time.Now().UTC())
	require.NoError(t, err)
	assert.False(t, flipped, "terminator must not flip a recovered row")

	var status string
	require.NoError(t, db.QueryRow(`
		SELECT status FROM payment_grace_periods WHERE team_id = $1::uuid`,
		teamUUID).Scan(&status))
	assert.Equal(t, models.PaymentGraceStatusRecovered, status, "must stay recovered")
}

// TestGetActivePaymentGracePeriod_CrossTeamIsolation guards the most
// dangerous failure mode: a Create or GetActive call mis-scoping by
// team_id would leak one customer's billing state to another. We seed
// two teams, fail-charge one, and verify the other's GetActive returns
// nil — the rows do not blur across team boundaries.
func TestGetActivePaymentGracePeriod_CrossTeamIsolation(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamA := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	teamB := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	defer db.Exec(`DELETE FROM teams WHERE id = ANY($1::uuid[])`, "{"+teamA.String()+","+teamB.String()+"}")

	_, err := models.CreatePaymentGracePeriod(context.Background(), db, freshGraceParams(t, teamA))
	require.NoError(t, err)

	gA, err := models.GetActivePaymentGracePeriod(context.Background(), db, teamA)
	require.NoError(t, err)
	require.NotNil(t, gA)
	assert.Equal(t, teamA, gA.TeamID)

	gB, err := models.GetActivePaymentGracePeriod(context.Background(), db, teamB)
	require.NoError(t, err)
	assert.Nil(t, gB, "team B must not see team A's grace row")

	// And teamB can open its own grace row independently — the unique
	// index is partial-per-team, not global.
	_, err = models.CreatePaymentGracePeriod(context.Background(), db, freshGraceParams(t, teamB))
	require.NoError(t, err, "team B must be able to open its own grace row")
}
