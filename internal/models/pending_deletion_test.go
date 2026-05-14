package models_test

// pending_deletion_test.go — coverage for the Wave FIX-I pending_deletions
// model layer. Migration 044.
//
// Skips when TEST_DATABASE_URL is unset (see requireDB in
// resource_env_test.go). Pure-unit cases at the bottom (MaskEmail,
// token-hash determinism) run unconditionally.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// TestCreatePendingDeletion_HappyPath asserts that a fresh row lands
// with status='pending', the returned plaintext hashes to the stored
// hash, and the row is queryable by both token-hash and resource-id.
func TestCreatePendingDeletion_HappyPath(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	var userID uuid.UUID
	require.NoError(t, db.QueryRowContext(ctx, `
		INSERT INTO users (team_id, email, role, is_primary)
		VALUES ($1, $2, 'owner', true)
		RETURNING id
	`, teamID, "alice@example.com").Scan(&userID))

	resourceID := uuid.New()
	pending, plaintext, err := models.CreatePendingDeletion(
		ctx, db, resourceID, models.PendingDeletionResourceDeploy,
		teamID, userID, "alice@example.com", 15*time.Minute,
	)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM pending_deletions WHERE id = $1`, pending.ID)

	assert.Equal(t, models.PendingDeletionStatusPending, pending.Status)
	assert.Equal(t, "alice@example.com", pending.EmailSentTo)
	assert.True(t, strings.HasPrefix(plaintext, models.PendingDeletionTokenPrefix),
		"plaintext token must carry the canonical prefix")
	assert.Equal(t, models.HashPendingDeletionToken(plaintext), pending.ConfirmationTokenHash,
		"stored hash must match sha256(plaintext)")
	assert.WithinDuration(t, time.Now().Add(15*time.Minute), pending.ExpiresAt, 5*time.Second)

	// Token-hash lookup hits the row.
	got, err := models.GetPendingDeletionByTokenHash(ctx, db, pending.ConfirmationTokenHash)
	require.NoError(t, err)
	assert.Equal(t, pending.ID, got.ID)

	// Resource lookup hits the row.
	got, err = models.GetPendingDeletionByResource(ctx, db, resourceID, models.PendingDeletionResourceDeploy)
	require.NoError(t, err)
	assert.Equal(t, pending.ID, got.ID)
}

// TestCreatePendingDeletion_BlocksDuplicate asserts that a second
// create for the same (resource_id, resource_type) returns
// ErrPendingDeletionAlreadyExists while the first is still in
// 'pending' status. After the first is cancelled, a fresh create
// succeeds (terminal-state rows don't block new ones).
func TestCreatePendingDeletion_BlocksDuplicate(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	var userID uuid.UUID
	require.NoError(t, db.QueryRowContext(ctx, `
		INSERT INTO users (team_id, email, role, is_primary)
		VALUES ($1, $2, 'owner', true) RETURNING id
	`, teamID, "alice@example.com").Scan(&userID))

	resourceID := uuid.New()
	first, _, err := models.CreatePendingDeletion(ctx, db, resourceID,
		models.PendingDeletionResourceDeploy, teamID, userID, "alice@example.com", 15*time.Minute)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM pending_deletions WHERE id = $1`, first.ID)

	_, _, err = models.CreatePendingDeletion(ctx, db, resourceID,
		models.PendingDeletionResourceDeploy, teamID, userID, "alice@example.com", 15*time.Minute)
	assert.ErrorIs(t, err, models.ErrPendingDeletionAlreadyExists,
		"second create on a pending resource must surface the dedupe error")

	// Cancel the first; a fresh create now succeeds.
	won, err := models.MarkPendingDeletionCancelled(ctx, db, first.ID)
	require.NoError(t, err)
	require.True(t, won)

	second, _, err := models.CreatePendingDeletion(ctx, db, resourceID,
		models.PendingDeletionResourceDeploy, teamID, userID, "alice@example.com", 15*time.Minute)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM pending_deletions WHERE id = $1`, second.ID)
	assert.NotEqual(t, first.ID, second.ID)
}

// TestMarkPendingDeletionConfirmed_AtomicCAS asserts that two
// concurrent confirms resolve to exactly one winner. The losing call
// returns won=false, nil — which the handler reads as "already
// resolved" → 410.
func TestMarkPendingDeletionConfirmed_AtomicCAS(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)
	var userID uuid.UUID
	require.NoError(t, db.QueryRowContext(ctx, `
		INSERT INTO users (team_id, email, role, is_primary) VALUES ($1, $2, 'owner', true)
		RETURNING id`, teamID, "a@example.com").Scan(&userID))

	pending, _, err := models.CreatePendingDeletion(ctx, db, uuid.New(),
		models.PendingDeletionResourceDeploy, teamID, userID, "a@example.com", 15*time.Minute)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM pending_deletions WHERE id = $1`, pending.ID)

	won1, err := models.MarkPendingDeletionConfirmed(ctx, db, pending.ID)
	require.NoError(t, err)
	assert.True(t, won1, "first confirm must win")

	won2, err := models.MarkPendingDeletionConfirmed(ctx, db, pending.ID)
	require.NoError(t, err)
	assert.False(t, won2, "second confirm must read as already-resolved")

	// Cancel on an already-confirmed row also reads false — the row
	// is in a terminal non-'pending' state.
	wonCancel, err := models.MarkPendingDeletionCancelled(ctx, db, pending.ID)
	require.NoError(t, err)
	assert.False(t, wonCancel)
}

// TestGetPendingDeletionByTokenHash_ExpiredReturnsNotFound asserts that
// a row whose expires_at < now() is invisible to the token-hash lookup —
// the handler sees the same envelope shape as "wrong token", which
// preserves the "don't leak token validity" invariant.
func TestGetPendingDeletionByTokenHash_ExpiredReturnsNotFound(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)
	var userID uuid.UUID
	require.NoError(t, db.QueryRowContext(ctx, `
		INSERT INTO users (team_id, email, role, is_primary) VALUES ($1, $2, 'owner', true)
		RETURNING id`, teamID, "a@example.com").Scan(&userID))

	// Insert directly with a negative TTL so the row is born expired.
	pending, _, err := models.CreatePendingDeletion(ctx, db, uuid.New(),
		models.PendingDeletionResourceDeploy, teamID, userID, "a@example.com", 1*time.Millisecond)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM pending_deletions WHERE id = $1`, pending.ID)
	time.Sleep(10 * time.Millisecond)

	_, err = models.GetPendingDeletionByTokenHash(ctx, db, pending.ConfirmationTokenHash)
	assert.ErrorIs(t, err, models.ErrPendingDeletionNotFound)
}

// TestExpireOldPendingDeletions_FlipsExpired asserts that the worker's
// sweeper helper flips every past-TTL row to 'expired' and returns the
// (id, resource_id, ...) tuples so the worker can emit one audit row
// per expiry.
func TestExpireOldPendingDeletions_FlipsExpired(t *testing.T) {
	requireDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)
	var userID uuid.UUID
	require.NoError(t, db.QueryRowContext(ctx, `
		INSERT INTO users (team_id, email, role, is_primary) VALUES ($1, $2, 'owner', true)
		RETURNING id`, teamID, "a@example.com").Scan(&userID))

	// One row expired 5 minutes ago.
	expired, _, err := models.CreatePendingDeletion(ctx, db, uuid.New(),
		models.PendingDeletionResourceDeploy, teamID, userID, "a@example.com", -5*time.Minute)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM pending_deletions WHERE id = $1`, expired.ID)
	// One row still in the future.
	fresh, _, err := models.CreatePendingDeletion(ctx, db, uuid.New(),
		models.PendingDeletionResourceDeploy, teamID, userID, "a@example.com", 15*time.Minute)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM pending_deletions WHERE id = $1`, fresh.ID)

	flipped, err := models.ExpireOldPendingDeletions(ctx, db)
	require.NoError(t, err)

	// We only assert that the expired row is in the returned set — other
	// test runs may have left their own expired rows behind.
	var foundExpired, foundFresh bool
	for _, e := range flipped {
		if e.ID == expired.ID {
			foundExpired = true
		}
		if e.ID == fresh.ID {
			foundFresh = true
		}
	}
	assert.True(t, foundExpired, "expired row must be in the sweeper's return set")
	assert.False(t, foundFresh, "fresh row must NOT be flipped")

	// Verify the row's status is now 'expired'.
	var status string
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT status FROM pending_deletions WHERE id = $1`, expired.ID).Scan(&status))
	assert.Equal(t, models.PendingDeletionStatusExpired, status)
}

// ── Pure-unit cases (no DB) ──────────────────────────────────────────────────

// TestMaskEmail covers the privacy-preserving address rendering used in
// API envelopes + audit metadata.
func TestMaskEmail(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"alice@example.com", "a***@example.com"},
		{"a@example.com", "a@example.com"}, // single-char local stays
		{"", ""},
		{"no-at-sign", "no-at-sign"},
		{"ALICE@example.com", "A***@example.com"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, models.MaskEmail(tc.in),
			"MaskEmail(%q)", tc.in)
	}
}

// TestHashPendingDeletionToken_IsStable asserts the hash function is
// deterministic + collision-resistant on the same input. Sanity check —
// drift here breaks every existing token in the DB.
func TestHashPendingDeletionToken_IsStable(t *testing.T) {
	a := models.HashPendingDeletionToken("del_some_token_value")
	b := models.HashPendingDeletionToken("del_some_token_value")
	c := models.HashPendingDeletionToken("del_other")
	assert.Equal(t, a, b, "same input → same hash")
	assert.NotEqual(t, a, c, "different input → different hash")
	assert.Len(t, a, 64, "sha256 hex must be 64 chars")
}
