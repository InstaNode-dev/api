package models_test

// email_events_test.go — DB-backed tests for the email_events
// read/write surface. Skips when TEST_DATABASE_URL is unset so the
// suite runs cleanly in environments without Postgres.
//
// Covers:
//   - Insert + read-back (basic shape).
//   - HasSuppressionFor returns true for a recent bounce.
//   - HasSuppressionFor returns false for a stale (>365d) bounce.
//   - HasSuppressionFor returns true for an unsubscribe at ANY age.
//   - InsertEmailEvent dedupes when the same message_id replays.

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

func requireDBEmailEvents(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
}

// uniqueEmail returns a fresh email per test invocation so concurrent
// runs don't collide on the dedupe index. Using uuid as the local part
// also keeps the index key well-distributed.
func uniqueEmail() string {
	return uuid.NewString() + "@bounce-test.example.com"
}

func TestEmailEvents_InsertAndReadback(t *testing.T) {
	requireDBEmailEvents(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	emailAddr := uniqueEmail()
	raw := json.RawMessage(`{"event":"hard_bounce","email":"x","message_id":"msg-readback-1"}`)

	id, err := models.InsertEmailEvent(context.Background(), db,
		models.EmailEventProviderBrevo, models.EmailEventTypeBounce, emailAddr,
		"mailbox does not exist", raw)
	require.NoError(t, err)
	require.NotEqual(t, uuid.Nil, id, "expected non-nil id on first insert")

	// Verify row landed with all the expected fields.
	var (
		provider, evType, email, reason string
		gotRaw                          []byte
	)
	err = db.QueryRowContext(context.Background(),
		`SELECT provider, event_type, email, reason, raw FROM email_events WHERE id = $1`,
		id).Scan(&provider, &evType, &email, &reason, &gotRaw)
	require.NoError(t, err)
	assert.Equal(t, models.EmailEventProviderBrevo, provider)
	assert.Equal(t, models.EmailEventTypeBounce, evType)
	assert.Equal(t, emailAddr, email)
	assert.Equal(t, "mailbox does not exist", reason)
	assert.JSONEq(t, string(raw), string(gotRaw))
}

func TestEmailEvents_HasSuppressionFor_RecentBounce_True(t *testing.T) {
	requireDBEmailEvents(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	emailAddr := uniqueEmail()
	raw := json.RawMessage(`{"message_id":"msg-recent-1"}`)
	_, err := models.InsertEmailEvent(context.Background(), db,
		models.EmailEventProviderBrevo, models.EmailEventTypeBounce, emailAddr, "", raw)
	require.NoError(t, err)

	suppressed, err := models.HasSuppressionFor(context.Background(), db, emailAddr)
	require.NoError(t, err)
	assert.True(t, suppressed, "recent bounce must suppress")
}

func TestEmailEvents_HasSuppressionFor_StaleBounce_False(t *testing.T) {
	// Bounces decay after 365d. Insert a row, manually backdate created_at
	// beyond the window, verify HasSuppressionFor returns false.
	requireDBEmailEvents(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	emailAddr := uniqueEmail()
	raw := json.RawMessage(`{"message_id":"msg-stale-1"}`)
	id, err := models.InsertEmailEvent(context.Background(), db,
		models.EmailEventProviderBrevo, models.EmailEventTypeBounce, emailAddr, "", raw)
	require.NoError(t, err)

	// Backdate created_at to 400 days ago — well beyond the 365d window.
	_, err = db.ExecContext(context.Background(),
		`UPDATE email_events SET created_at = $1 WHERE id = $2`,
		time.Now().UTC().Add(-400*24*time.Hour), id)
	require.NoError(t, err)

	suppressed, err := models.HasSuppressionFor(context.Background(), db, emailAddr)
	require.NoError(t, err)
	assert.False(t, suppressed, "bounce older than 365d must NOT suppress (decay)")
}

func TestEmailEvents_HasSuppressionFor_StaleUnsubscribe_StillTrue(t *testing.T) {
	// Unsubscribes do NOT decay. Same setup as the stale-bounce test but
	// with event_type=unsubscribe — must still return true.
	requireDBEmailEvents(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	emailAddr := uniqueEmail()
	raw := json.RawMessage(`{"message_id":"msg-unsub-1"}`)
	id, err := models.InsertEmailEvent(context.Background(), db,
		models.EmailEventProviderBrevo, models.EmailEventTypeUnsubscribe, emailAddr, "", raw)
	require.NoError(t, err)

	// Backdate to 5 years ago — way beyond any reasonable decay window.
	_, err = db.ExecContext(context.Background(),
		`UPDATE email_events SET created_at = $1 WHERE id = $2`,
		time.Now().UTC().Add(-5*365*24*time.Hour), id)
	require.NoError(t, err)

	suppressed, err := models.HasSuppressionFor(context.Background(), db, emailAddr)
	require.NoError(t, err)
	assert.True(t, suppressed, "unsubscribes must NEVER decay (permanent opt-out)")
}

func TestEmailEvents_HasSuppressionFor_SpamComplaint_True(t *testing.T) {
	requireDBEmailEvents(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	emailAddr := uniqueEmail()
	raw := json.RawMessage(`{"message_id":"msg-spam-1"}`)
	_, err := models.InsertEmailEvent(context.Background(), db,
		models.EmailEventProviderSES, models.EmailEventTypeSpamComplaint, emailAddr, "", raw)
	require.NoError(t, err)

	suppressed, err := models.HasSuppressionFor(context.Background(), db, emailAddr)
	require.NoError(t, err)
	assert.True(t, suppressed, "spam complaint must suppress")
}

func TestEmailEvents_HasSuppressionFor_SoftBounce_False(t *testing.T) {
	// Soft bounces (mailbox full, greylisted) are deliberately excluded
	// from the suppression set — a transient failure shouldn't
	// permanently silence sends.
	requireDBEmailEvents(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	emailAddr := uniqueEmail()
	raw := json.RawMessage(`{"message_id":"msg-soft-1"}`)
	_, err := models.InsertEmailEvent(context.Background(), db,
		models.EmailEventProviderBrevo, models.EmailEventTypeSoftBounce, emailAddr, "", raw)
	require.NoError(t, err)

	suppressed, err := models.HasSuppressionFor(context.Background(), db, emailAddr)
	require.NoError(t, err)
	assert.False(t, suppressed, "soft bounces must NOT suppress (retry semantics)")
}

func TestEmailEvents_InsertEmailEvent_DedupesOnMessageID(t *testing.T) {
	// Provider replays the same delivery event. With the partial UNIQUE
	// index, the second insert returns (Nil, nil) instead of erroring.
	requireDBEmailEvents(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	emailAddr := uniqueEmail()
	raw := json.RawMessage(`{"message_id":"msg-dedupe-1"}`)

	id1, err := models.InsertEmailEvent(context.Background(), db,
		models.EmailEventProviderBrevo, models.EmailEventTypeBounce, emailAddr, "", raw)
	require.NoError(t, err)
	require.NotEqual(t, uuid.Nil, id1, "first insert should return non-nil id")

	id2, err := models.InsertEmailEvent(context.Background(), db,
		models.EmailEventProviderBrevo, models.EmailEventTypeBounce, emailAddr, "", raw)
	require.NoError(t, err, "second insert with same (provider, type, email, message_id) must NOT error")
	assert.Equal(t, uuid.Nil, id2, "duplicate insert returns uuid.Nil so caller can 200 silently")

	// Confirm only one row exists for this dedupe key.
	var cnt int
	err = db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM email_events WHERE email = $1`,
		emailAddr).Scan(&cnt)
	require.NoError(t, err)
	assert.Equal(t, 1, cnt, "dedupe index must keep only one row")
}

func TestEmailEvents_InsertEmailEvent_RejectsEmptyFields(t *testing.T) {
	requireDBEmailEvents(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	cases := []struct {
		name      string
		provider  string
		eventType string
		email     string
		raw       json.RawMessage
	}{
		{"missing provider", "", models.EmailEventTypeBounce, "x@y.com", json.RawMessage(`{}`)},
		{"missing event_type", models.EmailEventProviderBrevo, "", "x@y.com", json.RawMessage(`{}`)},
		{"missing email", models.EmailEventProviderBrevo, models.EmailEventTypeBounce, "", json.RawMessage(`{}`)},
		{"missing raw", models.EmailEventProviderBrevo, models.EmailEventTypeBounce, "x@y.com", json.RawMessage{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			id, err := models.InsertEmailEvent(context.Background(), db,
				c.provider, c.eventType, c.email, "", c.raw)
			assert.Error(t, err, "expected validation error")
			assert.Equal(t, uuid.Nil, id)
		})
	}
}

func TestEmailEvents_HasSuppressionFor_EmptyEmail_FalseNoQuery(t *testing.T) {
	// Defensive: empty email should short-circuit without hitting the DB.
	requireDBEmailEvents(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	suppressed, err := models.HasSuppressionFor(context.Background(), db, "")
	require.NoError(t, err)
	assert.False(t, suppressed)
}

// ---------------------------------------------------------------------------
// EMAIL-BUGBASH 2026-05-19 — dedup ledger, recent-audit lookup, suppression
// checker. DB-backed; skip when TEST_DATABASE_URL is unset.
// ---------------------------------------------------------------------------

// TestClaimEmailSend_OneCycleOneEmail is the EMAIL-BUGBASH C4/C5 regression
// guard. The fix gates each transactional email on a successful
// ClaimEmailSend, so a single billing cycle yields exactly one email. This
// test proves the ledger contract directly: the first claim of a key wins
// (true), every subsequent claim of the SAME key loses (false). Fails before
// the fix because no dedup ledger existed — both Razorpay events would send.
func TestClaimEmailSend_OneCycleOneEmail(t *testing.T) {
	requireDBEmailEvents(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	ctx := context.Background()
	key := "receipt:sub_" + uuid.NewString() + ":paid:1"

	// First event of the cycle (subscription.activated) — claims, sends.
	first, err := models.ClaimEmailSend(ctx, db, key, models.EmailSendKindReceipt)
	require.NoError(t, err)
	assert.True(t, first, "first event of a billing cycle must claim the send")

	// Second event of the SAME cycle (subscription.charged) — must NOT send.
	second, err := models.ClaimEmailSend(ctx, db, key, models.EmailSendKindReceipt)
	require.NoError(t, err)
	assert.False(t, second, "C4/C5: second event of the same cycle must be deduped — one cycle = one email")

	// A redelivery of either event re-attempts the same key — still deduped.
	third, err := models.ClaimEmailSend(ctx, db, key, models.EmailSendKindReceipt)
	require.NoError(t, err)
	assert.False(t, third, "webhook redelivery must stay deduped")

	// A DIFFERENT cycle (next paid_count) is a fresh key — sends again.
	nextKey := "receipt:sub_" + uuid.NewString() + ":paid:2"
	nextCycle, err := models.ClaimEmailSend(ctx, db, nextKey, models.EmailSendKindReceipt)
	require.NoError(t, err)
	assert.True(t, nextCycle, "a genuinely distinct billing cycle must still send")
}

// TestClaimEmailSend_EmptyKeyAlwaysSends verifies the degrade path: an empty
// dedup key (no stable cycle anchor) falls back to always-send rather than
// claiming a colliding empty key.
func TestClaimEmailSend_EmptyKeyAlwaysSends(t *testing.T) {
	requireDBEmailEvents(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	a, err := models.ClaimEmailSend(context.Background(), db, "", models.EmailSendKindReceipt)
	require.NoError(t, err)
	assert.True(t, a)
	b, err := models.ClaimEmailSend(context.Background(), db, "   ", models.EmailSendKindReceipt)
	require.NoError(t, err)
	assert.True(t, b, "empty/blank key must never collapse unrelated sends")
}

// TestRecentAuditEventExists_F2 is the EMAIL-BUGBASH F2 regression guard for
// the admin-demote double-cancellation-email fix. handleSubscriptionCancelled
// calls RecentAuditEventExists before emitting its own cancellation audit
// row; a fresh subscription.canceled_by_admin row must be detected so the
// webhook path skips its (duplicate) email.
func TestRecentAuditEventExists_F2(t *testing.T) {
	requireDBEmailEvents(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	ctx := context.Background()
	teamID := seedTeam(t, db)

	// No admin-cancel row yet → false.
	exists, err := models.RecentAuditEventExists(ctx, db, teamID,
		models.AuditKindSubscriptionCanceledByAdmin, time.Hour)
	require.NoError(t, err)
	assert.False(t, exists, "no admin-cancel row → webhook path emits its own email")

	// Admin demotes the customer → subscription.canceled_by_admin row lands.
	require.NoError(t, models.InsertAuditEvent(ctx, db, models.AuditEvent{
		TeamID: teamID,
		Actor:  "admin",
		Kind:   models.AuditKindSubscriptionCanceledByAdmin,
		Summary: "admin canceled subscription on demote",
	}))

	// Now the webhook-path lookup must see it and skip the duplicate email.
	exists, err = models.RecentAuditEventExists(ctx, db, teamID,
		models.AuditKindSubscriptionCanceledByAdmin, time.Hour)
	require.NoError(t, err)
	assert.True(t, exists, "F2: fresh admin-cancel row must suppress the webhook-path cancellation email")

	// A different team is unaffected.
	otherTeam := seedTeam(t, db)
	exists, err = models.RecentAuditEventExists(ctx, db, otherTeam,
		models.AuditKindSubscriptionCanceledByAdmin, time.Hour)
	require.NoError(t, err)
	assert.False(t, exists, "F2 dedup must be scoped to the team")

	// A stale row (outside the window) must NOT match — backdate it.
	_, err = db.ExecContext(ctx,
		`UPDATE audit_log SET created_at = now() - interval '2 hours'
		  WHERE team_id = $1 AND kind = $2`,
		teamID, models.AuditKindSubscriptionCanceledByAdmin)
	require.NoError(t, err)
	exists, err = models.RecentAuditEventExists(ctx, db, teamID,
		models.AuditKindSubscriptionCanceledByAdmin, time.Hour)
	require.NoError(t, err)
	assert.False(t, exists, "an admin-cancel row older than the window must not suppress")
}

// TestSuppressionChecker_IsSuppressed is the EMAIL-BUGBASH C3 regression
// guard for the api-side suppression wiring: NewSuppressionChecker must
// report a hard-bounced address as suppressed (and a clean address as not),
// satisfying the email.SuppressionChecker contract the email Client consults
// before every send.
func TestSuppressionChecker_IsSuppressed(t *testing.T) {
	requireDBEmailEvents(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	ctx := context.Background()
	checker := models.NewSuppressionChecker(db)

	clean1 := uniqueEmail()
	ok, err := checker.IsSuppressed(ctx, clean1)
	require.NoError(t, err)
	assert.False(t, ok, "an address with no email_events row must not be suppressed")

	bounced := uniqueEmail()
	_, err = models.InsertEmailEvent(ctx, db,
		models.EmailEventProviderBrevo, models.EmailEventTypeBounce, bounced,
		"mailbox does not exist", json.RawMessage(`{"message_id":"msg-supchk-1"}`))
	require.NoError(t, err)

	ok, err = checker.IsSuppressed(ctx, bounced)
	require.NoError(t, err)
	assert.True(t, ok, "C3: a hard-bounced address must be reported suppressed so the api send path skips it")

	// A nil-DB checker degrades to never-suppress (test/bootstrap path).
	nilChecker := models.NewSuppressionChecker(nil)
	ok, err = nilChecker.IsSuppressed(ctx, bounced)
	require.NoError(t, err)
	assert.False(t, ok, "a nil-DB checker must never suppress")
}
