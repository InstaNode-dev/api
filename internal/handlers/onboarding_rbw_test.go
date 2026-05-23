package handlers_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/testhelpers"
)

// TestIsValidEmail covers every rejection arm + the accept path.
func TestIsValidEmail(t *testing.T) {
	valid := []string{"you@example.com", "a.b+c@sub.example.co.uk", "x@y.z"}
	for _, s := range valid {
		require.True(t, handlers.IsValidEmailForTest(s), "should accept %q", s)
	}
	invalid := map[string]string{
		"empty":            "",
		"inner_space":      "you @example.com",
		"inner_tab":        "you\t@example.com",
		"display_form":     "Name <you@example.com>",
		"angle_no_space":   "<you@example.com>", // parses but addr != input
		"no_at":            "notanemail",
		"dotless_domain":   "user@localhost",
		"trailing_dot":     "user@example.com.",
		"leading_dot_dom":  "user@.example.com",
		"empty_local":      "@example.com",
		"too_long":         string(make([]byte, 255)) + "@x.com",
	}
	for name, s := range invalid {
		require.False(t, handlers.IsValidEmailForTest(s), "should reject %s (%q)", name, s)
	}
}

// TestMaskEmailForLog covers the masked path + the no-@ fallback.
func TestMaskEmailForLog(t *testing.T) {
	require.Equal(t, "y***@example.com", handlers.MaskEmailForLogForTest("you@example.com"))
	require.Equal(t, "***", handlers.MaskEmailForLogForTest("no-at-sign"))
	require.Equal(t, "***", handlers.MaskEmailForLogForTest("@leadingat.com")) // at index 0 → fallback
}

// TestEmitOnboardingClaimedAudit covers the insert-success path (real user) +
// the warn arm (closed DB), plus the userID==Nil branch of the NullUUID.
func TestEmitOnboardingClaimedAudit(t *testing.T) {
	db, cleanup := testhelpers.SetupTestDB(t)
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	// success: valid user UUID
	handlers.EmitOnboardingClaimedAuditForTest(db, teamID, uuid.New(), 3, "a@b.com")
	// userID == Nil → NullUUID Valid=false branch
	handlers.EmitOnboardingClaimedAuditForTest(db, teamID, uuid.Nil, 0, "c@d.com")
	// warn arm: closed DB
	cleanup()
	handlers.EmitOnboardingClaimedAuditForTest(db, teamID, uuid.New(), 1, "e@f.com")
}

// TestSendClaimVerificationEmail covers nil-mailer no-op, empty-email no-op,
// the send-success path, and the send-failure warn arm.
func TestSendClaimVerificationEmail(t *testing.T) {
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()

	// nil mailer → no-op
	handlers.SendClaimVerificationEmailForTest(db, nil, "x@y.com", "/dash")

	// empty email after normalize → no-op
	m0 := &handlers.ClaimMailerForTest{}
	handlers.SendClaimVerificationEmailForTest(db, m0, "   ", "/dash")
	require.False(t, m0.Called, "empty email must not send")

	// success
	m1 := &handlers.ClaimMailerForTest{}
	handlers.SendClaimVerificationEmailForTest(db, m1, "ok@example.com", "/dash")
	require.True(t, m1.Called, "valid email should attempt send")

	// send-failure warn arm
	m2 := &handlers.ClaimMailerForTest{Err: assertErr{}}
	handlers.SendClaimVerificationEmailForTest(db, m2, "fail@example.com", "/dash")
	require.True(t, m2.Called)
}

// TestSendClaimVerificationEmail_CreateLinkError covers the CreateMagicLink
// failure arm (closed DB → no send attempt).
func TestSendClaimVerificationEmail_CreateLinkError(t *testing.T) {
	db, cleanup := testhelpers.SetupTestDB(t)
	cleanup() // closed pool → CreateMagicLink errors
	m := &handlers.ClaimMailerForTest{}
	handlers.SendClaimVerificationEmailForTest(db, m, "x@example.com", "/dash")
	require.False(t, m.Called, "must not send when magic-link creation fails")
}

type assertErr struct{}

func (assertErr) Error() string { return "send boom" }
