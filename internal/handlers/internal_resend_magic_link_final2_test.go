package handlers_test

// internal_resend_magic_link_final2_test.go — FINAL SERIAL PASS #2 coverage for
// the DB-error arms of internal_resend_magic_link.go the existing coverage
// suite leaves uncovered:
//
//   * GetMagicLinkByID non-NotFound error → db_failed         (L127-132, failAfter=0)
//   * UpdateMagicLinkTokenHash error      → db_failed          (L174-181, failAfter=1)
//   * MarkMagicLinkSendFailed error + attempts lookup error    (L195-209, failAfter=2 + failing mailer)
//   * MarkMagicLinkSendAbandoned error    (best-effort)         (L211-217, seeded at cap + failing mailer + failAfter)
//
// Reuses the existing resendMLTestApp / mintResendMLJWT / seedMagicLink /
// resendMLPost / fakeMagicLinkMailer / testResendMagicLinkSecret seams +
// openFaultDB. Magic links are seeded on the pooled DB; the handler runs on a
// fault DB sharing the same postgres so the targeted later query errors.

import (
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

func resendNeedDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
}

// GetMagicLinkByID errors (closed DB) → db_failed 503 (not magic_link_not_found).
func TestResendMLFinal2_LookupDBError(t *testing.T) {
	resendNeedDB(t)
	faultDB := openFaultDB(t, 0)
	app := resendMLTestApp(t, faultDB, testResendMagicLinkSecret, &fakeMagicLinkMailer{})
	linkID := uuid.NewString()
	jwt := mintResendMLJWT(t, testResendMagicLinkSecret, "resend_magic_link", linkID, 0)
	resp := resendMLPost(t, app, jwt, linkID)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// UpdateMagicLinkTokenHash errors → db_failed 503. failAfter=1: GetMagicLinkByID
// ok, the token-hash UPDATE errors.
func TestResendMLFinal2_UpdateHashError(t *testing.T) {
	resendNeedDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	linkID := seedMagicLink(t, seedDB, time.Now().Add(time.Hour), 0)

	faultDB := openFaultDB(t, 1)
	app := resendMLTestApp(t, faultDB, testResendMagicLinkSecret, &fakeMagicLinkMailer{})
	jwt := mintResendMLJWT(t, testResendMagicLinkSecret, "resend_magic_link", linkID, 0)
	resp := resendMLPost(t, app, jwt, linkID)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// Send fails AND the post-failure DB calls (MarkMagicLinkSendFailed,
// readMagicLinkAttempts) also error. failAfter=2: GetMagicLinkByID(1) +
// UpdateMagicLinkTokenHash(2) ok, MarkMagicLinkSendFailed(3) errors →
// mark_failed_failed log; readMagicLinkAttempts(4) errors → attempts_lookup
// log; freshAttempts=0 < cap → send_failed retry response (still 200).
func TestResendMLFinal2_MarkFailedAndAttemptsError(t *testing.T) {
	resendNeedDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	linkID := seedMagicLink(t, seedDB, time.Now().Add(time.Hour), 0)

	faultDB := openFaultDB(t, 2)
	app := resendMLTestApp(t, faultDB, testResendMagicLinkSecret,
		&fakeMagicLinkMailer{err: errors.New("smtp down")})
	jwt := mintResendMLJWT(t, testResendMagicLinkSecret, "resend_magic_link", linkID, 0)
	resp := resendMLPost(t, app, jwt, linkID)
	defer resp.Body.Close()
	// The post-send DB failures are best-effort/logged; the request still
	// returns 200 with status=failed (retry).
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// Send fails on a link already AT the attempt cap; the abandon-mark DB call
// errors. Seed attempts = cap so MarkMagicLinkSendFailed bumps it past the cap;
// failAfter chosen so MarkMagicLinkSendAbandoned(5) errors (best-effort →
// abandoned 200). team-less internal handler so no rate-limit interference.
func TestResendMLFinal2_MarkAbandonedError(t *testing.T) {
	resendNeedDB(t)
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	// Seed with attempts already at cap so the next failed send abandons.
	linkID := seedMagicLink(t, seedDB, time.Now().Add(time.Hour), 3)

	// GetMagicLinkByID(1)+UpdateHash(2)+MarkSendFailed(3)+readAttempts(4) ok,
	// MarkMagicLinkSendAbandoned(5) errors.
	faultDB := openFaultDB(t, 4)
	app := resendMLTestApp(t, faultDB, testResendMagicLinkSecret,
		&fakeMagicLinkMailer{err: errors.New("smtp down")})
	jwt := mintResendMLJWT(t, testResendMagicLinkSecret, "resend_magic_link", linkID, 0)
	resp := resendMLPost(t, app, jwt, linkID)
	defer resp.Body.Close()
	// abandon-mark failure is best-effort → still 200.
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
