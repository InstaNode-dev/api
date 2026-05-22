package handlers

// export_test.go — test-only exports of unexported symbols so external
// (handlers_test) tests can exercise package internals without making the
// surface area public. Go automatically only includes this file in test
// builds (file name suffix `_test.go`).

import (
	"context"
	"database/sql"

	"github.com/google/uuid"

	"instant.dev/internal/config"
	"instant.dev/internal/models"
)

// PersistMagicLinkSendStatusForTest re-exports the unexported
// persistMagicLinkSendStatus helper so the external handlers_test package can
// drive its two error branches (MarkMagicLinkSendFailed / MarkMagicLinkSent
// failure) against an isolated DB without an import cycle. The helper logs +
// swallows on failure (the user-visible 202 is unchanged), so a direct call is
// the only way to reach those branches.
func PersistMagicLinkSendStatusForTest(ctx context.Context, db *sql.DB, id uuid.UUID, sendErr error, requestID string) {
	persistMagicLinkSendStatus(ctx, db, id, sendErr, requestID)
}

// ErrProvisionPersistFailedForTest re-exports the persistence-failure sentinel
// for MR-P0-3 regression tests.
var ErrProvisionPersistFailedForTest = errProvisionPersistFailed

// RunFinalizeProvisionForTest invokes the unexported finalizeProvision helper
// with the supplied dependencies. Used by the MR-P0-3 regression test to
// assert that a persistence failure runs cleanup, soft-deletes the row, and
// returns the sentinel error — without making finalizeProvision part of the
// package's public surface.
func RunFinalizeProvisionForTest(
	ctx context.Context,
	dbConn *sql.DB,
	cfg *config.Config,
	res *models.Resource,
	connectionURL, keyPrefix, providerResourceID, requestID, logPrefix string,
	cleanup func(),
) error {
	helper := provisionHelper{db: dbConn, cfg: cfg}
	return helper.finalizeProvision(ctx, res, connectionURL, keyPrefix, providerResourceID, requestID, logPrefix, cleanup)
}

// CodeToAgentActionMetaForTest is a read-only mirror of the package's
// errorCodeMeta exposed for MR-P0-3 coverage tests. Mirrored as a separate
// type (not a type-alias) to keep the unexported errorCodeMeta out of the
// public surface — tests only need the two visible fields.
type CodeToAgentActionMetaForTest struct {
	AgentAction string
	UpgradeURL  string
}

// LookupCodeToAgentActionForTest returns the registered agent_action metadata
// for `code`, or (zero, false) when the code has no entry. Mirrors the
// lookup respondError itself performs, so the test exercises exactly the
// same branch as the production envelope-emit path.
func LookupCodeToAgentActionForTest(code string) (CodeToAgentActionMetaForTest, bool) {
	meta, ok := codeToAgentAction[code]
	if !ok {
		return CodeToAgentActionMetaForTest{}, false
	}
	return CodeToAgentActionMetaForTest{
		AgentAction: meta.AgentAction,
		UpgradeURL:  meta.UpgradeURL,
	}, true
}

// VerifyRazorpayTimestampForTest re-exports the unexported timestamp-window
// predicate for the SRR security-cluster H46-F3 regression tests. Pure
// function (no I/O), so a unit test can lock in the boundary semantics
// without spinning up the HTTP app. Returns (rejected, ageSeconds).
func VerifyRazorpayTimestampForTest(createdAt, nowUnix int64) (bool, int64) {
	return verifyRazorpayTimestamp(createdAt, nowUnix)
}

// RazorpayTimestampWindowForTest re-exports the window constant so a
// test that wants to compute "boundary-1 / boundary / boundary+1" stays
// in sync with the production value automatically.
const RazorpayTimestampWindowForTest = razorpayTimestampWindow

// SetOAuthURLsForTest repoints the package-level OAuth provider endpoint vars
// at a test server (httptest.Server.URL + per-endpoint suffixes) so the
// external handlers_test package can drive the full OAuth exchange path
// without hitting the real github.com / accounts.google.com. Returns a restore
// func the caller defers. base="" restores nothing and is a no-op guard.
func SetOAuthURLsForTest(base string) (restore func()) {
	prev := []*string{
		&githubTokenURL, &githubUserURL, &githubUserEmailURL,
		&googleTokenInfoURL, &googleTokenURL, &googleUserInfoURL,
	}
	saved := make([]string, len(prev))
	for i, p := range prev {
		saved[i] = *p
	}
	githubTokenURL = base + "/gh/token"
	githubUserURL = base + "/gh/user"
	githubUserEmailURL = base + "/gh/emails"
	googleTokenInfoURL = base + "/g/tokeninfo"
	googleTokenURL = base + "/g/token"
	googleUserInfoURL = base + "/g/userinfo"
	return func() {
		for i, p := range prev {
			*p = saved[i]
		}
	}
}
