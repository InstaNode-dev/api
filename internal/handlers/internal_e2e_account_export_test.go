package handlers

// internal_e2e_account_export_test.go — white-box seams for the external
// internal_e2e_account_*_test.go coverage suite (package handlers_test).

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// E2EAllowedTiersForTest exposes the closed set of tiers the mint accepts so a
// registry-iterating test (rule 18) can assert every allowed tier round-trips
// without re-typing the list — a hand-typed slice would itself be a single-site
// fallacy. Returns a copy so a test cannot mutate the handler's source of truth.
func E2EAllowedTiersForTest() []string {
	out := make([]string, 0, len(e2eAllowedTiers))
	for tier := range e2eAllowedTiers {
		out = append(out, tier)
	}
	return out
}

// E2EBlockedTiersForTest exposes the explicitly-rejected (gated) tiers so a
// registry-iterating test asserts each one 400s with tier_not_allowed.
func E2EBlockedTiersForTest() []string {
	out := make([]string, 0, len(e2eBlockedTiers))
	for tier := range e2eBlockedTiers {
		out = append(out, tier)
	}
	return out
}

// E2ESeedResourceTypesForTest exposes the with_resources seed set so the seed
// test asserts exactly the resource types the handler creates — iterated, not
// hand-listed, so adding a seed type auto-expands the assertion.
func E2ESeedResourceTypesForTest() []string {
	out := make([]string, len(e2eSeedResourceTypes))
	copy(out, e2eSeedResourceTypes)
	return out
}

// SetE2ESeedFastResourcesForTest overrides the e2eSeedFastResources seam so a
// test can force CreateAccount's seed_failed (503) arm deterministically,
// without making the real resources table reject an insert mid-request.
// Returns a restore func.
func SetE2ESeedFastResourcesForTest(err error) (restore func()) {
	prev := e2eSeedFastResources
	e2eSeedFastResources = func(_ *E2EAccountHandler, _ context.Context, _ uuid.UUID, _, _ string) ([]string, error) {
		return nil, err
	}
	return func() { e2eSeedFastResources = prev }
}

// SetE2ESignSessionJWTForTest overrides the e2eSignSessionJWT seam so a test
// can force the token_issue_failed (503) arm of CreateAccount. Returns a
// restore func. HS256-over-[]byte never errors in practice, so this seam is
// the only way to deterministically exercise that defensive branch.
func SetE2ESignSessionJWTForTest(fn func(jwtSecret string, userID, teamID uuid.UUID, email string, expiresAt time.Time) (string, error)) (restore func()) {
	prev := e2eSignSessionJWT
	e2eSignSessionJWT = fn
	return func() { e2eSignSessionJWT = prev }
}

// SetE2ESeedFailedDeployForTest overrides the e2eSeedFailedDeploy seam so a
// test can force CreateAccount's with_failed_deploy seed_failed (503) arm
// deterministically, without making the real deployments table reject an
// insert mid-request. Returns a restore func.
func SetE2ESeedFailedDeployForTest(err error) (restore func()) {
	prev := e2eSeedFailedDeploy
	e2eSeedFailedDeploy = func(_ *E2EAccountHandler, _ context.Context, _ uuid.UUID, _, _ string) (string, error) {
		return "", err
	}
	return func() { e2eSeedFailedDeploy = prev }
}

// E2EFailedDeploySeedForTest exposes the seeded failed-deploy autopsy payload
// so the seed test asserts the API serves exactly what the factory wrote
// (reason/exit_code/last_lines/hint) — single source of truth, not a re-typed
// expectation. Returns copies so a test cannot mutate the handler's constants.
func E2EFailedDeploySeedForTest() (errorMessage, reason, event, hint string, exitCode int, lastLines []string) {
	ll := make([]string, len(e2eFailedDeployLastLines))
	copy(ll, e2eFailedDeployLastLines)
	return e2eFailedDeployErrorMessage, e2eFailedDeployReason, e2eFailedDeployEvent,
		e2eFailedDeployHint, e2eFailedDeployExitCode, ll
}
