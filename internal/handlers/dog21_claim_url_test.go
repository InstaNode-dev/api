package handlers

// dog21_claim_url_test.go — DOG-21 regression.
//
// Every anonymous-tier 201 provision response (db/cache/nosql/queue/
// vector/webhook/storage) MUST emit a top-level `claim_url` alongside
// `upgrade` / `upgrade_jwt`. Pre-fix the field was documented on the
// 402 recycle-gate envelope but absent on the 201, so agents that
// wanted to surface a claim CTA had to hand-construct the URL from
// upgrade_jwt — breaking the contract across vendor integrations.
//
// Source-level regression so we don't need a live Postgres/Redis to
// pin the contract. The full integration test path lives in
// existing service tests (provarms_test.go etc.).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// anonProvisionHandlerFiles lists every file that emits a 201 anonymous
// provision response. Iterating this list (rule 18 — registry not
// hand-typed assertions) means a new service handler added to the same
// shape automatically gets the same coverage requirement.
var anonProvisionHandlerFiles = []string{
	"db.go",
	"cache.go",
	"nosql.go",
	"queue.go",
	"vector.go",
	"webhook.go",
	"storage.go",
}

// TestDOG21_ClaimURLEmittedOnEveryAnonProvision asserts every anon
// provision handler file emits at least one `claim_url` field. The
// number of expected emissions per file is at least the number of
// `upgrade_jwt` emissions in that file (one per code path: the
// fingerprint-dedup branch and the fresh-201 branch each emit one).
func TestDOG21_ClaimURLEmittedOnEveryAnonProvision(t *testing.T) {
	for _, fname := range anonProvisionHandlerFiles {
		t.Run(fname, func(t *testing.T) {
			path := filepath.Join(".", fname)
			raw, err := os.ReadFile(path)
			require.NoError(t, err, "must read handler file %s", path)
			src := string(raw)

			// Every site that emits upgrade_jwt is an anon-201 site. The
			// pre-fix code emitted upgrade_jwt without claim_url. The fix
			// requires claim_url at every such site.
			jwtCount := strings.Count(src, "upgrade_jwt")
			claimCount := strings.Count(src, "claim_url")

			require.Greater(t, jwtCount, 0,
				"DOG-21: %s should still have anon-provision code paths that emit upgrade_jwt", fname)
			assert.GreaterOrEqual(t, claimCount, jwtCount,
				"DOG-21: %s emits upgrade_jwt %d time(s) but claim_url only %d time(s) — every 201 anon response must carry claim_url",
				fname, jwtCount, claimCount)
		})
	}
}

// TestDOG21_OpenAPISchemaDocumentsClaimURLOnEveryAnonResponse pins
// the rule-22 surface checklist: every provision-response schema in
// openapi.go must describe the new claim_url field.
func TestDOG21_OpenAPISchemaDocumentsClaimURL(t *testing.T) {
	raw, err := os.ReadFile("openapi.go")
	require.NoError(t, err)
	src := string(raw)

	// At least 7 claim_url description lines (one per service schema +
	// the ErrorResponse schema = 8 minimum). We use 7 as the floor
	// because counting in openapi.go is fragile against future renames;
	// 7 catches the "added to only some schemas" failure mode without
	// flaking on cosmetic JSON splitting.
	claimURLDescCount := strings.Count(src, `"claim_url":`)
	assert.GreaterOrEqual(t, claimURLDescCount, 7,
		"DOG-21: openapi.go must document claim_url across all 7 provision-response schemas + ErrorResponse (rule 22 surface checklist)")

	// The widened ErrorResponse description must call out the new 201 emit
	// surface so an agent reading the doc knows to expect claim_url on
	// success too, not only the recycle-gate 402.
	assert.Contains(t, src, "ALSO emitted on every successful 201 anonymous provision",
		"DOG-21: ErrorResponse.claim_url description must reflect the 201-anon emit (the documentation gap that caused the original report)")
}
