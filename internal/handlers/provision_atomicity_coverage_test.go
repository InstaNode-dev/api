package handlers_test

// provision_atomicity_coverage_test.go — MR-P0-3 cross-handler coverage guard
// (BugBash 2026-05-20).
//
// CLAUDE.md rule 18: when the bug class is "all members of a registry should
// X", the regression test iterates the live registry (here: every .go file in
// internal/handlers/ that calls models.CreateResource), not a hand-typed
// slice. This test scans the handlers directory and asserts that every
// production-code `models.CreateResource(` call site lives in a file that
// also contains a `finalizeProvision(` call. The orphan-generator bug fixed
// by MR-P0-3 was exactly this: a handler that inserted a `resources` row,
// did the backend gRPC, and persisted the connection URL inline with `// fail
// open` comments — a logged error and a 201 carrying credentials for a row
// the platform could not address. Catching a new handler that re-introduces
// that shape at test time (not in prod) is the whole point.
//
// The test is intentionally STATIC (string scan over source files), not a
// reflection-based registry walk: there is no in-memory "provisioning
// handler" registry the platform exposes today, so a string scan over the
// canonical authorial source is the cheapest way to enforce the invariant.
// Per CLAUDE.md convention, this is a "registry-iterating" test even though
// the registry happens to be the source tree itself: it discovers call sites
// dynamically rather than encoding them in a hand-typed list that would
// itself drift.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
)

// handlersDir is the package path under audit. The test runs from
// internal/handlers/ (test files live alongside production code), so the
// relative path is "." — but we resolve absolutely so the test fails clearly
// if invoked from an unexpected CWD.
func handlersDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	// Sanity: we expect to be inside internal/handlers/.
	if !strings.HasSuffix(wd, "internal/handlers") {
		t.Fatalf("expected CWD to end with internal/handlers, got %q", wd)
	}
	return wd
}

// productionGoFile returns true for a .go file that is part of the production
// build (i.e. NOT a *_test.go file and NOT a tooling file).
func productionGoFile(name string) bool {
	if !strings.HasSuffix(name, ".go") {
		return false
	}
	if strings.HasSuffix(name, "_test.go") {
		return false
	}
	return true
}

// TestEveryCreateResourceCallSiteIsFollowedByFinalizeProvision is the MR-P0-3
// cross-handler coverage guard. For every production handler file that calls
// `models.CreateResource(`, the file MUST also contain a `finalizeProvision(`
// call. (We deliberately check at file granularity, not exact-line proximity:
// some handlers split create + finalize across helper functions, and the
// file-level pairing is the correct enforcement scope — a CreateResource in
// db.go without ANY finalizeProvision in db.go is the bug. A finalizeProvision
// somewhere in db.go for a CreateResource somewhere in db.go is acceptable
// because they cluster by service.)
//
// Allow-listed files: a small set of CreateResource callers that are NOT
// provisioning entry points and therefore do not require finalizeProvision:
//   - test files (filtered above)
//   - none in production today — every CreateResource caller IS a provisioning
//     handler. The allow-list map is present so future intentional exemptions
//     can be added with an explanatory comment.
func TestEveryCreateResourceCallSiteIsFollowedByFinalizeProvision(t *testing.T) {
	dir := handlersDir(t)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	// Files that legitimately call models.CreateResource WITHOUT
	// finalizeProvision. Empty today — add an entry only with a justifying
	// comment naming the alternate persistence path the file uses. Any new
	// entry here is a code-review trigger by itself.
	allowList := map[string]string{}

	type violation struct {
		file   string
		reason string
	}
	var violations []violation

	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		if !productionGoFile(ent.Name()) {
			continue
		}

		path := filepath.Join(dir, ent.Name())
		body, err := os.ReadFile(path)
		require.NoError(t, err)
		src := string(body)

		// Strip line comments before searching so commented-out CreateResource
		// references in long file-header notes don't trip the test. (Block
		// comments are rare and not used in this codebase to discuss
		// CreateResource by name; a future change could swap to go/parser
		// for full fidelity.)
		stripped := stripLineComments(src)

		hasCreate := strings.Contains(stripped, "models.CreateResource(")
		if !hasCreate {
			continue
		}

		if _, ok := allowList[ent.Name()]; ok {
			continue
		}

		hasFinalize := strings.Contains(stripped, "finalizeProvision(")
		if !hasFinalize {
			violations = append(violations, violation{
				file: ent.Name(),
				reason: "calls models.CreateResource but does NOT call finalizeProvision — " +
					"this is the MR-P0-3 orphan-generator shape (insert row, downstream " +
					"provision, return 201 without atomically persisting credentials). Wire " +
					"the path through h.finalizeProvision so a persistence failure tears down " +
					"the backend and returns 503, never 201.",
			})
		}
	}

	if len(violations) > 0 {
		var msg strings.Builder
		msg.WriteString("MR-P0-3 atomic-provisioning coverage failed.\n")
		msg.WriteString("Every handler file that calls models.CreateResource MUST also call ")
		msg.WriteString("finalizeProvision (see internal/handlers/provision_helper.go).\n\n")
		msg.WriteString("Violations:\n")
		for _, v := range violations {
			msg.WriteString("  - ")
			msg.WriteString(v.file)
			msg.WriteString(": ")
			msg.WriteString(v.reason)
			msg.WriteString("\n")
		}
		t.Fatal(msg.String())
	}
}

// TestEveryFinalizeProvisionCallSiteRespondsProvisionFailedOnError is the
// second-half guard: the value of finalizeProvision is in its 503-on-failure
// semantic, so the handler MUST translate a non-nil return into a 503 via
// respondProvisionFailed (or a domain-specific 5xx that maps to the same
// shape). A handler that calls finalizeProvision but then ignores the error
// would re-introduce the bug from the other side. We check at file level:
// every file calling finalizeProvision MUST also reference
// respondProvisionFailed or an equivalent error handler (twinCoreErr in the
// bulk-twin path).
func TestEveryFinalizeProvisionCallSiteRespondsProvisionFailedOnError(t *testing.T) {
	dir := handlersDir(t)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	// Acceptable downstream-error handlers — any file calling finalizeProvision
	// must also reference at least one of these by name (string-grep). The set
	// is intentionally small: every production caller funnels through one of
	// them.
	acceptableHandlers := []string{
		"respondProvisionFailed", // canonical 503 envelope
		"twinCoreErr",            // bulk-twin handler — returns string err
	}

	type violation struct {
		file   string
		reason string
	}
	var violations []violation

	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		if !productionGoFile(ent.Name()) {
			continue
		}
		// The helper itself defines finalizeProvision; skip.
		if ent.Name() == "provision_helper.go" {
			continue
		}

		path := filepath.Join(dir, ent.Name())
		body, err := os.ReadFile(path)
		require.NoError(t, err)
		src := stripLineComments(string(body))

		if !strings.Contains(src, "finalizeProvision(") {
			continue
		}

		found := false
		for _, h := range acceptableHandlers {
			if strings.Contains(src, h) {
				found = true
				break
			}
		}
		if !found {
			violations = append(violations, violation{
				file:   ent.Name(),
				reason: "calls finalizeProvision but does NOT route the error through respondProvisionFailed or twinCoreErr — a swallowed persistence error is the MR-P0-3 bug in reverse.",
			})
		}
	}

	if len(violations) > 0 {
		var msg strings.Builder
		msg.WriteString("MR-P0-3 503-response coverage failed.\n")
		for _, v := range violations {
			msg.WriteString("  - ")
			msg.WriteString(v.file)
			msg.WriteString(": ")
			msg.WriteString(v.reason)
			msg.WriteString("\n")
		}
		t.Fatal(msg.String())
	}
}

// stripLineComments removes `// …` line comments from Go source so the test
// search ignores commented-out code (file-header docs, deprecated examples)
// that mention CreateResource / finalizeProvision but do not call them.
func stripLineComments(src string) string {
	// Simple line-by-line strip — fine for our test which only does
	// substring containment, not AST analysis. The regexp is conservative:
	// it does NOT strip // inside double-quoted strings, which Go source
	// only rarely contains for this token set; the codebase's
	// `models.CreateResource(` reference in a string literal would be
	// notable on its own.
	re := regexp.MustCompile(`(?m)^[\t ]*//.*$`)
	return re.ReplaceAllString(src, "")
}

// TestProvisionFailedHasAgentAction asserts that the catch-all
// `provision_failed` code returned by respondProvisionFailed carries an
// explicit agent_action — not the AgentActionContactSupport fallback. The
// MR-P0-3 path returns 503 with code=provision_failed; for callers (CLI, MCP,
// dashboard, Claude Code) to do the right thing the body must include the
// "retry with exponential backoff" sentence.
func TestProvisionFailedHasAgentAction(t *testing.T) {
	meta, ok := handlers.LookupCodeToAgentActionForTest("provision_failed")
	require.True(t, ok,
		"provision_failed MUST have an entry in codeToAgentAction so MR-P0-3 503s do not fall back to AgentActionContactSupport")
	assert.NotEmpty(t, meta.AgentAction,
		"provision_failed agent_action MUST be non-empty")
	// Spot-check the U3 contract: "Tell the user" opening + a real URL.
	assert.Contains(t, meta.AgentAction, "Tell the user",
		"provision_failed agent_action must open with 'Tell the user' per U3 contract")
	assert.Contains(t, meta.AgentAction, "https://instanode.dev",
		"provision_failed agent_action must contain a full https://instanode.dev URL per U3 contract")
	// Spot-check the retry guidance — the MR-P0-3 path's contract is
	// "retry with backoff," not "email support."
	assert.True(t,
		strings.Contains(meta.AgentAction, "Retry") || strings.Contains(meta.AgentAction, "backoff"),
		"provision_failed agent_action must instruct the agent to retry (with backoff), not contact support — backend object was rolled back")
}
