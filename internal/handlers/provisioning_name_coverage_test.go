package handlers

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestProvisioningEndpoints_AllUseRequireName — T14 P1-1 regression coverage.
//
// Bug: /vector/new bypassed mandatory naming because it called
// sanitizeNameForRequest (which permits an empty name + generates a
// default) instead of requireName (which rejects an empty name with
// 400 name_required). Seven other provisioning endpoints had already
// rolled to requireName during the Part-A naming feature — the 8th
// rolled silently.
//
// Coverage form (registry-iterating, per CLAUDE.md rule 18): scan every
// provisioning handler file and assert it contains exactly one
// requireName(c, ...) call and zero sanitizeNameForRequest(c, ...)
// calls on the *new-resource path*. The latter helper still exists for
// other endpoints (twin redeploys, family bulk-twin etc.) so the test
// only asserts the new-resource entry point uses requireName.
//
// The list below IS the registry — if a new /xxx/new endpoint lands,
// add the file here. Forgetting is the bug class this test catches.
func TestProvisioningEndpoints_AllUseRequireName(t *testing.T) {
	t.Parallel()

	files := map[string]struct {
		// Must contain a requireName(c, ...) call on the new-resource
		// entry point.
		wantRequireName bool
		// Must NOT call sanitizeNameForRequest(c, ...) at the
		// top of the request handler — the new-resource entry point
		// must be the strict requireName variant.
		bannedHelpers []string
	}{
		"db.go":      {wantRequireName: true, bannedHelpers: []string{"sanitizeNameForRequest"}},
		"cache.go":   {wantRequireName: true, bannedHelpers: []string{"sanitizeNameForRequest"}},
		"nosql.go":   {wantRequireName: true, bannedHelpers: []string{"sanitizeNameForRequest"}},
		"queue.go":   {wantRequireName: true, bannedHelpers: []string{"sanitizeNameForRequest"}},
		"storage.go": {wantRequireName: true, bannedHelpers: []string{"sanitizeNameForRequest"}},
		"webhook.go": {wantRequireName: true, bannedHelpers: []string{"sanitizeNameForRequest"}},
		"vector.go":  {wantRequireName: true, bannedHelpers: []string{"sanitizeNameForRequest"}},
		// deploy.go uses requireName too (with the renamed rawName var).
		"deploy.go": {wantRequireName: true, bannedHelpers: nil},
	}

	reqNameRE := regexp.MustCompile(`\brequireName\(c, [^)]*\)`)

	for fname, want := range files {
		path := filepath.Join(".", fname)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("%s: %v", fname, err)
			continue
		}
		src := string(b)
		if want.wantRequireName && !reqNameRE.MatchString(src) {
			t.Errorf("%s: missing requireName(c, ...) call — provisioning endpoints MUST enforce mandatory naming. See T14 P1-1 (BugHunt 2026-05-20).", fname)
		}
		for _, banned := range want.bannedHelpers {
			// Banned helper must not appear on a line that also contains
			// "c, body.Name" or "c, rawName" — those are the request-entry
			// usages. Helpers used in other (twin / bulk) flows are OK.
			pat := regexp.MustCompile(`\b` + regexp.QuoteMeta(banned) + `\(c, (body\.Name|rawName)\)`)
			if pat.MatchString(src) {
				t.Errorf("%s: new-resource entry point uses %s(...) — must use requireName(...) instead. See T14 P1-1.", fname, banned)
			}
		}
	}

	// Sanity check: the registry must be non-empty (catches accidentally
	// deleting all entries).
	if len(files) < 7 {
		t.Fatalf("registry has only %d entries — at least 7 /*/new endpoints exist; refusing to silently shrink coverage", len(files))
	}

	_ = strings.TrimSpace // suppress unused import if regexp removed
}
