package handlers

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestProvisionForTwin_NoDSNLeak — T12 P1-1 regression coverage.
//
// Bug: db.go / cache.go / nosql.go twin paths used
//
//	return respondProvisionFailed(c, err, err.Error())
//
// which echoes the raw provisioner error into the response body. For the
// shared-backend providers the provisioner error wraps the admin DSN
// (e.g. "dial postgres://instant_root:<adminpw>@…"), so a single failed
// twin provision leaked the master admin password to the caller.
//
// Coverage form (registry-iterating, per CLAUDE.md rule 18): scan every
// provisioning handler source file in this package and assert *none* of
// them call respondProvisionFailed(..., err.Error()). The non-twin paths
// already use static messages — this guard makes sure no future edit
// regresses any of them back to err.Error().
func TestProvisionForTwin_NoDSNLeak(t *testing.T) {
	t.Parallel()

	// Files in this package that own a /xxx/new (or twin) provisioning
	// handler. Hard-coded list — if a new provisioning file lands, add it
	// here. Keeping the list explicit is safer than globbing because
	// non-provisioning handlers (admin, audit, billing) can legitimately
	// echo upstream error text.
	files := []string{
		"db.go",
		"cache.go",
		"nosql.go",
		"queue.go",
		"storage.go",
		"vector.go",
		"webhook.go",
	}

	// Match `respondProvisionFailed(... , err.Error())` (any whitespace,
	// any first/second arg). The pattern is *.Error() not just err.Error()
	// because the caller variable might be `finErr`, `provErr`, etc.
	leakRE := regexp.MustCompile(`respondProvisionFailed\([^)]*\.Error\(\)\s*\)`)

	for _, f := range files {
		path := filepath.Join(".", f)
		b, err := os.ReadFile(path)
		if err != nil {
			// Tolerate missing files (e.g. vector.go absent in some
			// historical commits) — coverage of the files that *do*
			// exist is the contract.
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("read %s: %v", f, err)
		}
		src := string(b)
		matches := leakRE.FindAllString(src, -1)
		if len(matches) > 0 {
			t.Errorf("DSN leak: %s calls respondProvisionFailed with err.Error() (%d site(s)):\n  %s\n"+
				"\nUse a static message instead — see T12 P1-1 (BugHunt 2026-05-20).",
				f, len(matches), strings.Join(matches, "\n  "))
		}
	}
}
