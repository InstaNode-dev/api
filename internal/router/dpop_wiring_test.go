package router_test

// dpop_wiring_test.go — pins the W9 audit decision that the RequireDPoP
// middleware is installed in BOTH the /api/v1 auth-gated group AND the
// /deploy auth-gated group. The middleware itself is exhaustively
// covered in internal/middleware/dpop_test.go — what this file guards
// is the wiring: a future refactor that drops the middleware from the
// router would silently regress every key-bound bearer to bearer-only
// auth, defeating sender-binding entirely.
//
// We grep the router source rather than instantiating the real router
// (which needs Postgres + Redis + gRPC + email — all out of scope for a
// unit test). This is the same pattern admin_path_prefix_test.go uses
// to guard the admin-prefix branch.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDPoP_WiredIntoAPIGroup(t *testing.T) {
	// Find router.go relative to this test file. Walk up until we find
	// the file (handles `go test ./...` from repo root as well as from
	// the package directory).
	source := readRouterSource(t)

	// /api/v1 group MUST include RequireDPoP between PopulateTeamRole
	// and RequireWritable. The exact wording matters because the test
	// is the contract — drop the line and the test fails loudly.
	if !strings.Contains(source, `api := app.Group("/api/v1",`) {
		t.Fatal("router.go no longer registers the /api/v1 group with the multi-line builder pattern this test relies on")
	}
	apiGroupStart := strings.Index(source, `api := app.Group("/api/v1",`)
	apiGroupBlock := extractGroupBlock(source[apiGroupStart:])
	if apiGroupBlock == "" {
		t.Fatal("router.go: could not find closing paren of /api/v1 group declaration")
	}
	if !strings.Contains(apiGroupBlock, "middleware.RequireDPoP(rdb)") {
		t.Errorf("router.go: /api/v1 group MUST install middleware.RequireDPoP(rdb); group block was:\n%s", apiGroupBlock)
	}
}

// extractGroupBlock returns the substring from `app.Group(` through its
// matching closing paren, tracking nesting depth so the inner middleware
// calls don't terminate the scan early.
func extractGroupBlock(s string) string {
	open := strings.Index(s, "(")
	if open < 0 {
		return ""
	}
	depth := 1
	for i := open + 1; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[:i+1]
			}
		}
	}
	return ""
}

func TestDPoP_WiredIntoDeployGroup(t *testing.T) {
	source := readRouterSource(t)

	if !strings.Contains(source, `deployGroup := app.Group("/deploy",`) {
		t.Fatal("router.go no longer registers the /deploy group with the multi-line builder pattern this test relies on")
	}
	deployStart := strings.Index(source, `deployGroup := app.Group("/deploy",`)
	deployBlock := extractGroupBlock(source[deployStart:])
	if deployBlock == "" {
		t.Fatal("router.go: could not find closing paren of /deploy group declaration")
	}
	if !strings.Contains(deployBlock, "middleware.RequireDPoP(rdb)") {
		t.Errorf("router.go: /deploy group MUST install middleware.RequireDPoP(rdb); group block was:\n%s", deployBlock)
	}
}

// readRouterSource loads router.go from disk. Locates the file by walking
// up from CWD looking for internal/router/router.go.
func readRouterSource(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	dir := cwd
	for i := 0; i < 6; i++ {
		candidate := filepath.Join(dir, "internal", "router", "router.go")
		if _, err := os.Stat(candidate); err == nil {
			data, err := os.ReadFile(candidate)
			if err != nil {
				t.Fatalf("read %s: %v", candidate, err)
			}
			return string(data)
		}
		// Try the sibling-folder layout (running from internal/router).
		if filepath.Base(dir) == "router" {
			candidate2 := filepath.Join(dir, "router.go")
			if _, err := os.Stat(candidate2); err == nil {
				data, err := os.ReadFile(candidate2)
				if err != nil {
					t.Fatalf("read %s: %v", candidate2, err)
				}
				return string(data)
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate internal/router/router.go from cwd=%s", cwd)
	return ""
}
