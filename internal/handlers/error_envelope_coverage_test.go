package handlers

// error_envelope_coverage_test.go — registry-iterating coverage gate
// (per CLAUDE.md rule 18) that enforces the "every emitted error code
// has an agent_action entry OR is in an explicit allowlist" invariant.
//
// Pre-wave-3 the codeToAgentAction registry covered ~38 codes; every
// other emit site fell back to AgentActionContactSupport on 5xx or to
// an empty agent_action on 4xx. The W7G contract (every 4xx carries a
// machine-readable next-action sentence) was silently violated for
// ~160 emitted codes.
//
// This test walks every `respondError*("..., "<code>", ...)` call site
// in api/internal/handlers/*.go via go/parser, extracts the literal
// `<code>` argument, and asserts each one is either:
//
//   (a) present in codeToAgentAction, OR
//   (b) listed in coverageAllowlist (pure plumbing codes that legitimately
//       fall back to AgentActionContactSupport — adding a per-code
//       sentence would not be more useful than "email support").
//
// A new emit site landing in CI without an entry here OR in the allowlist
// fails this test — closing the door against silent regression.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// coverageAllowlist enumerates the error codes that are intentionally
// allowed to fall back to AgentActionContactSupport (5xx) or to an
// empty agent_action (4xx). Add a code here ONLY when no domain-specific
// guidance would be more useful than the generic "email support" sentence.
//
// Every entry MUST be commented with the reason. PRs that add a code
// here without a per-code rationale should be rejected at review.
var coverageAllowlist = map[string]string{
	// "code" and "x" are regex-extraction artefacts, never emitted in
	// real handler call sites. Filtered by the test (see emitCode).
	"code": "regex artefact — not a real emit",
	"x":    "regex artefact — not a real emit",
}

// TestErrorCode_HasAgentAction is the registry-iterating coverage gate.
// It walks every respondError* call site under internal/handlers/, pulls
// out the literal error-code string, and asserts each one is in either
// codeToAgentAction or coverageAllowlist.
//
// Per CLAUDE.md rule 18: this test iterates the LIVE call sites (via
// go/ast) rather than a hand-typed slice. A new call site that misses
// a registry entry fails the build, not prod.
func TestErrorCode_HasAgentAction(t *testing.T) {
	// Locate the handlers directory. The test runs from the package
	// directory, so the source files live in `.`.
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) == 0 {
		t.Fatalf("no .go files found in handlers package directory")
	}

	emitted := map[string][]string{} // code → list of "file:line" emit sites

	fset := token.NewFileSet()
	for _, f := range files {
		// Skip test files — we only want production emit sites.
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		// Read file bytes ourselves so the parser can't be tricked by a
		// generated cache.
		buf, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		af, err := parser.ParseFile(fset, f, buf, parser.AllErrors)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			// Match respondError / respondErrorWithAgentAction /
			// respondErrorWithRetry / respondRecycleGate / WriteFiberError —
			// every helper that ultimately writes a 4xx/5xx envelope.
			ident, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			switch ident.Name {
			case "respondError",
				"respondErrorWithAgentAction",
				"respondErrorWithRetry",
				"respondRecycleGate",
				"WriteFiberError":
			default:
				return true
			}
			// The error code is one of the args, always a string
			// literal. Walk args looking for the first BasicLit STRING
			// whose value matches the snake_case pattern. The first
			// such literal in the call is the code; subsequent literals
			// are messages / agent_action sentences which contain spaces.
			for _, arg := range call.Args {
				lit, ok := arg.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				v, err := unquote(lit.Value)
				if err != nil {
					continue
				}
				if !isErrorCodeShape(v) {
					continue
				}
				pos := fset.Position(call.Pos())
				emitted[v] = append(emitted[v], pos.String())
				break // only the first matches the contract
			}
			return true
		})
	}

	// Now assert every emitted code has either a registry entry or is
	// in the allowlist.
	var missing []string
	for code, sites := range emitted {
		if _, ok := codeToAgentAction[code]; ok {
			continue
		}
		if _, ok := coverageAllowlist[code]; ok {
			continue
		}
		missing = append(missing, code+" (first site: "+sites[0]+")")
	}
	sort.Strings(missing)

	if len(missing) > 0 {
		t.Errorf("%d error codes are emitted but have neither a codeToAgentAction entry nor a coverageAllowlist entry:\n  %s\n\nAdd entries to codeToAgentAction in helpers.go OR add to coverageAllowlist with a rationale.",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// isErrorCodeShape reports whether s is a plausible respondError* `code`
// argument: lowercase letters / digits / underscore, 3-64 chars, doesn't
// start with a digit. Filters out messages ("Token must be a valid UUID"
// has spaces and uppercase) and short single-letter helpers.
func isErrorCodeShape(s string) bool {
	if len(s) < 3 || len(s) > 64 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			// ok
		case r >= '0' && r <= '9':
			if i == 0 {
				return false
			}
		case r == '_':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// unquote strips the surrounding quotes from a Go string-literal token.
// We intentionally don't use strconv.Unquote here to avoid pulling in
// escape-sequence handling — every error code in this codebase is
// plain ASCII and doesn't need decoding.
func unquote(s string) (string, error) {
	if len(s) < 2 {
		return "", errBadLiteral
	}
	switch s[0] {
	case '"', '`':
		return s[1 : len(s)-1], nil
	}
	return "", errBadLiteral
}

var errBadLiteral = errString("not a quoted string literal")

type errString string

func (e errString) Error() string { return string(e) }
