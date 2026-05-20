package handlers

// error_envelope_coverage_test.go — Wave 2 UX polish gate (2026-05-20).
//
// Walks every respondError-family call site under internal/handlers/ via
// the AST and asserts:
//
//   - every 4xx code has a codeToAgentAction entry (or is in the explicit
//     inline-action-only allowlist below)
//   - every 5xx code has an entry OR falls through to the curated
//     plumbing5xxFallbackCodes allowlist (which the AgentActionContactSupport
//     fallback covers)
//   - no stale entry — every code in codeToAgentAction is actually emitted
//
// Rule 18 from CLAUDE.md ("registry-iterating regression tests, not
// hand-typed lists") is the design pattern this test embodies. Adding a
// new code without a matching entry fails this test.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

type emittedErrorCode struct {
	code   string
	status string
	file   string
	line   int
}

func is4xxStatusCode(s string) bool {
	switch s {
	case "StatusBadRequest", "StatusUnauthorized", "StatusPaymentRequired",
		"StatusForbidden", "StatusNotFound", "StatusMethodNotAllowed",
		"StatusNotAcceptable", "StatusProxyAuthRequired",
		"StatusRequestTimeout", "StatusConflict", "StatusGone",
		"StatusLengthRequired", "StatusPreconditionFailed",
		"StatusRequestEntityTooLarge", "StatusRequestURITooLong",
		"StatusUnsupportedMediaType", "StatusRequestedRangeNotSatisfiable",
		"StatusExpectationFailed", "StatusTeapot",
		"StatusMisdirectedRequest", "StatusUnprocessableEntity",
		"StatusLocked", "StatusFailedDependency", "StatusTooEarly",
		"StatusUpgradeRequired", "StatusPreconditionRequired",
		"StatusTooManyRequests", "StatusRequestHeaderFieldsTooLarge",
		"StatusUnavailableForLegalReasons":
		return true
	}
	if len(s) == 3 && s[0] == '4' {
		return true
	}
	return false
}

func is5xxStatusCode(s string) bool {
	switch s {
	case "StatusInternalServerError", "StatusNotImplemented",
		"StatusBadGateway", "StatusServiceUnavailable",
		"StatusGatewayTimeout", "StatusHTTPVersionNotSupported",
		"StatusVariantAlsoNegotiates", "StatusInsufficientStorage",
		"StatusLoopDetected", "StatusNotExtended",
		"StatusNetworkAuthenticationRequired":
		return true
	}
	if len(s) == 3 && s[0] == '5' {
		return true
	}
	return false
}

func extractStatusName(arg ast.Expr) string {
	switch e := arg.(type) {
	case *ast.SelectorExpr:
		return e.Sel.Name
	case *ast.BasicLit:
		return e.Value
	case *ast.Ident:
		return e.Name
	}
	return ""
}

func extractCodeLit(arg ast.Expr) string {
	lit, ok := arg.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	v := lit.Value
	if len(v) < 2 {
		return ""
	}
	return v[1 : len(v)-1]
}

func errEnvCallIdent(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	}
	return ""
}

// scanEmittedErrorCodes walks every non-test .go file under
// internal/handlers/ and returns every literal `code` string passed to a
// respondError-family function paired with the status arg (where
// statically resolvable).
func scanEmittedErrorCodes(t *testing.T) []emittedErrorCode {
	t.Helper()
	var out []emittedErrorCode

	entries, err := os.ReadDir(".")
	require.NoError(t, err, "read internal/handlers dir")

	fset := token.NewFileSet()
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.AllErrors)
		require.NoError(t, err, "parse %s", name)
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id := errEnvCallIdent(call.Fun)
			if id == "" {
				return true
			}
			var codeArg, statusArg ast.Expr
			switch id {
			case "respondError", "respondErrorWithAgentAction", "respondErrorWithRetry", "WriteFiberError":
				if len(call.Args) < 4 {
					return true
				}
				statusArg = call.Args[1]
				codeArg = call.Args[2]
			case "respondRecycleGate":
				if len(call.Args) < 2 {
					return true
				}
				codeArg = call.Args[1]
				statusArg = nil
			default:
				return true
			}
			code := extractCodeLit(codeArg)
			if code == "" {
				return true
			}
			pos := fset.Position(call.Pos())
			status := ""
			if statusArg != nil {
				status = extractStatusName(statusArg)
			} else {
				status = "StatusPaymentRequired"
			}
			out = append(out, emittedErrorCode{
				code:   code,
				status: status,
				file:   pos.Filename,
				line:   pos.Line,
			})
			return true
		})
	}
	return out
}

// TestErrorCode_HasAgentAction is the Wave 2 UX polish coverage gate.
// See file header for the contract.
func TestErrorCode_HasAgentAction(t *testing.T) {
	emitted := scanEmittedErrorCodes(t)
	require.NotEmpty(t, emitted, "no respondError calls discovered — AST walk regressed")

	// Codes only ever emitted via respondErrorWithAgentAction (caller
	// supplies the action inline). Maintained explicitly so a new
	// inline-only emission is a code-review decision.
	inlineActionOnlyCodes := map[string]bool{
		"already_connected":                   true,
		"already_paused":                      true,
		"backup_not_ready":                    true,
		"deployment_limit_reached":            true,
		"destructive_ack_required":            true,
		"downgrade_not_self_serve":            true,
		"email_not_verified":                  true,
		"github_requires_paid_tier":           true,
		"invalid_email_format":                true,
		"invalid_hours":                       true,
		"invalid_notify_webhook":              true,
		"not_paused":                          true,
		"private_deploy_requires_allowed_ips": true,
		"private_deploy_requires_pro":         true,
		"queue_limit_reached":                 true,
		"restore_in_progress":                 true,
		"slug_mismatch":                       true,
		"subscription_cancel_failed":          true,
		"target_cross_team":                   true,
	}

	// 5xx codes intentionally relying on AgentActionContactSupport.
	// Pure-plumbing failures where "email support@instanode.dev with this
	// request_id" is the only honest next action.
	plumbing5xxFallbackCodes := map[string]bool{
		"approval_failed":         true,
		"backup_create_failed":    true,
		"backup_lookup_failed":    true,
		"compute_update_failed":   true,
		"count_failed":            true,
		"create_failed":           true,
		"db_error":                true,
		"db_failed":               true,
		"delete_failed":           true,
		"deletion_create_failed":  true,
		"deletion_lookup_failed":  true,
		"deletion_mark_failed":    true,
		"deletion_request_failed": true,
		"execute_failed":          true,
		"family_validate_failed":  true,
		"fetch_failed":            true,
		"generate_failed":         true,
		"inflight_check_failed":   true,
		"internal_error":          true,
		"list_failed":             true,
		"logs_failed":             true,
		"lookup_failed":           true,
		"mark_converted_failed":   true,
		"pause_failed":            true,
		"persist_failed":          true,
		"provider_failed":         true,
		"quota_check_failed":      true,
		"reject_failed":           true,
		"restore_create_failed":   true,
		"restore_failed":          true,
		"resume_failed":           true,
		"role_lookup_failed":      true,
		"session_failed":          true,
		"status_failed":           true,
		"status_lookup_failed":    true,
		"stream_failed":           true,
		"summary_failed":          true,
		"team_creation_failed":    true,
		"team_lookup_failed":      true,
		"tier_failed":             true,
		"update_failed":           true,
		"upgrade_failed":          true,
		"usage_failed":            true,
		"user_creation_failed":    true,
		"user_upsert_failed":      true,
		"verify_failed":           true,
	}

	codeStatuses := map[string]map[string]bool{}
	codeSites := map[string]emittedErrorCode{}
	for _, e := range emitted {
		if codeStatuses[e.code] == nil {
			codeStatuses[e.code] = map[string]bool{}
		}
		codeStatuses[e.code][e.status] = true
		if _, ok := codeSites[e.code]; !ok {
			codeSites[e.code] = e
		}
	}

	var missingFourXX []string
	var missing5xxNotOnAllowlist []string

	for code, statuses := range codeStatuses {
		_, mapped := codeToAgentAction[code]
		if mapped {
			continue
		}
		if inlineActionOnlyCodes[code] {
			continue
		}
		is4xx := false
		is5xx := false
		for s := range statuses {
			if is4xxStatusCode(s) {
				is4xx = true
			}
			if is5xxStatusCode(s) {
				is5xx = true
			}
		}
		if is4xx {
			site := codeSites[code]
			missingFourXX = append(missingFourXX,
				code+" (status: "+joinSetKeys(statuses)+", at "+site.file+":"+intToStr(site.line)+")")
			continue
		}
		if is5xx {
			if plumbing5xxFallbackCodes[code] {
				continue
			}
			site := codeSites[code]
			missing5xxNotOnAllowlist = append(missing5xxNotOnAllowlist,
				code+" (status: "+joinSetKeys(statuses)+", at "+site.file+":"+intToStr(site.line)+")")
		}
		if !is4xx && !is5xx {
			site := codeSites[code]
			missingFourXX = append(missingFourXX,
				code+" (status: "+joinSetKeys(statuses)+" — UNRESOLVED, defaulting to 4xx rule, at "+site.file+":"+intToStr(site.line)+")")
		}
	}

	if len(missingFourXX) > 0 {
		sort.Strings(missingFourXX)
		t.Errorf("the following 4xx error codes have NO agent_action entry in codeToAgentAction:\n  - %s\n\nAdd them to helpers.go::codeToAgentAction, OR — if the call site always supplies the action via respondErrorWithAgentAction — add the code to inlineActionOnlyCodes in this test.",
			strings.Join(missingFourXX, "\n  - "))
	}
	if len(missing5xxNotOnAllowlist) > 0 {
		sort.Strings(missing5xxNotOnAllowlist)
		t.Errorf("the following 5xx error codes have NO agent_action entry AND are not on plumbing5xxFallbackCodes allow-list:\n  - %s\n\nDecide: add a domain-specific entry to helpers.go::codeToAgentAction, OR add to plumbing5xxFallbackCodes in this test.",
			strings.Join(missing5xxNotOnAllowlist, "\n  - "))
	}
}

// TestErrorCode_NoStaleRegistryEntries asserts the inverse direction —
// every code in codeToAgentAction is emitted by handler source or is in
// the external-emitter allowlist.
func TestErrorCode_NoStaleRegistryEntries(t *testing.T) {
	emitted := scanEmittedErrorCodes(t)
	emittedSet := map[string]bool{}
	for _, e := range emitted {
		emittedSet[e.code] = true
	}

	externalEmitterCodes := map[string]bool{
		// router.go ErrorHandler — Fiber default 404/405/413/415
		"not_found":              true,
		"method_not_allowed":     true,
		"payload_too_large":      true,
		"unsupported_media_type": true,
		// middleware/quota.go + friends
		"quota_exceeded":                true,
		"upgrade_required":              true,
		"vault_quota_exceeded":          true,
		"vault_not_available":           true,
		"vault_env_not_allowed":         true,
		"member_limit":                  true,
		"tier_unavailable":              true,
		"rate_limit_exceeded":           true,
		"unauthorized":                  true,
		"auth_required":                 true,
		"invalid_token":                 true,
		"missing_token":                 true,
		"vault_requires_auth":           true,
		"invitation_invalid":            true,
		"already_accepted":              true,
		"already_claimed":               true,
		"webhook_inactive":              true,
		"resource_not_found":            true,
		"forbidden":                     true,
		"last_owner":                    true,
		"cannot_remove_primary":         true,
		"cannot_assign_owner_role":      true,
		"invalid_body":                  true,
		"invalid_email":                 true,
		"provision_limit_reached":       true,
		"provisioner_unavailable":       true,
		"provision_failed":              true,
		"billing_provider_unavailable":  true,
		"dpop_replay_check_unavailable": true,
		"deletion_token_invalid":        true,
		"deletion_already_pending":      true,
		"deletion_email_disabled":       true,
		"storage_limit_reached":         true,
	}

	var stale []string
	for code := range codeToAgentAction {
		if emittedSet[code] {
			continue
		}
		if externalEmitterCodes[code] {
			continue
		}
		stale = append(stale, code)
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		t.Errorf("the following codeToAgentAction entries are NOT emitted anywhere in internal/handlers/ (likely stale):\n  - %s\n\nDelete from helpers.go::codeToAgentAction, OR — if emitted from middleware/router — add to externalEmitterCodes in this test.",
			strings.Join(stale, "\n  - "))
	}
}

func joinSetKeys(m map[string]bool) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

func intToStr(i int) string {
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	var buf [12]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// Keep fiber import in scope even if other tests in this package are
// rearranged.
var _ = fiber.StatusOK
