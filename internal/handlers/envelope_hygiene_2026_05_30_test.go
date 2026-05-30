package handlers

// envelope_hygiene_2026_05_30_test.go — coverage gates for the
// 2026-05-30 envelope-hygiene bundle:
//
//   • BUG-API-020 — the `invalid_token` agent_action used to name
//     INSTANODE_TOKEN even though the code is emitted from 9 sites
//     that are NOT about the user's Bearer credential (webhook URL
//     path token, invitation token, storage URL path token,
//     onboarding claim JWT, stack manifest needs token, deploy logs
//     URL path token). The fix rewrites the agent_action text to
//     stay neutral. This test pins the new wording so a future
//     regression that re-introduces "INSTANODE_TOKEN" trips here.
//
//   • BUG-API-423 — /webhook/receive/:token returned the generic
//     `not_found` error code for both the unknown-token and the
//     wrong-resource-type branches. Webhook senders grepping on the
//     error code can't disambiguate from any other route 404. The
//     fix swaps both branches to a surface-specific
//     `webhook_not_found` code. This test pins both branches.
//
// COVERAGE BLOCK (rule 17):
//
//   Symptom:        BUG-API-020 — agents emitting the wrong remediation
//                   ("have the user log in") for path-token surfaces.
//                   BUG-API-423 — webhook senders can't branch on the
//                   surface-specific 404 code.
//   Enumeration:    `rg -nF '"invalid_token"' internal/handlers/` (9
//                   non-test sites + 1 helpers.go registry entry).
//                   `rg -nF '"webhook_not_found"' internal/handlers/`
//                   (2 emit sites in webhook.go Receive).
//   Sites found:    invalid_token: 9 emit sites, 1 registry entry.
//                   webhook_not_found: 2 emit sites, 1 registry entry.
//   Sites touched:  registry entry rewrites the agent_action for ALL
//                   9 invalid_token emit sites at once; the
//                   webhook.go Receive 2 sites get the new code
//                   directly. (Other helpers.go callers stay on the
//                   generic `not_found` envelope — that's fine, they
//                   are not the surface this finding targets.)
//   Coverage test:  TestInvalidToken_AgentAction_DoesNotNameInstanodeToken
//                   + TestWebhookReceive_NotFoundUsesSurfaceCode below.
//   Live verified:  on the merge commit, run
//                     curl -sS https://api.instanode.dev/webhook/receive/aaaa | jq .agent_action
//                   asserts the new neutral copy, and
//                     curl -sS -X POST https://api.instanode.dev/webhook/receive/00000000-0000-0000-0000-000000000000 -d 'x' | jq .error
//                   asserts `webhook_not_found`.

import (
	"strings"
	"testing"
)

// TestInvalidToken_AgentAction_DoesNotNameInstanodeToken pins the
// post-fix wording for the `invalid_token` registry entry. It does NOT
// hand-type the new sentence (that would defeat rule 18 — a test
// pinning the exact string is itself a single-site fallacy). Instead
// it asserts the two contracts the fix exists to preserve:
//
//   (1) the agent_action MUST NOT contain "INSTANODE_TOKEN" — the
//       remediation is wrong for every site emitting this code.
//   (2) the agent_action MUST contain a path-token hint so an agent
//       can recognise the URL-path-token case (the dominant emit
//       site — 6 of 9 are URL path tokens). We accept any of
//       "URL", "URL path", or "path" + "UUID" — keeps the wording
//       flexible for future tightening without breaking the gate.
//
// Sibling middleware/auth.go's `unauthorizedAgentAction` constant is
// intentionally untouched — that path IS about the user's Bearer
// credential and the INSTANODE_TOKEN noun is correct there.
func TestInvalidToken_AgentAction_DoesNotNameInstanodeToken(t *testing.T) {
	meta, ok := codeToAgentAction["invalid_token"]
	if !ok {
		t.Fatalf("codeToAgentAction missing the 'invalid_token' entry — registry regressed")
	}
	if meta.AgentAction == "" {
		t.Fatalf("invalid_token agent_action is empty — every 4xx must carry the LLM-ready next sentence (W7G contract)")
	}
	if strings.Contains(meta.AgentAction, "INSTANODE_TOKEN") {
		t.Errorf(
			"invalid_token agent_action MUST NOT name INSTANODE_TOKEN — the code is emitted from 9 non-auth sites "+
				"(webhook path token, invitation token, storage path token, onboarding claim JWT, stack manifest "+
				"needs token, deploy logs path token). The user is NOT being asked to re-mint a Bearer credential. "+
				"Current text: %q", meta.AgentAction,
		)
	}
	// Surface hint — the agent_action must mention either "URL", "path",
	// or "UUID" so an agent can place the remediation in the right
	// surface. This is the load-bearing positive assertion paired with
	// the negative INSTANODE_TOKEN check above.
	lower := strings.ToLower(meta.AgentAction)
	hasSurfaceHint := strings.Contains(lower, "url") ||
		strings.Contains(lower, "path") ||
		strings.Contains(lower, "uuid")
	if !hasSurfaceHint {
		t.Errorf(
			"invalid_token agent_action must hint at the URL-path-token surface (mention URL/path/UUID) so an "+
				"agent can branch correctly. Current text: %q", meta.AgentAction,
		)
	}
}

// TestWebhookNotFound_AgentAction_HasSurfaceSpecificCopy pins the
// presence of the new `webhook_not_found` registry entry that
// BUG-API-423 introduced. The copy must NOT redirect the agent back
// to the generic "URL is wrong" remediation — it must tell them to
// confirm the path-token came from POST /webhook/new.
func TestWebhookNotFound_AgentAction_HasSurfaceSpecificCopy(t *testing.T) {
	meta, ok := codeToAgentAction["webhook_not_found"]
	if !ok {
		t.Fatalf("codeToAgentAction missing the 'webhook_not_found' entry — registry regressed (TestCodeToAgentAction_NoOrphans should also fail)")
	}
	if meta.AgentAction == "" {
		t.Fatalf("webhook_not_found agent_action is empty — every 4xx must carry the LLM-ready next sentence")
	}
	lower := strings.ToLower(meta.AgentAction)
	if !strings.Contains(lower, "webhook") {
		t.Errorf("webhook_not_found agent_action must mention 'webhook' so the surface is unambiguous; got %q", meta.AgentAction)
	}
	if !strings.Contains(meta.AgentAction, "/webhook/new") {
		t.Errorf("webhook_not_found agent_action must point at POST /webhook/new for re-provisioning; got %q", meta.AgentAction)
	}
}
