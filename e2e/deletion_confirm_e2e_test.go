//go:build e2e

// deletion_confirm_e2e_test.go — Wave FIX-I.
//
// End-to-end coverage of the two-step email-confirmed deletion flow on
// DELETE /api/v1/deployments/:id. Runs against a live api pod.
//
// NOTE: the deeper four-path matrix (request / confirm / cancel /
// expired) is exercised against a real DB in
// internal/handlers/deploy_delete_test.go. This e2e layer asserts the
// contract surface — agent_action carries the canonical sentence,
// confirmation_sent_to is masked, the 202 envelope is wire-compatible.
//
// The provision step requires multipart tarball upload that the
// existing e2e helpers don't carry yet, so this test is currently a
// skeleton that t.Skip's. Wiring real provisioning here is a
// follow-up — the handler-level coverage is sufficient for ship.

package e2e

import (
	"testing"
)

// TestE2E_DeleteDeploy_PaidTeam_TwoStepContract is the contract-shape
// guard for the live API's 202 envelope. Currently t.Skip — wiring
// /deploy/new into the e2e helpers is a follow-up.
//
// What this WILL exercise once the helper lands:
//
//   1. Provision a pro-tier deployment as a claimed team.
//   2. DELETE /api/v1/deployments/{id} → 202 with
//      deletion_status="pending_confirmation",
//      confirmation_sent_to matches "*@example.com" with *** mask,
//      agent_action non-empty and contains "Tell the user".
//   3. DELETE on /confirm-deletion path → 200 with
//      deletion_status="cancelled".
//   4. With X-Skip-Email-Confirmation: yes → 200 immediate.
//
// Until that lands, the handler tests cover all four paths against a
// real DB via NewTestAppWithServices — see
// internal/handlers/deploy_delete_test.go.
func TestE2E_DeleteDeploy_PaidTeam_TwoStepContract(t *testing.T) {
	t.Skip("e2e wiring for /deploy/new multipart upload is a follow-up; handler tests in internal/handlers/deploy_delete_test.go cover the four paths")
}
