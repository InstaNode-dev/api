package models_test

// redeploy_guard_test.go — P2 bug-hunt coverage (2026-05-17 round 3).
//
// Fix #1: POST /deploy/:id/redeploy must reject a deployment in a terminal
//         status (expired/deleted/stopped) — redeploying one would resurrect
//         an over-TTL / over-cap workload. The handler gate calls
//         models.IsDeploymentTerminal; this pins its classification.
// Fix #2: stack Redeploy must re-run the tier cap when the stack is not in an
//         active (slot-occupying) status. The handler gate calls
//         models.IsStackActive; this pins its classification.

import (
	"testing"

	"instant.dev/internal/models"
)

// TestIsDeploymentTerminal pins which deployment statuses the redeploy gate
// treats as non-redeployable. If a new terminal status is added without
// updating IsDeploymentTerminal, this test must be extended in the same PR.
func TestIsDeploymentTerminal(t *testing.T) {
	cases := []struct {
		status string
		want   bool
	}{
		// Terminal — redeploy must be rejected (409).
		{models.DeployStatusExpired, true},
		{models.DeployStatusDeleted, true},
		{models.DeployStatusStopped, true},
		// Live / transient — redeploy is allowed.
		{models.DeployStatusBuilding, false},
		{models.DeployStatusDeploying, false},
		{models.DeployStatusHealthy, false},
		{"failed", false}, // a failed deploy CAN be redeployed (retry the build)
		{"", false},
	}
	for _, c := range cases {
		if got := models.IsDeploymentTerminal(c.status); got != c.want {
			t.Errorf("IsDeploymentTerminal(%q) = %v, want %v", c.status, got, c.want)
		}
	}
}

// TestIsStackActive pins which stack statuses occupy a billable tier slot.
// The stack Redeploy cap-recheck only fires when the stack is NOT active, so
// a drift here would either re-block active redeploys or let failed/stopped
// stacks redeploy back to building past the cap.
func TestIsStackActive(t *testing.T) {
	cases := []struct {
		status string
		want   bool
	}{
		// Active — occupies a slot; redeploy is a no-net-change, no cap check.
		{"building", true},
		{"deploying", true},
		{"healthy", true},
		// Inactive — frees the slot; redeploy must re-run the cap check.
		{"failed", false},
		{"stopped", false},
		{"deleting", false},
		{"", false},
	}
	for _, c := range cases {
		if got := models.IsStackActive(c.status); got != c.want {
			t.Errorf("IsStackActive(%q) = %v, want %v", c.status, got, c.want)
		}
	}
}
