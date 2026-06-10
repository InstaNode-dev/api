//go:build e2e

package e2e

// cohort_helpers_test.go — shared helper for the authed e2e flows added
// 2026-06-10 (D1/D2/D6). Mints a throwaway is_test_cohort account against the
// LIVE api via POST /internal/e2e/account (guarded by the X-E2E-Token header =
// E2E_ACCOUNT_TOKEN) and ALWAYS reaps it via DELETE /internal/e2e/account/:id.
// The mint/reap surface is INERT in prod unless the operator wired the secret,
// so tests that need it skip cleanly when E2E_ACCOUNT_TOKEN is unset.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"testing"
)

// e2eAccountToken returns the guard secret for the /internal/e2e/account
// surface, or "" when unset (tests then skip).
func e2eAccountToken() string { return os.Getenv("E2E_ACCOUNT_TOKEN") }

// cohort is a minted ephemeral test account.
type cohort struct {
	TeamID     string `json:"team_id"`
	UserID     string `json:"user_id"`
	Email      string `json:"email"`
	Tier       string `json:"tier"`
	SessionJWT string `json:"session_jwt"`
}

// mintCohort creates a real is_test_cohort account on the live api. It SKIPS the
// test when E2E_ACCOUNT_TOKEN is unset (the surface is inert without it). The
// returned reap func DELETEs the account; always defer it.
func mintCohort(t *testing.T, tier string) (cohort, func()) {
	t.Helper()
	tok := e2eAccountToken()
	if tok == "" {
		t.Skip("E2E_ACCOUNT_TOKEN unset — cohort-minting e2e flow skipped (surface is inert without it)")
	}

	reqBody, _ := json.Marshal(map[string]string{"tier": tier, "env": "production"})
	req, err := http.NewRequest(http.MethodPost, baseURL()+"/internal/e2e/account", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("mintCohort: NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-E2E-Token", tok)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("mintCohort: POST /internal/e2e/account: %v", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		// Inert-by-default: token wrong or surface not armed on this deploy.
		resp.Body.Close()
		t.Skip("POST /internal/e2e/account returned 404 — surface inert / token mismatch; skipping")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("mintCohort: want 200, got %d\n%s", resp.StatusCode, readBody(t, resp))
	}
	var c cohort
	decodeJSON(t, resp, &c)
	if c.TeamID == "" || c.SessionJWT == "" {
		t.Fatalf("mintCohort: response missing team_id/session_jwt: %+v", c)
	}

	reap := func() {
		dreq, derr := http.NewRequest(http.MethodDelete,
			baseURL()+"/internal/e2e/account/"+c.TeamID, nil)
		if derr != nil {
			t.Logf("mintCohort reap: NewRequest: %v", derr)
			return
		}
		dreq.Header.Set("X-E2E-Token", tok)
		dresp, derr := client.Do(dreq)
		if derr != nil {
			t.Logf("mintCohort reap: DELETE failed (account may linger): %v", derr)
			return
		}
		dresp.Body.Close()
		if dresp.StatusCode != http.StatusOK {
			t.Logf("mintCohort reap: DELETE returned %d for team %s", dresp.StatusCode, c.TeamID)
		}
	}
	return c, reap
}
