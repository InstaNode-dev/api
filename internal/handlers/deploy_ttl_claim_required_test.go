package handlers_test

// deploy_ttl_claim_required_test.go — B7-P1-7 (BugBash 2026-05-20)
// regression gate for the anonymous-tier walls on the deploy-TTL keeper
// endpoints.
//
// Bug class:
//   POST /api/v1/deployments/:id/make-permanent and POST /:id/ttl reject
//   anonymous-tier callers with 402. The wall's `error` code used to be
//   `upgrade_required`, which is the keyword for "paid plan needed" —
//   not the right semantics here, where the remediation is a FREE claim.
//   Agents that branch on the response `error` keyword (instead of reading
//   the prose agent_action) routed the user to the paid pricing page when
//   a 30-second free claim would have cleared the wall.
//
// Why a registry-iterating test (rule 18 — CLAUDE.md):
//   This is a two-site bug: MakePermanent (deploy_ttl.go:63-69) and SetTTL
//   (deploy_ttl.go:137-143) both emitted the wrong code. A hand-typed
//   single-route assertion would re-regress the moment a third TTL-keeper
//   route lands and re-uses the `upgrade_required` template. The table
//   below iterates EVERY anon-rejected deploy-TTL route and asserts the
//   contract identically; adding a new route without adding a row here
//   makes the failure mode loud, not silent.
//
// Surface coverage (rule 17):
//   Symptom:       JSON body `error: "upgrade_required"` on anon /make-permanent + /ttl
//   Enumeration:   rg -F '"upgrade_required"' internal/handlers/deploy_ttl.go
//   Sites found:   2  (L65, L139)
//   Sites touched: 2  (both arms flipped to "claim_required" in same PR)
//   Coverage test: this file — iterates a 2-route table; a third arm
//                  that emits `upgrade_required` makes the matching row fail.
//   Live verified: pending — anonymous deploys cannot be made permanent
//                  on a real prod hit; the unit test exercises both code
//                  paths against a real test DB with an "anonymous"-tier
//                  team. Live curl awaiting deploy.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// TestDeployTTL_AnonymousArmsEmitClaimRequired pins the contract for every
// anonymous-tier wall on the deploy-TTL keeper endpoints. The table is the
// registry — adding a new TTL route that rejects anon must add a row here.
func TestDeployTTL_AnonymousArmsEmitClaimRequired(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "anonymous")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "u-claim-1", teamID, "anon@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	d, err := models.CreateDeployment(context.Background(), db, models.CreateDeploymentParams{
		TeamID: uuid.MustParse(teamID),
		AppID:  "ttl-anon-" + uuid.NewString()[:6],
		Tier:   "anonymous",
	})
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, d.ID)

	// Registry of every anon-rejected deploy-TTL route. ADD A ROW HERE
	// when a new keeper endpoint lands and rejects anon — otherwise the
	// next emitter of `upgrade_required` will slip past this gate.
	type armCase struct {
		name   string
		method string
		path   string
		body   string
	}
	arms := []armCase{
		{
			name:   "make_permanent",
			method: http.MethodPost,
			path:   "/api/v1/deployments/" + d.AppID + "/make-permanent",
			body:   "",
		},
		{
			name:   "set_ttl",
			method: http.MethodPost,
			path:   "/api/v1/deployments/" + d.AppID + "/ttl",
			body:   `{"hours":48}`,
		},
	}

	for _, arm := range arms {
		t.Run(arm.name, func(t *testing.T) {
			var bodyReader io.Reader
			if arm.body != "" {
				bodyReader = strings.NewReader(arm.body)
			}
			req := httptest.NewRequest(arm.method, arm.path, bodyReader)
			if arm.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			req.Header.Set("Authorization", "Bearer "+sessionJWT)

			resp, err := app.Test(req, 5000)
			require.NoError(t, err)
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)

			assert.Equal(t, http.StatusPaymentRequired, resp.StatusCode,
				"%s: anon-tier must 402, got body=%s", arm.name, body)

			var out struct {
				OK          bool   `json:"ok"`
				Error       string `json:"error"`
				Message     string `json:"message"`
				AgentAction string `json:"agent_action"`
				UpgradeURL  string `json:"upgrade_url"`
			}
			require.NoError(t, json.Unmarshal(body, &out),
				"%s: response must be JSON envelope: %s", arm.name, body)

			assert.False(t, out.OK, "%s: ok must be false", arm.name)

			// THE bug — error code keyword. `upgrade_required` routes
			// agents to paid pricing; `claim_required` routes them to
			// the free claim flow.
			assert.Equal(t, "claim_required", out.Error,
				"%s: error keyword must be claim_required (agents branching on code route by this keyword); upgrade_required mis-routes to paid pricing", arm.name)

			// upgrade_url is the machine-readable destination an agent
			// would surface as a CTA. For a FREE claim it must point at
			// /claim, not /pricing or /start (deprecated alias).
			assert.Equal(t, "https://instanode.dev/claim", out.UpgradeURL,
				"%s: upgrade_url must point at the free /claim flow, not /pricing", arm.name)

			// agent_action sentence must still pass the U3 contract and
			// say "claim" (the action verb).
			assert.NotEmpty(t, out.AgentAction, "%s: agent_action must not be empty", arm.name)
			assert.Contains(t, strings.ToLower(out.AgentAction), "claim",
				"%s: agent_action must name the next action (claim)", arm.name)
		})
	}
}

// TestDeployTTL_NoUpgradeRequiredInSource is the structural guard for the
// same regression: if any future hand-edit re-introduces the
// `"upgrade_required"` string into deploy_ttl.go's anon walls, this test
// fails before the registry-iterating arm test even runs. Belt + braces.
//
// NOTE: this asserts on the deploy_ttl.go FILE (source-level grep), so it
// catches the regression at compile-time-of-the-test rather than at the
// HTTP boundary. The arm-iterating test above is the HTTP-boundary gate.
func TestDeployTTL_NoUpgradeRequiredInSource(t *testing.T) {
	// Read the source file deterministically — golden-grep style. Tests
	// run with cwd == the package directory, so the relative path is the
	// source file alongside this test.
	const sourcePath = "deploy_ttl.go"
	rawBytes, err := os.ReadFile(sourcePath)
	require.NoError(t, err, "source file must be readable: %s", sourcePath)
	raw := string(rawBytes)

	// Any string literal `"upgrade_required"` inside deploy_ttl.go is
	// a regression of B7-P1-7 — the anon walls there are required to
	// emit `claim_required` instead. Other handlers (db.go, vector.go,
	// nosql.go, ...) are still allowed to emit `upgrade_required`
	// because their walls really are paid-plan walls.
	assert.NotContains(t, raw, `"upgrade_required"`,
		"B7-P1-7 regression: deploy_ttl.go must not emit the `upgrade_required` keyword — anon-tier walls here are FREE-claim walls and must emit `claim_required` so code-switching agents route to /claim instead of /pricing")
}
