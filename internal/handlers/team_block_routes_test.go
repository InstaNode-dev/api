package handlers_test

// team_block_routes_test.go — W3 team-block integration suite.
//
// Covers the team & member management user-flow block from
// USER-FLOW-INVENTORY-AND-TEST-MATRIX.md §F (F1–F11). Each route below was, in
// internal/router/route_donebar_guard_test.go, listed in
// routeCoverageExemptions with a "TODO: matrix W3 …" pointer and NO mapped
// test. This suite supplies the DB-backed integration coverage the done-bar
// guard's routeTestMap now points at, so the routes move exempt → mapped.
//
// Every test runs against a real migrated Postgres (testhelpers.SetupTestDB)
// through the production RBAC middleware chain (teamBlockApp). For each route
// the suite asserts, where applicable:
//   - happy path (correct 2xx + persisted state / response contract),
//   - authz (owner / member / non-owner → correct 200 / 403),
//   - cross-team isolation (acting on another team's id is refused),
//   - the response/contract shape (ok flag, key fields, env defaults).
//
// Skips loudly when TEST_DATABASE_URL is unset (teamBlockSkipNoDB).

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
)

// ─────────────────────────────────────────────────────────────────────────
// GET /api/v1/team — TeamSelfHandler.Get  (F1)
// ─────────────────────────────────────────────────────────────────────────

func TestTeamBlock_GetTeam(t *testing.T) {
	teamBlockSkipNoDB(t)
	db, cleanup := teamBlockDB(t)
	defer cleanup()
	teamID, ownerID := teamBlockSeedTeamOwner(t, db, "pro")

	t.Run("owner happy path returns team contract", func(t *testing.T) {
		app := teamBlockApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
		status, body := teamBlockReq(t, app, http.MethodGet, "/api/v1/team", nil)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, true, body["ok"])
		team, ok := body["team"].(map[string]any)
		require.True(t, ok, "team object present")
		assert.Equal(t, teamID.String(), team["id"])
		assert.Equal(t, "pro", team["plan_tier"])
	})

	t.Run("viewer member can read team", func(t *testing.T) {
		viewerID := teamBlockAddMember(t, db, teamID, "viewer")
		app := teamBlockApp(t, db, miniRedis(t), viewerID.String(), teamID.String())
		status, _ := teamBlockReq(t, app, http.MethodGet, "/api/v1/team", nil)
		require.Equal(t, http.StatusOK, status)
	})

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		app := teamBlockApp(t, db, miniRedis(t), "", "")
		status, _ := teamBlockReq(t, app, http.MethodGet, "/api/v1/team", nil)
		require.Equal(t, http.StatusUnauthorized, status)
	})
}

// ─────────────────────────────────────────────────────────────────────────
// PATCH /api/v1/team — TeamSelfHandler.Update  (F1, owner-only)
// ─────────────────────────────────────────────────────────────────────────

func TestTeamBlock_PatchTeam(t *testing.T) {
	teamBlockSkipNoDB(t)
	db, cleanup := teamBlockDB(t)
	defer cleanup()
	teamID, ownerID := teamBlockSeedTeamOwner(t, db, "pro")

	t.Run("owner renames team and it persists", func(t *testing.T) {
		app := teamBlockApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
		status, body := teamBlockReq(t, app, http.MethodPatch, "/api/v1/team",
			map[string]any{"name": "Renamed Team"})
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, true, body["ok"])
		assert.Equal(t, "Renamed Team", teamBlockTeamName(t, db, teamID))
	})

	t.Run("developer member forbidden (RequireRole owner)", func(t *testing.T) {
		devID := teamBlockAddMember(t, db, teamID, "developer")
		app := teamBlockApp(t, db, miniRedis(t), devID.String(), teamID.String())
		status, body := teamBlockReq(t, app, http.MethodPatch, "/api/v1/team",
			map[string]any{"name": "Hacked"})
		require.Equal(t, http.StatusForbidden, status)
		assert.Equal(t, "forbidden", body["error"])
	})

	t.Run("empty name rejected 400", func(t *testing.T) {
		app := teamBlockApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
		status, _ := teamBlockReq(t, app, http.MethodPatch, "/api/v1/team",
			map[string]any{"name": "   "})
		require.Equal(t, http.StatusBadRequest, status)
	})
}

// ─────────────────────────────────────────────────────────────────────────
// DELETE /api/v1/team + POST /api/v1/team/restore — TeamDeletionHandler  (F10)
// ─────────────────────────────────────────────────────────────────────────

func TestTeamBlock_DeleteAndRestoreTeam(t *testing.T) {
	teamBlockSkipNoDB(t)
	db, cleanup := teamBlockDB(t)
	defer cleanup()

	t.Run("owner deletes (two-step slug confirm) then restores", func(t *testing.T) {
		teamID, ownerID := teamBlockSeedTeamOwner(t, db, "pro")
		team, err := models.GetTeamByID(context.Background(), db, teamID)
		require.NoError(t, err)
		slug := models.TeamSlug(team)

		app := teamBlockApp(t, db, miniRedis(t), ownerID.String(), teamID.String())

		// Delete — 202 Accepted, grace window opens.
		status, body := teamBlockReq(t, app, http.MethodDelete, "/api/v1/team",
			map[string]any{"confirm_team_slug": slug})
		require.Equal(t, http.StatusAccepted, status)
		assert.Equal(t, true, body["ok"])
		assert.NotEmpty(t, body["deletion_at"])

		// Restore — 200, team back to active.
		rstatus, rbody := teamBlockReq(t, app, http.MethodPost, "/api/v1/team/restore", nil)
		require.Equal(t, http.StatusOK, rstatus)
		assert.Equal(t, true, rbody["ok"])
	})

	t.Run("slug mismatch refuses with 409", func(t *testing.T) {
		teamID, ownerID := teamBlockSeedTeamOwner(t, db, "pro")
		app := teamBlockApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
		status, body := teamBlockReq(t, app, http.MethodDelete, "/api/v1/team",
			map[string]any{"confirm_team_slug": "definitely-not-the-slug"})
		require.Equal(t, http.StatusConflict, status)
		assert.Equal(t, "slug_mismatch", body["error"])
	})

	t.Run("admin member forbidden from deleting (RequireRole owner)", func(t *testing.T) {
		teamID, _ := teamBlockSeedTeamOwner(t, db, "pro")
		adminID := teamBlockAddMember(t, db, teamID, "admin")
		app := teamBlockApp(t, db, miniRedis(t), adminID.String(), teamID.String())
		status, _ := teamBlockReq(t, app, http.MethodDelete, "/api/v1/team",
			map[string]any{"confirm_team_slug": "anything"})
		require.Equal(t, http.StatusForbidden, status)
	})

	t.Run("restore when not pending returns 409", func(t *testing.T) {
		teamID, ownerID := teamBlockSeedTeamOwner(t, db, "pro")
		app := teamBlockApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
		status, body := teamBlockReq(t, app, http.MethodPost, "/api/v1/team/restore", nil)
		require.Equal(t, http.StatusConflict, status)
		assert.Equal(t, "not_pending", body["error"])
	})
}

// ─────────────────────────────────────────────────────────────────────────
// GET /api/v1/team/summary — TeamSummaryHandler.GetSummary  (E13/F-aggregation)
// ─────────────────────────────────────────────────────────────────────────

func TestTeamBlock_GetTeamSummary(t *testing.T) {
	teamBlockSkipNoDB(t)
	db, cleanup := teamBlockDB(t)
	defer cleanup()
	teamID, ownerID := teamBlockSeedTeamOwner(t, db, "growth")

	t.Run("member gets summary with tier + counts + cache header", func(t *testing.T) {
		app := teamBlockApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
		resp := doJSON(t, app, http.MethodGet, "/api/v1/team/summary", nil, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Contains(t, resp.Header.Get("Cache-Control"), "private", "summary aggregation is privately cached")
		body := decodeBody(t, resp)
		assert.Equal(t, true, body["ok"])
		assert.Equal(t, "growth", body["tier"])
		_, hasCounts := body["counts"]
		assert.True(t, hasCounts, "counts present")
	})

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		app := teamBlockApp(t, db, miniRedis(t), "", "")
		status, _ := teamBlockReq(t, app, http.MethodGet, "/api/v1/team/summary", nil)
		require.Equal(t, http.StatusUnauthorized, status)
	})
}

// ─────────────────────────────────────────────────────────────────────────
// GET + PATCH /api/v1/team/settings — TeamSettingsHandler  (F9)
// ─────────────────────────────────────────────────────────────────────────

func TestTeamBlock_TeamSettings(t *testing.T) {
	teamBlockSkipNoDB(t)
	db, cleanup := teamBlockDB(t)
	defer cleanup()
	teamID, ownerID := teamBlockSeedTeamOwner(t, db, "pro")

	t.Run("GET any member reads settings with default policy", func(t *testing.T) {
		viewerID := teamBlockAddMember(t, db, teamID, "viewer")
		app := teamBlockApp(t, db, miniRedis(t), viewerID.String(), teamID.String())
		status, body := teamBlockReq(t, app, http.MethodGet, "/api/v1/team/settings", nil)
		require.Equal(t, http.StatusOK, status)
		settings, ok := body["settings"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "auto_24h", settings["default_deployment_ttl_policy"])
	})

	t.Run("PATCH admin updates default ttl policy and it persists", func(t *testing.T) {
		adminID := teamBlockAddMember(t, db, teamID, "admin")
		app := teamBlockApp(t, db, miniRedis(t), adminID.String(), teamID.String())
		status, body := teamBlockReq(t, app, http.MethodPatch, "/api/v1/team/settings",
			map[string]any{"default_deployment_ttl_policy": "permanent"})
		require.Equal(t, http.StatusOK, status)
		settings := body["settings"].(map[string]any)
		assert.Equal(t, "permanent", settings["default_deployment_ttl_policy"])

		reloaded, err := models.GetTeamByID(context.Background(), db, teamID)
		require.NoError(t, err)
		assert.Equal(t, "permanent", reloaded.DefaultDeploymentTTLPolicy)
	})

	t.Run("PATCH developer forbidden (RequireRole admin)", func(t *testing.T) {
		devID := teamBlockAddMember(t, db, teamID, "developer")
		app := teamBlockApp(t, db, miniRedis(t), devID.String(), teamID.String())
		status, _ := teamBlockReq(t, app, http.MethodPatch, "/api/v1/team/settings",
			map[string]any{"default_deployment_ttl_policy": "permanent"})
		require.Equal(t, http.StatusForbidden, status)
	})

	t.Run("PATCH invalid policy rejected 400", func(t *testing.T) {
		app := teamBlockApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
		status, body := teamBlockReq(t, app, http.MethodPatch, "/api/v1/team/settings",
			map[string]any{"default_deployment_ttl_policy": "forever-and-ever"})
		require.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "invalid_ttl_policy", body["error"])
	})
}

// ─────────────────────────────────────────────────────────────────────────
// GET + PUT /api/v1/team/env-policy — EnvPolicyHandler  (F8)
// ─────────────────────────────────────────────────────────────────────────

func TestTeamBlock_EnvPolicy(t *testing.T) {
	teamBlockSkipNoDB(t)
	db, cleanup := teamBlockDB(t)
	defer cleanup()
	teamID, ownerID := teamBlockSeedTeamOwner(t, db, "pro")

	t.Run("GET any member reads policy (empty default object)", func(t *testing.T) {
		devID := teamBlockAddMember(t, db, teamID, "developer")
		app := teamBlockApp(t, db, miniRedis(t), devID.String(), teamID.String())
		status, body := teamBlockReq(t, app, http.MethodGet, "/api/v1/team/env-policy", nil)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, true, body["ok"])
		_, ok := body["policy"]
		assert.True(t, ok, "policy key present (never null)")
	})

	t.Run("PUT owner sets policy and GET reflects it", func(t *testing.T) {
		app := teamBlockApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
		status, body := teamBlockReq(t, app, http.MethodPut, "/api/v1/team/env-policy",
			map[string]any{"production": map[string]any{"deploy": []string{"owner"}}})
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, true, body["ok"])

		gstatus, gbody := teamBlockReq(t, app, http.MethodGet, "/api/v1/team/env-policy", nil)
		require.Equal(t, http.StatusOK, gstatus)
		policy := gbody["policy"].(map[string]any)
		assert.Contains(t, policy, "production")
	})

	t.Run("PUT non-owner forbidden (owner_required handler check)", func(t *testing.T) {
		adminID := teamBlockAddMember(t, db, teamID, "admin")
		app := teamBlockApp(t, db, miniRedis(t), adminID.String(), teamID.String())
		status, body := teamBlockReq(t, app, http.MethodPut, "/api/v1/team/env-policy",
			map[string]any{"production": map[string]any{"deploy": []string{"owner"}}})
		require.Equal(t, http.StatusForbidden, status)
		assert.Equal(t, "owner_required", body["error"])
	})
}

// ─────────────────────────────────────────────────────────────────────────
// GET /api/v1/team/members — TeamMembersHandler.ListMembers  (F4)
// ─────────────────────────────────────────────────────────────────────────

func TestTeamBlock_ListMembers(t *testing.T) {
	teamBlockSkipNoDB(t)
	db, cleanup := teamBlockDB(t)
	defer cleanup()
	teamID, ownerID := teamBlockSeedTeamOwner(t, db, "pro")
	teamBlockAddMember(t, db, teamID, "developer")

	t.Run("member lists all members with limit", func(t *testing.T) {
		app := teamBlockApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
		status, body := teamBlockReq(t, app, http.MethodGet, "/api/v1/team/members", nil)
		require.Equal(t, http.StatusOK, status)
		members, ok := body["members"].([]any)
		require.True(t, ok)
		assert.Len(t, members, 2)
		_, hasLimit := body["member_limit"]
		assert.True(t, hasLimit)
	})

	t.Run("non-member forbidden", func(t *testing.T) {
		// A user who belongs to a DIFFERENT team but claims this team in the
		// session — the in-handler role lookup returns no row → 403.
		otherTeamID, otherUserID := teamBlockSeedTeamOwner(t, db, "pro")
		_ = otherTeamID
		app := teamBlockApp(t, db, miniRedis(t), otherUserID.String(), teamID.String())
		status, _ := teamBlockReq(t, app, http.MethodGet, "/api/v1/team/members", nil)
		require.Equal(t, http.StatusForbidden, status)
	})
}

// ─────────────────────────────────────────────────────────────────────────
// POST /api/v1/team/members/invite — TeamMembersHandler.InviteMember  (F2)
// ─────────────────────────────────────────────────────────────────────────

func TestTeamBlock_InviteMember(t *testing.T) {
	teamBlockSkipNoDB(t)
	db, cleanup := teamBlockDB(t)
	defer cleanup()
	teamID, ownerID := teamBlockSeedTeamOwner(t, db, "team") // unlimited seats

	t.Run("owner invites a developer (RBAC token flow)", func(t *testing.T) {
		app := teamBlockApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
		status, body := teamBlockReq(t, app, http.MethodPost, "/api/v1/team/members/invite",
			map[string]any{"email": "invitee-" + uuid.NewString()[:8] + "@instant.dev", "role": "developer"})
		require.Equal(t, http.StatusCreated, status)
		inv, ok := body["invitation"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "developer", inv["role"])
		assert.NotEmpty(t, inv["token"])
	})

	t.Run("developer member forbidden from inviting", func(t *testing.T) {
		devID := teamBlockAddMember(t, db, teamID, "developer")
		app := teamBlockApp(t, db, miniRedis(t), devID.String(), teamID.String())
		status, _ := teamBlockReq(t, app, http.MethodPost, "/api/v1/team/members/invite",
			map[string]any{"email": "x-" + uuid.NewString()[:8] + "@instant.dev", "role": "viewer"})
		require.Equal(t, http.StatusForbidden, status)
	})

	t.Run("invalid role rejected 400", func(t *testing.T) {
		app := teamBlockApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
		status, body := teamBlockReq(t, app, http.MethodPost, "/api/v1/team/members/invite",
			map[string]any{"email": "y-" + uuid.NewString()[:8] + "@instant.dev", "role": "superuser"})
		require.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "invalid_role", body["error"])
	})
}

// ─────────────────────────────────────────────────────────────────────────
// POST /api/v1/team/members/leave — TeamMembersHandler.LeaveTeam  (F5)
// ─────────────────────────────────────────────────────────────────────────

func TestTeamBlock_LeaveTeam(t *testing.T) {
	teamBlockSkipNoDB(t)
	db, cleanup := teamBlockDB(t)
	defer cleanup()
	teamID, ownerID := teamBlockSeedTeamOwner(t, db, "pro")

	t.Run("non-primary member leaves successfully", func(t *testing.T) {
		memberID := teamBlockAddMember(t, db, teamID, "developer")
		app := teamBlockApp(t, db, miniRedis(t), memberID.String(), teamID.String())
		status, body := teamBlockReq(t, app, http.MethodPost, "/api/v1/team/members/leave", nil)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, true, body["ok"])
	})

	t.Run("sole owner cannot leave (409)", func(t *testing.T) {
		app := teamBlockApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
		status, _ := teamBlockReq(t, app, http.MethodPost, "/api/v1/team/members/leave", nil)
		require.Equal(t, http.StatusConflict, status)
	})
}

// ─────────────────────────────────────────────────────────────────────────
// DELETE /api/v1/team/members/:user_id — TeamMembersHandler.RemoveMember  (F4)
// ─────────────────────────────────────────────────────────────────────────

func TestTeamBlock_RemoveMember(t *testing.T) {
	teamBlockSkipNoDB(t)
	db, cleanup := teamBlockDB(t)
	defer cleanup()
	teamID, ownerID := teamBlockSeedTeamOwner(t, db, "pro")

	t.Run("owner removes a member", func(t *testing.T) {
		memberID := teamBlockAddMember(t, db, teamID, "developer")
		app := teamBlockApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
		status, body := teamBlockReq(t, app, http.MethodDelete, "/api/v1/team/members/"+memberID.String(), nil)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, true, body["ok"])
	})

	t.Run("non-owner forbidden", func(t *testing.T) {
		targetID := teamBlockAddMember(t, db, teamID, "viewer")
		adminID := teamBlockAddMember(t, db, teamID, "admin")
		app := teamBlockApp(t, db, miniRedis(t), adminID.String(), teamID.String())
		status, _ := teamBlockReq(t, app, http.MethodDelete, "/api/v1/team/members/"+targetID.String(), nil)
		require.Equal(t, http.StatusForbidden, status)
	})

	t.Run("invalid user id 400", func(t *testing.T) {
		app := teamBlockApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
		status, _ := teamBlockReq(t, app, http.MethodDelete, "/api/v1/team/members/not-a-uuid", nil)
		require.Equal(t, http.StatusBadRequest, status)
	})
}

// ─────────────────────────────────────────────────────────────────────────
// PATCH /api/v1/team/members/:user_id — TeamMembersHandler.UpdateRole  (F4)
// ─────────────────────────────────────────────────────────────────────────

func TestTeamBlock_UpdateMemberRole(t *testing.T) {
	teamBlockSkipNoDB(t)
	db, cleanup := teamBlockDB(t)
	defer cleanup()
	teamID, ownerID := teamBlockSeedTeamOwner(t, db, "pro")

	t.Run("owner promotes developer to admin and it persists", func(t *testing.T) {
		memberID := teamBlockAddMember(t, db, teamID, "developer")
		app := teamBlockApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
		status, body := teamBlockReq(t, app, http.MethodPatch, "/api/v1/team/members/"+memberID.String(),
			map[string]any{"role": "admin"})
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, "admin", body["role"])
		assert.Equal(t, "admin", teamBlockUserRole(t, db, teamID, memberID))
	})

	t.Run("cannot assign owner role via PATCH (400)", func(t *testing.T) {
		memberID := teamBlockAddMember(t, db, teamID, "developer")
		app := teamBlockApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
		status, _ := teamBlockReq(t, app, http.MethodPatch, "/api/v1/team/members/"+memberID.String(),
			map[string]any{"role": "owner"})
		require.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("non-owner forbidden", func(t *testing.T) {
		targetID := teamBlockAddMember(t, db, teamID, "viewer")
		adminID := teamBlockAddMember(t, db, teamID, "admin")
		app := teamBlockApp(t, db, miniRedis(t), adminID.String(), teamID.String())
		status, _ := teamBlockReq(t, app, http.MethodPatch, "/api/v1/team/members/"+targetID.String(),
			map[string]any{"role": "developer"})
		require.Equal(t, http.StatusForbidden, status)
	})
}

// ─────────────────────────────────────────────────────────────────────────
// POST /api/v1/team/members/:user_id/promote-to-primary
//   TeamMembersHandler.PromoteToPrimary  (F6)
// ─────────────────────────────────────────────────────────────────────────

func TestTeamBlock_PromoteToPrimary(t *testing.T) {
	teamBlockSkipNoDB(t)
	db, cleanup := teamBlockDB(t)
	defer cleanup()
	teamID, ownerID := teamBlockSeedTeamOwner(t, db, "pro")

	t.Run("owner transfers primary to another member", func(t *testing.T) {
		memberID := teamBlockAddMember(t, db, teamID, "admin")
		app := teamBlockApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
		status, body := teamBlockReq(t, app, http.MethodPost,
			"/api/v1/team/members/"+memberID.String()+"/promote-to-primary", nil)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, memberID.String(), body["primary_user_id"])
		// New primary is now owner.
		assert.Equal(t, "owner", teamBlockUserRole(t, db, teamID, memberID))
	})

	t.Run("non-owner forbidden", func(t *testing.T) {
		targetID := teamBlockAddMember(t, db, teamID, "viewer")
		adminID := teamBlockAddMember(t, db, teamID, "admin")
		app := teamBlockApp(t, db, miniRedis(t), adminID.String(), teamID.String())
		status, _ := teamBlockReq(t, app, http.MethodPost,
			"/api/v1/team/members/"+targetID.String()+"/promote-to-primary", nil)
		require.Equal(t, http.StatusForbidden, status)
	})
}

// ─────────────────────────────────────────────────────────────────────────
// GET /api/v1/team/invitations + DELETE /api/v1/team/invitations/:id
//   TeamMembersHandler.ListInvitations / RevokeInvitation  (F2)
// ─────────────────────────────────────────────────────────────────────────

func TestTeamBlock_Invitations(t *testing.T) {
	teamBlockSkipNoDB(t)
	db, cleanup := teamBlockDB(t)
	defer cleanup()
	teamID, ownerID := teamBlockSeedTeamOwner(t, db, "team")

	// Seed one pending RBAC invitation directly via the model.
	inv, err := models.CreateRBACInvitation(context.Background(), db, teamID,
		"pending-"+uuid.NewString()[:8]+"@instant.dev", "developer", ownerID)
	require.NoError(t, err)

	t.Run("owner lists pending invitations", func(t *testing.T) {
		app := teamBlockApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
		status, body := teamBlockReq(t, app, http.MethodGet, "/api/v1/team/invitations", nil)
		require.Equal(t, http.StatusOK, status)
		invs, ok := body["invitations"].([]any)
		require.True(t, ok)
		assert.GreaterOrEqual(t, len(invs), 1)
	})

	t.Run("non-owner forbidden from listing", func(t *testing.T) {
		devID := teamBlockAddMember(t, db, teamID, "developer")
		app := teamBlockApp(t, db, miniRedis(t), devID.String(), teamID.String())
		status, _ := teamBlockReq(t, app, http.MethodGet, "/api/v1/team/invitations", nil)
		require.Equal(t, http.StatusForbidden, status)
	})

	t.Run("owner revokes the invitation", func(t *testing.T) {
		app := teamBlockApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
		status, body := teamBlockReq(t, app, http.MethodDelete,
			"/api/v1/team/invitations/"+inv.ID.String(), nil)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, true, body["ok"])
	})

	t.Run("cross-team invitation cannot be revoked", func(t *testing.T) {
		// Another team's owner + invitation.
		otherTeamID, otherOwnerID := teamBlockSeedTeamOwner(t, db, "team")
		otherInv, err := models.CreateRBACInvitation(context.Background(), db, otherTeamID,
			"other-"+uuid.NewString()[:8]+"@instant.dev", "developer", otherOwnerID)
		require.NoError(t, err)
		// Our owner tries to revoke the OTHER team's invitation id.
		app := teamBlockApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
		status, _ := teamBlockReq(t, app, http.MethodDelete,
			"/api/v1/team/invitations/"+otherInv.ID.String(), nil)
		assert.True(t, teamBlockNotFoundOK(status), "cross-team revoke must be refused, got %d", status)
	})
}

// ─────────────────────────────────────────────────────────────────────────
// POST /api/v1/team/invitations/:id/accept
//   TeamMembersHandler.AcceptInvitation  (F3, by-id authed variant)
// ─────────────────────────────────────────────────────────────────────────

func TestTeamBlock_AcceptInvitationByID(t *testing.T) {
	teamBlockSkipNoDB(t)
	db, cleanup := teamBlockDB(t)
	defer cleanup()
	teamID, ownerID := teamBlockSeedTeamOwner(t, db, "team")

	t.Run("unknown invitation id returns 404", func(t *testing.T) {
		app := teamBlockApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
		status, _ := teamBlockReq(t, app, http.MethodPost,
			"/api/v1/team/invitations/"+uuid.NewString()+"/accept", nil)
		require.Equal(t, http.StatusNotFound, status)
	})

	t.Run("unauthenticated returns 401", func(t *testing.T) {
		app := teamBlockApp(t, db, miniRedis(t), "", "")
		status, _ := teamBlockReq(t, app, http.MethodPost,
			"/api/v1/team/invitations/"+uuid.NewString()+"/accept", nil)
		require.Equal(t, http.StatusUnauthorized, status)
	})
}

// ─────────────────────────────────────────────────────────────────────────
// DELETE /api/v1/teams/:team_id/invitations/:id
//   TeamsHandler.RevokeInvitation (plural-teams alias, admin-only)  (F2)
// ─────────────────────────────────────────────────────────────────────────

func TestTeamBlock_TeamsAliasRevokeInvitation(t *testing.T) {
	teamBlockSkipNoDB(t)
	db, cleanup := teamBlockDB(t)
	defer cleanup()
	teamID, ownerID := teamBlockSeedTeamOwner(t, db, "team")

	inv, err := models.CreateRBACInvitation(context.Background(), db, teamID,
		"alias-"+uuid.NewString()[:8]+"@instant.dev", "developer", ownerID)
	require.NoError(t, err)

	t.Run("admin revokes via plural-teams alias", func(t *testing.T) {
		adminID := teamBlockAddMember(t, db, teamID, "admin")
		app := teamBlockApp(t, db, miniRedis(t), adminID.String(), teamID.String())
		status, body := teamBlockReq(t, app, http.MethodDelete,
			"/api/v1/teams/"+teamID.String()+"/invitations/"+inv.ID.String(), nil)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, true, body["ok"])
	})

	t.Run("developer forbidden (RequireRole admin)", func(t *testing.T) {
		inv2, err := models.CreateRBACInvitation(context.Background(), db, teamID,
			"alias2-"+uuid.NewString()[:8]+"@instant.dev", "developer", ownerID)
		require.NoError(t, err)
		devID := teamBlockAddMember(t, db, teamID, "developer")
		app := teamBlockApp(t, db, miniRedis(t), devID.String(), teamID.String())
		status, _ := teamBlockReq(t, app, http.MethodDelete,
			"/api/v1/teams/"+teamID.String()+"/invitations/"+inv2.ID.String(), nil)
		require.Equal(t, http.StatusForbidden, status)
	})

	t.Run("cross-team path team_id mismatch refused", func(t *testing.T) {
		otherTeamID, _ := teamBlockSeedTeamOwner(t, db, "team")
		adminID := teamBlockAddMember(t, db, teamID, "admin")
		app := teamBlockApp(t, db, miniRedis(t), adminID.String(), teamID.String())
		// Admin of teamID tries to act on otherTeamID's path — requireTeamMatch
		// 403s because the path team_id != the session team_id.
		status, _ := teamBlockReq(t, app, http.MethodDelete,
			"/api/v1/teams/"+otherTeamID.String()+"/invitations/"+uuid.NewString(), nil)
		require.Equal(t, http.StatusForbidden, status)
	})
}
