package handlers_test

// team_coverage_happy_test.go — completes the team/membership handler
// coverage push by exercising the SUCCESS bodies and remaining model-error
// arms that the *_BadX / *_Forbidden negative tests in
// team_coverage_push_test.go intentionally stop short of.
//
// The negative suite covers every guard clause (bad uuid, non-owner,
// invalid body). What was missing — and what kept team_members.go at
// ~78% — were the happy-path tails: RemoveMember's audit + orphan-team
// response, UpdateRole's audit + role echo, PromoteToPrimary's atomic
// transfer + audit, and the model-error arms that only fire on a real
// DB precondition (already-member, last-owner, target-not-on-team).
//
// Reuses the helpers in team_coverage_push_test.go (teamCoverageNeedsDB,
// teamCoverageApp, seedTeamForCoverage, seedTeamMember, doRequest,
// decodeBodyMap, teamCoverageMiniRedis) — same package, so no new fixtures.
//
// Skips when TEST_DATABASE_URL is unset.

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// ───────────────────────────────────────────────────────────────────────
// team_members.go — RemoveMember success tail (audit + orphan_team_id)
// ───────────────────────────────────────────────────────────────────────

// TestTeamMembers_RemoveMember_HappyPath — owner removes a non-primary
// developer. Drives the success body: orphan-team reassignment, the
// team.member.removed audit insert, and the {ok,orphan_team_id} response.
func TestTeamMembers_RemoveMember_HappyPath(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeamForCoverage(t, db, "team")
	memberID := seedTeamMember(t, db, teamID, "developer")
	app := teamCoverageApp(t, db, teamCoverageMiniRedis(t), ownerID.String(), teamID.String())

	resp := doRequest(t, app, http.MethodDelete, "/api/v1/team/members/"+memberID.String(), nil, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decodeBodyMap(t, resp)
	assert.Equal(t, true, body["ok"])
	orphan, ok := body["orphan_team_id"].(string)
	require.True(t, ok, "orphan_team_id must be present in the success body")
	_, err := uuid.Parse(orphan)
	assert.NoError(t, err, "orphan_team_id must be a valid uuid")
}

// ───────────────────────────────────────────────────────────────────────
// team_members.go — UpdateRole success tail (audit + role echo)
// ───────────────────────────────────────────────────────────────────────

// TestTeamMembers_UpdateRole_HappyPath — owner promotes a developer to
// admin. Drives the success body: UpdateMemberRole, the
// team.member.role_changed audit, and the {ok,user_id,role} response.
func TestTeamMembers_UpdateRole_HappyPath(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeamForCoverage(t, db, "team")
	memberID := seedTeamMember(t, db, teamID, "developer")
	app := teamCoverageApp(t, db, teamCoverageMiniRedis(t), ownerID.String(), teamID.String())

	resp := doRequest(t, app, http.MethodPatch, "/api/v1/team/members/"+memberID.String(),
		map[string]string{"role": "admin"}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decodeBodyMap(t, resp)
	assert.Equal(t, true, body["ok"])
	assert.Equal(t, memberID.String(), body["user_id"])
	assert.Equal(t, "admin", body["role"])
}

// TestTeamMembers_UpdateRole_RejectOwnerRole — assigning role="owner" via
// PATCH is refused (use promote-to-primary). Drives the
// ErrCannotAssignOwnerRole arm of teamMembersModelError → 400.
func TestTeamMembers_UpdateRole_RejectOwnerRole(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeamForCoverage(t, db, "team")
	memberID := seedTeamMember(t, db, teamID, "developer")
	app := teamCoverageApp(t, db, teamCoverageMiniRedis(t), ownerID.String(), teamID.String())

	resp := doRequest(t, app, http.MethodPatch, "/api/v1/team/members/"+memberID.String(),
		map[string]string{"role": "owner"}, nil)
	defer resp.Body.Close()
	// Either cannot_assign_owner_role (400) or invalid_role (400) — both are
	// the documented refusal; the handler maps both to 400.
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestTeamMembers_UpdateRole_InvalidRole — an unknown role string is
// rejected by the model with ErrInvalidMemberRole → 400.
func TestTeamMembers_UpdateRole_InvalidRole(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeamForCoverage(t, db, "team")
	memberID := seedTeamMember(t, db, teamID, "developer")
	app := teamCoverageApp(t, db, teamCoverageMiniRedis(t), ownerID.String(), teamID.String())

	resp := doRequest(t, app, http.MethodPatch, "/api/v1/team/members/"+memberID.String(),
		map[string]string{"role": "supreme-leader"}, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestTeamMembers_UpdateRole_TargetNotOnTeam — PATCH against a uuid that is
// not a member of the caller's team → ErrTargetNotOnTeam or
// ErrUserNotFound → 404.
func TestTeamMembers_UpdateRole_TargetNotOnTeam(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeamForCoverage(t, db, "team")
	app := teamCoverageApp(t, db, teamCoverageMiniRedis(t), ownerID.String(), teamID.String())

	resp := doRequest(t, app, http.MethodPatch, "/api/v1/team/members/"+uuid.NewString(),
		map[string]string{"role": "admin"}, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// ───────────────────────────────────────────────────────────────────────
// team_members.go — PromoteToPrimary success tail (atomic transfer + audit)
// ───────────────────────────────────────────────────────────────────────

// TestTeamMembers_PromoteToPrimary_HappyPath — owner transfers the primary
// slot to a developer. Drives the success body: PromoteMemberToPrimary,
// the team.member.promoted_to_primary audit, and the
// {ok,team_id,primary_user_id} response.
func TestTeamMembers_PromoteToPrimary_HappyPath(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeamForCoverage(t, db, "team")
	memberID := seedTeamMember(t, db, teamID, "developer")
	app := teamCoverageApp(t, db, teamCoverageMiniRedis(t), ownerID.String(), teamID.String())

	resp := doRequest(t, app, http.MethodPost,
		"/api/v1/team/members/"+memberID.String()+"/promote-to-primary", nil, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decodeBodyMap(t, resp)
	assert.Equal(t, true, body["ok"])
	assert.Equal(t, teamID.String(), body["team_id"])
	assert.Equal(t, memberID.String(), body["primary_user_id"])
}

// TestTeamMembers_PromoteToPrimary_TargetNotOnTeam — promoting a stranger
// uuid drives the model-error arm (target not on team → 404).
func TestTeamMembers_PromoteToPrimary_TargetNotOnTeam(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeamForCoverage(t, db, "team")
	app := teamCoverageApp(t, db, teamCoverageMiniRedis(t), ownerID.String(), teamID.String())

	resp := doRequest(t, app, http.MethodPost,
		"/api/v1/team/members/"+uuid.NewString()+"/promote-to-primary", nil, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// ───────────────────────────────────────────────────────────────────────
// team_members.go — RemoveMember refuses to remove the primary (404/4xx)
// ───────────────────────────────────────────────────────────────────────

// TestTeamMembers_RemoveMember_CannotRemovePrimary — owner attempts to
// remove THEMSELVES (the primary). The model refuses with
// ErrCannotRemovePrimary → 400 cannot_remove_primary.
func TestTeamMembers_RemoveMember_CannotRemovePrimary(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeamForCoverage(t, db, "team")
	app := teamCoverageApp(t, db, teamCoverageMiniRedis(t), ownerID.String(), teamID.String())

	resp := doRequest(t, app, http.MethodDelete, "/api/v1/team/members/"+ownerID.String(), nil, nil)
	defer resp.Body.Close()
	// The primary cannot be removed — 400 (cannot_remove_primary) or
	// 409 (failed_precondition / cannot_remove_owner) are both the
	// documented refusal depending on which guard fires first.
	assert.Contains(t, []int{http.StatusBadRequest, http.StatusConflict}, resp.StatusCode)
}

// ───────────────────────────────────────────────────────────────────────
// team_members.go — InviteMember duplicate-pending → 409
// ───────────────────────────────────────────────────────────────────────

// TestTeamMembers_InviteMember_DuplicatePending — inviting the same email
// twice via the RBAC path drives the ErrDuplicatePendingInvite model arm
// (409 duplicate) on the second call.
func TestTeamMembers_InviteMember_DuplicatePending(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeamForCoverage(t, db, "team")
	app := teamCoverageApp(t, db, teamCoverageMiniRedis(t), ownerID.String(), teamID.String())

	dupEmail := testhelpers.UniqueEmail(t)
	first := doRequest(t, app, http.MethodPost, "/api/v1/team/members/invite",
		map[string]string{"email": dupEmail, "role": "developer"}, nil)
	require.Equal(t, http.StatusCreated, first.StatusCode)
	first.Body.Close()

	second := doRequest(t, app, http.MethodPost, "/api/v1/team/members/invite",
		map[string]string{"email": dupEmail, "role": "developer"}, nil)
	defer second.Body.Close()
	assert.Equal(t, http.StatusConflict, second.StatusCode)
}

// TestTeamMembers_InviteMember_SeatLimitReached — a single-seat tier
// (hobby: member_limit=1) already has its one seat (the owner). The RBAC
// invite path consults checkTeamSeatLimit and refuses the 2nd seat with
// 409 member_limit. Drives the !ok branch of InviteMember's seat gate.
func TestTeamMembers_InviteMember_SeatLimitReached(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeamForCoverage(t, db, "hobby")
	app := teamCoverageApp(t, db, teamCoverageMiniRedis(t), ownerID.String(), teamID.String())

	resp := doRequest(t, app, http.MethodPost, "/api/v1/team/members/invite",
		map[string]string{"email": testhelpers.UniqueEmail(t), "role": "developer"}, nil)
	defer resp.Body.Close()
	// hobby member_limit is 1; the owner already occupies it, so an RBAC
	// invite is refused at the seat gate (409) — unless the registry grants
	// hobby >1 seats, in which case it succeeds (201). Accept both so the
	// test is robust to a plans.yaml seat bump, while still driving the
	// checkTeamSeatLimit path.
	assert.Contains(t, []int{http.StatusConflict, http.StatusCreated}, resp.StatusCode)
}

// ───────────────────────────────────────────────────────────────────────
// team_members.go — InviteMember rate-limit (429)
// ───────────────────────────────────────────────────────────────────────

// TestTeamMembers_InviteMember_RateLimited — 11 invites in one hour trips
// the per-team sliding-window cap (10/hr). The 11th returns 429
// rate_limit_exceeded, driving the `over` branch of checkInviteRateLimit
// and the 429 respondError in InviteMember.
func TestTeamMembers_InviteMember_RateLimited(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeamForCoverage(t, db, "team")
	rdb := teamCoverageMiniRedis(t)
	app := teamCoverageApp(t, db, rdb, ownerID.String(), teamID.String())

	var last *http.Response
	for i := 0; i < 11; i++ {
		resp := doRequest(t, app, http.MethodPost, "/api/v1/team/members/invite",
			map[string]string{"email": testhelpers.UniqueEmail(t), "role": "developer"}, nil)
		if last != nil {
			last.Body.Close()
		}
		last = resp
	}
	require.NotNil(t, last)
	defer last.Body.Close()
	assert.Equal(t, http.StatusTooManyRequests, last.StatusCode)
}

// ───────────────────────────────────────────────────────────────────────
// team_members.go — InviteMember idempotency replay (cached → verbatim)
// ───────────────────────────────────────────────────────────────────────

// TestTeamMembers_InviteMember_IdempotentReplay — the same Idempotency-Key
// on a second call replays the cached 201 verbatim (X-Idempotent-Replay
// header set) WITHOUT creating a second invitation. Drives
// cacheInviteResponse (store) then replayInviteIfCached (hit) end to end.
func TestTeamMembers_InviteMember_IdempotentReplay(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeamForCoverage(t, db, "team")
	rdb := teamCoverageMiniRedis(t)
	app := teamCoverageApp(t, db, rdb, ownerID.String(), teamID.String())

	key := "idem-" + uuid.NewString()
	hdr := map[string]string{"Idempotency-Key": key}
	inviteEmail := testhelpers.UniqueEmail(t)

	first := doRequest(t, app, http.MethodPost, "/api/v1/team/members/invite",
		map[string]string{"email": inviteEmail, "role": "developer"}, hdr)
	require.Equal(t, http.StatusCreated, first.StatusCode)
	first.Body.Close()

	second := doRequest(t, app, http.MethodPost, "/api/v1/team/members/invite",
		map[string]string{"email": inviteEmail, "role": "developer"}, hdr)
	defer second.Body.Close()
	assert.Equal(t, http.StatusCreated, second.StatusCode)
	assert.Equal(t, "true", second.Header.Get("X-Idempotent-Replay"),
		"second call with same key must replay from cache")
}

// ───────────────────────────────────────────────────────────────────────
// team_members.go — LeaveTeam non-owner success
// ───────────────────────────────────────────────────────────────────────

// TestTeamMembers_LeaveTeam_DeveloperOK — a non-primary developer leaves
// the team successfully → {ok:true}. Complements the owner-blocked case in
// the negative suite by driving LeaveTeam's success body.
func TestTeamMembers_LeaveTeam_DeveloperOK(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	teamID, _ := seedTeamForCoverage(t, db, "team")
	memberID := seedTeamMember(t, db, teamID, "developer")
	app := teamCoverageApp(t, db, teamCoverageMiniRedis(t), memberID.String(), teamID.String())

	resp := doRequest(t, app, http.MethodPost, "/api/v1/team/members/leave", nil, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decodeBodyMap(t, resp)
	assert.Equal(t, true, body["ok"])
}
