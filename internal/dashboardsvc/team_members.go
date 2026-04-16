package dashboardsvc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"instant.dev/internal/models"
	dashboardv1 "instant.dev/proto/dashboard/v1"
)

func teamMemberGRPCError(err error) error {
	switch {
	case errors.Is(err, models.ErrNotTeamOwner):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, models.ErrCannotRemoveOwner):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, models.ErrOwnerCannotLeave):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, models.ErrInvitationNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, models.ErrInvitationExpired):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, models.ErrInvitationNotPending):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, models.ErrEmailMismatchInvite):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, models.ErrMemberLimitReached):
		return status.Error(codes.ResourceExhausted, err.Error())
	case errors.Is(err, models.ErrAlreadyTeamMember):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, models.ErrInvalidInviteRole):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, models.ErrDuplicatePendingInvite):
		return status.Error(codes.AlreadyExists, err.Error())
	default:
		var notFound *models.ErrUserNotFound
		if errors.As(err, &notFound) {
			return status.Error(codes.NotFound, notFound.Error())
		}
		return status.Error(codes.Internal, err.Error())
	}
}

func (s *Server) teamPlanTier(ctx context.Context, teamID uuid.UUID) (string, error) {
	var tier string
	err := s.db.QueryRowContext(ctx, `SELECT plan_tier FROM teams WHERE id = $1`, teamID).Scan(&tier)
	if err != nil {
		return "", err
	}
	return tier, nil
}

func invitationToProto(inv *models.TeamInvitation) *dashboardv1.TeamInvitation {
	if inv == nil {
		return nil
	}
	return &dashboardv1.TeamInvitation{
		Id:        inv.ID.String(),
		Email:     inv.Email,
		Role:      inv.Role,
		Status:    inv.Status,
		InvitedBy: inv.InvitedBy.String(),
		CreatedAt: inv.CreatedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt: inv.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}
}

func (s *Server) requireTeamOwner(ctx context.Context, teamID uuid.UUID) error {
	authUser, err := authUserID(ctx)
	if err != nil {
		return err
	}
	role, err := models.GetUserRole(ctx, s.db, teamID, authUser)
	if err != nil {
		return status.Error(codes.Internal, "role lookup failed")
	}
	if role != "owner" {
		return status.Error(codes.PermissionDenied, "owner only")
	}
	return nil
}

// ListMembers implements dashboard.v1.DashboardService/ListMembers.
func (s *Server) ListMembers(ctx context.Context, req *dashboardv1.ListMembersRequest) (*dashboardv1.ListMembersResponse, error) {
	teamID, err := s.requireMatchingTeam(ctx, req.GetTeamId())
	if err != nil {
		return nil, err
	}
	if err := s.requireMatchingUser(ctx, req.GetUserId()); err != nil {
		return nil, err
	}
	authUser, err := authUserID(ctx)
	if err != nil {
		return nil, err
	}
	role, err := models.GetUserRole(ctx, s.db, teamID, authUser)
	if err != nil {
		return nil, status.Error(codes.Internal, "role lookup failed")
	}
	if role != "owner" && role != "member" {
		return nil, status.Error(codes.PermissionDenied, "not a member of this team")
	}

	members, err := models.ListTeamMembers(ctx, s.db, teamID)
	if err != nil {
		slog.Error("dashboardsvc.ListMembers.query_failed", "error", err, "team_id", teamID)
		return nil, status.Error(codes.Internal, "list members failed")
	}
	tier, err := s.teamPlanTier(ctx, teamID)
	if err != nil {
		slog.Error("dashboardsvc.ListMembers.tier_failed", "error", err, "team_id", teamID)
		return nil, status.Error(codes.Internal, "team tier lookup failed")
	}
	limit := int32(s.plans.TeamMemberLimit(tier))

	out := make([]*dashboardv1.TeamMember, 0, len(members))
	for _, m := range members {
		out = append(out, &dashboardv1.TeamMember{
			Id:        m.ID.String(),
			Email:     m.Email,
			Role:      m.Role,
			CreatedAt: m.CreatedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	return &dashboardv1.ListMembersResponse{Members: out, MemberLimit: limit}, nil
}

// InviteMember implements dashboard.v1.DashboardService/InviteMember.
func (s *Server) InviteMember(ctx context.Context, req *dashboardv1.InviteMemberRequest) (*dashboardv1.InviteMemberResponse, error) {
	teamID, err := s.requireMatchingTeam(ctx, req.GetTeamId())
	if err != nil {
		return nil, err
	}
	if err := s.requireMatchingUser(ctx, req.GetUserId()); err != nil {
		return nil, err
	}
	if err := s.requireTeamOwner(ctx, teamID); err != nil {
		return nil, err
	}
	authUser, err := authUserID(ctx)
	if err != nil {
		return nil, err
	}

	role := strings.TrimSpace(strings.ToLower(req.GetRole()))
	if role == "" {
		role = "member"
	}
	tier, err := s.teamPlanTier(ctx, teamID)
	if err != nil {
		return nil, status.Error(codes.Internal, "team tier lookup failed")
	}
	limit := s.plans.TeamMemberLimit(tier)

	inv, err := models.InviteMember(ctx, s.db, teamID, req.GetEmail(), role, authUser, limit)
	if err != nil {
		return nil, teamMemberGRPCError(err)
	}

	teamRow, err := models.GetTeamByID(ctx, s.db, teamID)
	if err != nil {
		slog.Warn("dashboardsvc.InviteMember.team_name_failed", "error", err, "team_id", teamID)
	}
	teamName := ""
	if teamRow != nil && teamRow.Name.Valid {
		teamName = teamRow.Name.String
	}
	if s.mail != nil {
		base := strings.TrimRight(s.cfg.DashboardBaseURL, "/")
		acceptURL := fmt.Sprintf("%s/settings?section=team&invite=%s", base, inv.ID.String())
		if err := s.mail.SendTeamInvite(ctx, inv.Email, teamName, acceptURL); err != nil {
			slog.Warn("dashboardsvc.InviteMember.email_failed", "error", err, "invitation_id", inv.ID)
		}
	}

	return &dashboardv1.InviteMemberResponse{Invitation: invitationToProto(inv)}, nil
}

// RemoveMember implements dashboard.v1.DashboardService/RemoveMember.
func (s *Server) RemoveMember(ctx context.Context, req *dashboardv1.RemoveMemberRequest) (*dashboardv1.RemoveMemberResponse, error) {
	teamID, err := s.requireMatchingTeam(ctx, req.GetTeamId())
	if err != nil {
		return nil, err
	}
	if err := s.requireMatchingUser(ctx, req.GetUserId()); err != nil {
		return nil, err
	}
	if err := s.requireTeamOwner(ctx, teamID); err != nil {
		return nil, err
	}
	target, err := uuid.Parse(req.GetTargetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid target_user_id")
	}
	if err := models.RemoveMember(ctx, s.db, teamID, target); err != nil {
		return nil, teamMemberGRPCError(err)
	}
	return &dashboardv1.RemoveMemberResponse{Ok: true}, nil
}

// ListInvitations implements dashboard.v1.DashboardService/ListInvitations.
func (s *Server) ListInvitations(ctx context.Context, req *dashboardv1.ListInvitationsRequest) (*dashboardv1.ListInvitationsResponse, error) {
	teamID, err := s.requireMatchingTeam(ctx, req.GetTeamId())
	if err != nil {
		return nil, err
	}
	if err := s.requireMatchingUser(ctx, req.GetUserId()); err != nil {
		return nil, err
	}
	if err := s.requireTeamOwner(ctx, teamID); err != nil {
		return nil, err
	}
	invs, err := models.ListInvitations(ctx, s.db, teamID)
	if err != nil {
		slog.Error("dashboardsvc.ListInvitations.query_failed", "error", err, "team_id", teamID)
		return nil, status.Error(codes.Internal, "list invitations failed")
	}
	out := make([]*dashboardv1.TeamInvitation, 0, len(invs))
	for i := range invs {
		out = append(out, invitationToProto(&invs[i]))
	}
	return &dashboardv1.ListInvitationsResponse{Invitations: out}, nil
}

// RevokeInvitation implements dashboard.v1.DashboardService/RevokeInvitation.
func (s *Server) RevokeInvitation(ctx context.Context, req *dashboardv1.RevokeInvitationRequest) (*dashboardv1.RevokeInvitationResponse, error) {
	teamID, err := s.requireMatchingTeam(ctx, req.GetTeamId())
	if err != nil {
		return nil, err
	}
	if err := s.requireMatchingUser(ctx, req.GetUserId()); err != nil {
		return nil, err
	}
	if err := s.requireTeamOwner(ctx, teamID); err != nil {
		return nil, err
	}
	invID, err := uuid.Parse(req.GetInvitationId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid invitation_id")
	}
	inv, err := models.GetInvitationByID(ctx, s.db, invID)
	if err != nil {
		return nil, teamMemberGRPCError(err)
	}
	if inv.TeamID != teamID {
		return nil, status.Error(codes.PermissionDenied, "invitation does not belong to this team")
	}
	if err := models.RevokeInvitation(ctx, s.db, invID); err != nil {
		return nil, teamMemberGRPCError(err)
	}
	return &dashboardv1.RevokeInvitationResponse{Ok: true}, nil
}

// AcceptInvitation implements dashboard.v1.DashboardService/AcceptInvitation.
func (s *Server) AcceptInvitation(ctx context.Context, req *dashboardv1.AcceptInvitationRequest) (*dashboardv1.AcceptInvitationResponse, error) {
	authUser, err := authUserID(ctx)
	if err != nil {
		return nil, err
	}
	invID, err := uuid.Parse(req.GetInvitationId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid invitation_id")
	}
	inv, err := models.GetInvitationByID(ctx, s.db, invID)
	if err != nil {
		return nil, teamMemberGRPCError(err)
	}
	tier, err := s.teamPlanTier(ctx, inv.TeamID)
	if err != nil {
		return nil, status.Error(codes.Internal, "team tier lookup failed")
	}
	limit := s.plans.TeamMemberLimit(tier)
	if err := models.AcceptInvitation(ctx, s.db, invID, authUser, limit); err != nil {
		return nil, teamMemberGRPCError(err)
	}
	return &dashboardv1.AcceptInvitationResponse{Ok: true}, nil
}

// LeaveTeam implements dashboard.v1.DashboardService/LeaveTeam.
func (s *Server) LeaveTeam(ctx context.Context, req *dashboardv1.LeaveTeamRequest) (*dashboardv1.LeaveTeamResponse, error) {
	teamID, err := s.requireMatchingTeam(ctx, req.GetTeamId())
	if err != nil {
		return nil, err
	}
	if err := s.requireMatchingUser(ctx, req.GetUserId()); err != nil {
		return nil, err
	}
	authUser, err := authUserID(ctx)
	if err != nil {
		return nil, err
	}
	if err := models.LeaveTeam(ctx, s.db, teamID, authUser); err != nil {
		return nil, teamMemberGRPCError(err)
	}
	return &dashboardv1.LeaveTeamResponse{Ok: true}, nil
}
