package dashboardsvc

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"instant.dev/internal/models"
	dashboardv1 "instant.dev/proto/dashboard/v1"
)

func mapStackDisplayStatus(dbStatus string) string {
	switch strings.ToLower(strings.TrimSpace(dbStatus)) {
	case "healthy":
		return "running"
	case "failed":
		return "failed"
	case "stopped", "deleted", "deleting":
		return "stopped"
	default:
		return "building"
	}
}

// pickPrimaryURLAndLogService chooses the best public URL and the service name
// used for log streaming (prefer exposed services with a URL).
func pickPrimaryURLAndLogService(svcs []*models.StackService) (url, logSvc string) {
	var fallback *models.StackService
	for _, ss := range svcs {
		if ss.AppURL == "" {
			continue
		}
		if ss.Expose {
			return ss.AppURL, ss.Name
		}
		if fallback == nil {
			fallback = ss
		}
	}
	if fallback != nil {
		return fallback.AppURL, fallback.Name
	}
	return "", ""
}

func stackToDashboardProto(st *models.Stack, svcs []*models.StackService) *dashboardv1.DashboardStack {
	url, logSvc := pickPrimaryURLAndLogService(svcs)
	teamStr := ""
	if st.TeamID != nil {
		teamStr = st.TeamID.String()
	}
	return &dashboardv1.DashboardStack{
		Id:          st.ID.String(),
		Slug:        st.Slug,
		Name:        st.Name,
		Status:      mapStackDisplayStatus(st.Status),
		Url:         url,
		CreatedAt:   st.CreatedAt.UTC().Format(time.RFC3339Nano),
		TeamId:      teamStr,
		LogsService: logSvc,
	}
}

// ListStacks implements dashboard.v1.DashboardService/ListStacks.
func (s *Server) ListStacks(ctx context.Context, req *dashboardv1.ListStacksRequest) (*dashboardv1.ListStacksResponse, error) {
	teamID, err := s.requireMatchingTeam(ctx, req.GetTeamId())
	if err != nil {
		return nil, err
	}

	stacks, err := models.GetStacksByTeam(ctx, s.db, teamID)
	if err != nil {
		slog.Error("dashboardsvc.ListStacks.query_failed", "error", err, "team_id", teamID)
		return nil, status.Error(codes.Internal, "list stacks failed")
	}

	out := make([]*dashboardv1.DashboardStack, 0, len(stacks))
	for _, st := range stacks {
		svcs, svcErr := models.GetStackServicesByStack(ctx, s.db, st.ID)
		if svcErr != nil {
			slog.Error("dashboardsvc.ListStacks.services_failed", "error", svcErr, "stack_id", st.ID)
			return nil, status.Error(codes.Internal, "list stacks failed")
		}
		out = append(out, stackToDashboardProto(st, svcs))
	}

	return &dashboardv1.ListStacksResponse{
		Stacks: out,
		Total:  int64(len(out)),
	}, nil
}

// GetStack implements dashboard.v1.DashboardService/GetStack.
func (s *Server) GetStack(ctx context.Context, req *dashboardv1.GetStackRequest) (*dashboardv1.GetStackResponse, error) {
	teamID, err := s.requireMatchingTeam(ctx, req.GetTeamId())
	if err != nil {
		return nil, err
	}

	slug := strings.TrimSpace(req.GetSlug())
	if slug == "" {
		return nil, status.Error(codes.InvalidArgument, "slug required")
	}

	stack, err := models.GetStackBySlug(ctx, s.db, slug)
	if err != nil {
		var notFound *models.ErrStackNotFound
		if errors.As(err, &notFound) {
			return nil, status.Error(codes.NotFound, "stack not found")
		}
		slog.Error("dashboardsvc.GetStack.lookup_failed", "error", err, "slug", slug)
		return nil, status.Error(codes.Internal, "get stack failed")
	}
	if stack.TeamID == nil || *stack.TeamID != teamID {
		return nil, status.Error(codes.NotFound, "stack not found")
	}

	svcs, err := models.GetStackServicesByStack(ctx, s.db, stack.ID)
	if err != nil {
		slog.Error("dashboardsvc.GetStack.services_failed", "error", err, "stack_id", stack.ID)
		return nil, status.Error(codes.Internal, "get stack failed")
	}

	return &dashboardv1.GetStackResponse{Stack: stackToDashboardProto(stack, svcs)}, nil
}

// DeleteStack implements dashboard.v1.DashboardService/DeleteStack.
func (s *Server) DeleteStack(ctx context.Context, req *dashboardv1.DeleteStackRequest) (*dashboardv1.DeleteStackResponse, error) {
	teamID, err := s.requireMatchingTeam(ctx, req.GetTeamId())
	if err != nil {
		return nil, err
	}

	slug := strings.TrimSpace(req.GetSlug())
	if slug == "" {
		return nil, status.Error(codes.InvalidArgument, "slug required")
	}

	stack, err := models.GetStackBySlug(ctx, s.db, slug)
	if err != nil {
		var notFound *models.ErrStackNotFound
		if errors.As(err, &notFound) {
			return nil, status.Error(codes.NotFound, "stack not found")
		}
		slog.Error("dashboardsvc.DeleteStack.lookup_failed", "error", err, "slug", slug)
		return nil, status.Error(codes.Internal, "delete stack failed")
	}
	if stack.TeamID == nil || *stack.TeamID != teamID {
		return nil, status.Error(codes.NotFound, "stack not found")
	}

	if s.stackProv != nil {
		if teardownErr := s.stackProv.TeardownStack(ctx, stack.Namespace); teardownErr != nil {
			slog.Warn("dashboardsvc.DeleteStack.teardown_failed",
				"slug", slug, "namespace", stack.Namespace, "error", teardownErr)
		}
	} else {
		slog.Warn("dashboardsvc.DeleteStack.no_stack_provider", "slug", slug)
	}

	if delErr := models.DeleteStack(ctx, s.db, stack.ID); delErr != nil {
		slog.Error("dashboardsvc.DeleteStack.db_failed", "error", delErr, "stack_id", stack.ID)
		return nil, status.Error(codes.Internal, "delete stack failed")
	}

	return &dashboardv1.DeleteStackResponse{Ok: true}, nil
}
