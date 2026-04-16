package dashboardsvc

import (
	"context"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ctxKey int

const (
	ctxKeyTeamID ctxKey = iota + 1
	ctxKeyUserID
)

func contextWithAuth(ctx context.Context, teamID, userID uuid.UUID) context.Context {
	ctx = context.WithValue(ctx, ctxKeyTeamID, teamID)
	ctx = context.WithValue(ctx, ctxKeyUserID, userID)
	return ctx
}

func authTeamID(ctx context.Context) (uuid.UUID, error) {
	v := ctx.Value(ctxKeyTeamID)
	t, ok := v.(uuid.UUID)
	if !ok || v == nil {
		return uuid.Nil, status.Error(codes.Unauthenticated, "not authenticated")
	}
	return t, nil
}

func authUserID(ctx context.Context) (uuid.UUID, error) {
	v := ctx.Value(ctxKeyUserID)
	u, ok := v.(uuid.UUID)
	if !ok || v == nil {
		return uuid.Nil, status.Error(codes.Unauthenticated, "not authenticated")
	}
	return u, nil
}

