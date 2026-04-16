package dashboardsvc

import (
	"context"
	"errors"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// sessionClaims mirrors middleware.sessionClaims (JWT issued after OAuth / CLI auth).
type sessionClaims struct {
	UserID string `json:"uid"`
	TeamID string `json:"tid"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

func (c sessionClaims) Valid() error {
	c.RegisteredClaims.IssuedAt = nil
	return c.RegisteredClaims.Valid()
}

// AuthInterceptor validates the gRPC "authorization" metadata (Bearer JWT) the same
// way HTTP RequireAuth does, then attaches team_id and user_id to the context.
func AuthInterceptor(jwtSecret string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}
		vals := md.Get("authorization")
		if len(vals) != 1 {
			return nil, status.Error(codes.Unauthenticated, "missing authorization")
		}
		header := strings.TrimSpace(vals[0])
		const bearerPrefix = "Bearer "
		if len(header) < len(bearerPrefix) || !strings.EqualFold(header[:len(bearerPrefix)], bearerPrefix) {
			return nil, status.Error(codes.Unauthenticated, "invalid authorization scheme")
		}
		tokenStr := strings.TrimSpace(header[len(bearerPrefix):])

		claims := &sessionClaims{}
		parsed, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(jwtSecret), nil
		})
		if err != nil || !parsed.Valid {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}
		if claims.UserID == "" || claims.TeamID == "" {
			return nil, status.Error(codes.Unauthenticated, "invalid token claims")
		}

		teamID, err := uuid.Parse(claims.TeamID)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid team in token")
		}
		userID, err := uuid.Parse(claims.UserID)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid user in token")
		}

		ctx = contextWithAuth(ctx, teamID, userID)
		return handler(ctx, req)
	}
}
