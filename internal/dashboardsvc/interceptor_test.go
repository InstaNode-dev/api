package dashboardsvc

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"instant.dev/internal/testhelpers"
)

func TestAuthInterceptor_MissingMetadata(t *testing.T) {
	t.Parallel()
	iv := AuthInterceptor(testhelpers.TestJWTSecret)
	_, err := iv(context.Background(), nil, &grpc.UnaryServerInfo{}, func(context.Context, interface{}) (interface{}, error) {
		t.Fatal("handler must not run")
		return nil, nil
	})
	require.Error(t, err)
	require.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestAuthInterceptor_MissingAuthorization(t *testing.T) {
	t.Parallel()
	iv := AuthInterceptor(testhelpers.TestJWTSecret)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-other", "x"))
	_, err := iv(ctx, nil, &grpc.UnaryServerInfo{}, func(context.Context, interface{}) (interface{}, error) {
		t.Fatal("handler must not run")
		return nil, nil
	})
	require.Error(t, err)
	require.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestAuthInterceptor_InvalidScheme(t *testing.T) {
	t.Parallel()
	iv := AuthInterceptor(testhelpers.TestJWTSecret)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Basic abc"))
	_, err := iv(ctx, nil, &grpc.UnaryServerInfo{}, func(context.Context, interface{}) (interface{}, error) {
		t.Fatal("handler must not run")
		return nil, nil
	})
	require.Error(t, err)
	require.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestAuthInterceptor_InvalidJWT(t *testing.T) {
	t.Parallel()
	iv := AuthInterceptor(testhelpers.TestJWTSecret)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer not-a-jwt"))
	_, err := iv(ctx, nil, &grpc.UnaryServerInfo{}, func(context.Context, interface{}) (interface{}, error) {
		t.Fatal("handler must not run")
		return nil, nil
	})
	require.Error(t, err)
	require.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestAuthInterceptor_ValidJWT_SetsActor(t *testing.T) {
	t.Parallel()
	teamID := uuid.New()
	userID := uuid.New()
	tok := testhelpers.MustSignSessionJWT(t, userID.String(), teamID.String(), "a@b.com")
	iv := AuthInterceptor(testhelpers.TestJWTSecret)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+tok))

	var sawTeam, sawUser uuid.UUID
	_, err := iv(ctx, nil, &grpc.UnaryServerInfo{}, func(ctx context.Context, _ interface{}) (interface{}, error) {
		var err2 error
		sawTeam, err2 = authTeamID(ctx)
		if err2 != nil {
			return nil, err2
		}
		sawUser, err2 = authUserID(ctx)
		return nil, err2
	})
	require.NoError(t, err)
	require.Equal(t, teamID, sawTeam)
	require.Equal(t, userID, sawUser)
}

func TestAuthInterceptor_BearerCaseInsensitive(t *testing.T) {
	t.Parallel()
	teamID := uuid.New()
	userID := uuid.New()
	tok := testhelpers.MustSignSessionJWT(t, userID.String(), teamID.String(), "a@b.com")
	iv := AuthInterceptor(testhelpers.TestJWTSecret)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "bearer "+tok))

	_, err := iv(ctx, nil, &grpc.UnaryServerInfo{}, func(ctx context.Context, _ interface{}) (interface{}, error) {
		tid, err2 := authTeamID(ctx)
		if err2 != nil {
			return nil, err2
		}
		uid, err2 := authUserID(ctx)
		if err2 != nil {
			return nil, err2
		}
		require.Equal(t, teamID, tid)
		require.Equal(t, userID, uid)
		return nil, nil
	})
	require.NoError(t, err)
}
