package dashboardsvc

import (
	"context"
	"database/sql"
	"net"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"instant.dev/internal/config"
	"instant.dev/internal/crypto"
	"instant.dev/internal/plans"
	"instant.dev/internal/providers/compute/noop"
	"instant.dev/internal/testhelpers"
	dashboardv1 "instant.dev/proto/dashboard/v1"
)

func newTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	s, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(s.Close)
	return redis.NewClient(&redis.Options{Addr: s.Addr()})
}

func testCfg() *config.Config {
	return &config.Config{
		JWTSecret:           testhelpers.TestJWTSecret,
		AESKey:              testhelpers.TestAESKeyHex,
		CustomerDatabaseURL: "",
		MongoAdminURI:       "",
		RazorpayKeyID:       "",
		RazorpayKeySecret:   "",
		RazorpayPlanIDHobby: "plan_hobby",
		RazorpayPlanIDPro:   "plan_pro",
		RazorpayPlanIDTeam:  "plan_team",
	}
}

func dialDashboardGRPC(t *testing.T, srv *Server) (dashboardv1.DashboardServiceClient, func()) {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	grpcSrv := grpc.NewServer(grpc.UnaryInterceptor(AuthInterceptor(testhelpers.TestJWTSecret)))
	dashboardv1.RegisterDashboardServiceServer(grpcSrv, srv)
	go func() { _ = grpcSrv.Serve(lis) }()
	conn, err := grpc.DialContext(context.Background(), "bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	cl := dashboardv1.NewDashboardServiceClient(conn)
	return cl, func() {
		_ = conn.Close()
		grpcSrv.Stop()
	}
}

func grpcAuthCtx(t *testing.T, teamID, userID uuid.UUID) context.Context {
	t.Helper()
	tok := testhelpers.MustSignSessionJWT(t, userID.String(), teamID.String(), "u@example.com")
	return metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+tok))
}

func resourceSelectColumns() *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id", "team_id", "token", "resource_type", "name", "connection_url", "key_prefix", "tier",
		"fingerprint", "cloud_vendor", "country_code", "status", "migration_status",
		"expires_at", "storage_bytes", "provider_resource_id", "created_request_id", "created_at",
	})
}

func TestListResources_Success_AndStorageExceeded(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	teamID := uuid.New()
	resID := uuid.New()
	tok := uuid.New()
	created := time.Date(2025, 3, 1, 12, 0, 0, 0, time.UTC)
	// anonymous postgres limit is 10MB in plans.Default — exceed with bytes
	storageBytes := int64(11 * 1024 * 1024)

	mock.ExpectQuery(`SELECT id, token, resource_type, tier, status, name, storage_bytes`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "token", "resource_type", "tier", "status", "name", "storage_bytes",
			"cloud_vendor", "country_code", "expires_at", "created_at",
		}).AddRow(resID, tok, "postgres", "anonymous", "active", "db1", storageBytes, "aws", "US", nil, created))

	mock.ExpectQuery(`SELECT storage_bytes FROM resources WHERE id`).
		WithArgs(resID).
		WillReturnRows(sqlmock.NewRows([]string{"storage_bytes"}).AddRow(storageBytes))

	srv := NewServer(db, newTestRedis(t), testCfg(), plans.Default(), nil, nil, nil, noop.NewStack())
	client, cleanup := dialDashboardGRPC(t, srv)
	defer cleanup()

	ctx := grpcAuthCtx(t, teamID, uuid.New())
	out, err := client.ListResources(ctx, &dashboardv1.ListResourcesRequest{TeamId: teamID.String()})
	require.NoError(t, err)
	require.Len(t, out.Resources, 1)
	require.Equal(t, int64(1), out.TotalCount)
	r := out.Resources[0]
	require.Equal(t, resID.String(), r.Id)
	require.Equal(t, tok.String(), r.Token)
	require.Equal(t, "postgres", r.ResourceType)
	require.True(t, r.StorageExceeded)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestListResources_TeamMismatch(t *testing.T) {
	t.Parallel()
	db, _, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	teamJWT := uuid.New()
	otherTeam := uuid.New()
	srv := NewServer(db, newTestRedis(t), testCfg(), plans.Default(), nil, nil, nil, noop.NewStack())
	client, cleanup := dialDashboardGRPC(t, srv)
	defer cleanup()

	ctx := grpcAuthCtx(t, teamJWT, uuid.New())
	_, err = client.ListResources(ctx, &dashboardv1.ListResourcesRequest{TeamId: otherTeam.String()})
	require.Error(t, err)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestListResources_Unauthenticated(t *testing.T) {
	t.Parallel()
	db, _, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	srv := NewServer(db, newTestRedis(t), testCfg(), plans.Default(), nil, nil, nil, noop.NewStack())
	client, cleanup := dialDashboardGRPC(t, srv)
	defer cleanup()

	_, err = client.ListResources(context.Background(), &dashboardv1.ListResourcesRequest{TeamId: uuid.New().String()})
	require.Error(t, err)
	require.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestGetResource_Success_WithConnectionURL(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	teamID := uuid.New()
	resID := uuid.New()
	tok := uuid.New()
	created := time.Now().UTC().Truncate(time.Second)
	aesKey, err := crypto.ParseAESKey(testhelpers.TestAESKeyHex)
	require.NoError(t, err)
	enc, err := crypto.Encrypt(aesKey, "postgres://u:pw@localhost:5432/db")
	require.NoError(t, err)

	mock.ExpectQuery(`SELECT id, token, resource_type, tier, status, name, storage_bytes, cloud_vendor, country_code, expires_at, created_at, connection_url`).
		WithArgs(tok, teamID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "token", "resource_type", "tier", "status", "name", "storage_bytes",
			"cloud_vendor", "country_code", "expires_at", "created_at", "connection_url",
		}).AddRow(resID, tok, "postgres", "hobby", "active", "n1", int64(100), nil, nil, nil, created, enc))

	mock.ExpectQuery(`SELECT storage_bytes FROM resources WHERE id`).
		WithArgs(resID).
		WillReturnRows(sqlmock.NewRows([]string{"storage_bytes"}).AddRow(int64(100)))

	srv := NewServer(db, newTestRedis(t), testCfg(), plans.Default(), nil, nil, nil, noop.NewStack())
	client, cleanup := dialDashboardGRPC(t, srv)
	defer cleanup()

	ctx := grpcAuthCtx(t, teamID, uuid.New())
	out, err := client.GetResource(ctx, &dashboardv1.GetResourceRequest{Token: tok.String(), TeamId: teamID.String()})
	require.NoError(t, err)
	require.Contains(t, out.Resource.ConnectionUrl, "postgres://")
	require.Equal(t, tok.String(), out.Resource.Token)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestGetResource_NotFound_EmptyResult(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	teamID := uuid.New()
	tok := uuid.New()

	mock.ExpectQuery(`SELECT id, token, resource_type`).
		WithArgs(tok, teamID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "token", "resource_type", "tier", "status", "name", "storage_bytes",
			"cloud_vendor", "country_code", "expires_at", "created_at", "connection_url",
		}))

	srv := NewServer(db, newTestRedis(t), testCfg(), plans.Default(), nil, nil, nil, noop.NewStack())
	client, cleanup := dialDashboardGRPC(t, srv)
	defer cleanup()

	ctx := grpcAuthCtx(t, teamID, uuid.New())
	_, err = client.GetResource(ctx, &dashboardv1.GetResourceRequest{Token: tok.String(), TeamId: teamID.String()})
	require.Error(t, err)
	require.Equal(t, codes.NotFound, status.Code(err))
}

func TestDeleteResource_Success(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	teamID := uuid.New()
	resID := uuid.New()
	tok := uuid.New()
	created := time.Now()

	rows := resourceSelectColumns().AddRow(
		resID, teamID, tok, "webhook", nil, nil, nil, "hobby",
		nil, nil, nil, "active", nil,
		nil, int64(0), nil, nil, created,
	)
	mock.ExpectQuery(`FROM resources WHERE token`).
		WithArgs(tok).
		WillReturnRows(rows)

	mock.ExpectExec(`UPDATE resources SET status = 'deleted'`).
		WithArgs(resID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	srv := NewServer(db, newTestRedis(t), testCfg(), plans.Default(), nil, nil, nil, noop.NewStack())
	client, cleanup := dialDashboardGRPC(t, srv)
	defer cleanup()

	ctx := grpcAuthCtx(t, teamID, uuid.New())
	out, err := client.DeleteResource(ctx, &dashboardv1.DeleteResourceRequest{Token: tok.String(), TeamId: teamID.String()})
	require.NoError(t, err)
	require.True(t, out.Ok)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestDeleteResource_NotFound(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	teamID := uuid.New()
	tok := uuid.New()

	mock.ExpectQuery(`FROM resources WHERE token`).
		WithArgs(tok).
		WillReturnError(sql.ErrNoRows)

	srv := NewServer(db, newTestRedis(t), testCfg(), plans.Default(), nil, nil, nil, noop.NewStack())
	client, cleanup := dialDashboardGRPC(t, srv)
	defer cleanup()

	ctx := grpcAuthCtx(t, teamID, uuid.New())
	_, err = client.DeleteResource(ctx, &dashboardv1.DeleteResourceRequest{Token: tok.String(), TeamId: teamID.String()})
	require.Error(t, err)
	require.Equal(t, codes.NotFound, status.Code(err))
}

func TestRotateCredentials_Success(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	teamID := uuid.New()
	resID := uuid.New()
	tok := uuid.New()
	created := time.Now()
	aesKey, err := crypto.ParseAESKey(testhelpers.TestAESKeyHex)
	require.NoError(t, err)
	enc, err := crypto.Encrypt(aesKey, "nats://usr:oldsecret@127.0.0.1:4222")
	require.NoError(t, err)

	rows := resourceSelectColumns().AddRow(
		resID, teamID, tok, "queue", nil, enc, nil, "hobby",
		nil, nil, nil, "active", nil,
		nil, int64(0), nil, nil, created,
	)
	mock.ExpectQuery(`FROM resources WHERE token`).
		WithArgs(tok).
		WillReturnRows(rows)

	mock.ExpectExec(`UPDATE resources SET connection_url`).
		WithArgs(sqlmock.AnyArg(), resID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	mock.ExpectQuery(`SELECT storage_bytes FROM resources WHERE id`).
		WithArgs(resID).
		WillReturnRows(sqlmock.NewRows([]string{"storage_bytes"}).AddRow(int64(0)))

	srv := NewServer(db, newTestRedis(t), testCfg(), plans.Default(), nil, nil, nil, noop.NewStack())
	client, cleanup := dialDashboardGRPC(t, srv)
	defer cleanup()

	ctx := grpcAuthCtx(t, teamID, uuid.New())
	out, err := client.RotateCredentials(ctx, &dashboardv1.RotateCredentialsRequest{Token: tok.String(), TeamId: teamID.String()})
	require.NoError(t, err)
	require.NotEmpty(t, out.ConnectionUrl)
	require.Contains(t, out.ConnectionUrl, "nats://")
	require.NotEmpty(t, out.Resource)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRotateCredentials_NoConnectionURL(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	teamID := uuid.New()
	resID := uuid.New()
	tok := uuid.New()
	created := time.Now()

	rows := resourceSelectColumns().AddRow(
		resID, teamID, tok, "queue", nil, nil, nil, "hobby",
		nil, nil, nil, "active", nil,
		nil, int64(0), nil, nil, created,
	)
	mock.ExpectQuery(`FROM resources WHERE token`).
		WithArgs(tok).
		WillReturnRows(rows)

	srv := NewServer(db, newTestRedis(t), testCfg(), plans.Default(), nil, nil, nil, noop.NewStack())
	client, cleanup := dialDashboardGRPC(t, srv)
	defer cleanup()

	ctx := grpcAuthCtx(t, teamID, uuid.New())
	_, err = client.RotateCredentials(ctx, &dashboardv1.RotateCredentialsRequest{Token: tok.String(), TeamId: teamID.String()})
	require.Error(t, err)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestGetTeam_Success(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	teamID := uuid.New()
	owner := uuid.New()
	created := time.Now().UTC().Truncate(time.Second)

	mock.ExpectQuery(`FROM teams t`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "plan_tier", "created_at", "count", "owner"}).
			AddRow(teamID, "My Team", "pro", created, int64(3), owner.String()))

	srv := NewServer(db, newTestRedis(t), testCfg(), plans.Default(), nil, nil, nil, noop.NewStack())
	client, cleanup := dialDashboardGRPC(t, srv)
	defer cleanup()

	ctx := grpcAuthCtx(t, teamID, owner)
	out, err := client.GetTeam(ctx, &dashboardv1.GetTeamRequest{TeamId: teamID.String(), UserId: owner.String()})
	require.NoError(t, err)
	require.Equal(t, teamID.String(), out.Team.Id)
	require.Equal(t, "My Team", out.Team.Name)
	require.Equal(t, "my-team", out.Team.Slug)
	require.Equal(t, int32(3), out.Team.MemberCount)
	require.Equal(t, owner.String(), out.Team.OwnerId)
}

func TestGetTeam_UserMismatch(t *testing.T) {
	t.Parallel()
	db, _, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	teamID := uuid.New()
	jwtUser := uuid.New()
	otherUser := uuid.New()

	srv := NewServer(db, newTestRedis(t), testCfg(), plans.Default(), nil, nil, nil, noop.NewStack())
	client, cleanup := dialDashboardGRPC(t, srv)
	defer cleanup()

	ctx := grpcAuthCtx(t, teamID, jwtUser)
	_, err = client.GetTeam(ctx, &dashboardv1.GetTeamRequest{TeamId: teamID.String(), UserId: otherUser.String()})
	require.Error(t, err)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestUpdateTeam_Success(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	teamID := uuid.New()
	userID := uuid.New()
	created := time.Now().UTC().Truncate(time.Second)

	mock.ExpectExec(`UPDATE teams SET name`).
		WithArgs("New Name", teamID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	mock.ExpectQuery(`FROM teams t`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "plan_tier", "created_at", "count", "owner"}).
			AddRow(teamID, "New Name", "hobby", created, int64(1), userID.String()))

	srv := NewServer(db, newTestRedis(t), testCfg(), plans.Default(), nil, nil, nil, noop.NewStack())
	client, cleanup := dialDashboardGRPC(t, srv)
	defer cleanup()

	ctx := grpcAuthCtx(t, teamID, userID)
	out, err := client.UpdateTeam(ctx, &dashboardv1.UpdateTeamRequest{
		TeamId: teamID.String(), UserId: userID.String(), Name: "New Name",
	})
	require.NoError(t, err)
	require.Equal(t, "New Name", out.Team.Name)
	require.Equal(t, "new-name", out.Team.Slug)
}

func TestUpdateTeam_EmptyName(t *testing.T) {
	t.Parallel()
	db, _, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	teamID := uuid.New()
	userID := uuid.New()
	srv := NewServer(db, newTestRedis(t), testCfg(), plans.Default(), nil, nil, nil, noop.NewStack())
	client, cleanup := dialDashboardGRPC(t, srv)
	defer cleanup()

	ctx := grpcAuthCtx(t, teamID, userID)
	_, err = client.UpdateTeam(ctx, &dashboardv1.UpdateTeamRequest{
		TeamId: teamID.String(), UserId: userID.String(), Name: "   ",
	})
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestGetBilling(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	teamID := uuid.New()
	mock.ExpectQuery(`SELECT plan_tier, stripe_customer_id FROM teams`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{"plan_tier", "stripe_customer_id"}).AddRow("pro", "sub_123"))

	cfg := testCfg()
	cfg.RazorpayKeyID = "key"
	cfg.RazorpayKeySecret = "secret"
	srv := NewServer(db, newTestRedis(t), cfg, plans.Default(), nil, nil, nil, noop.NewStack())
	client, cleanup := dialDashboardGRPC(t, srv)
	defer cleanup()

	ctx := grpcAuthCtx(t, teamID, uuid.New())
	out, err := client.GetBilling(ctx, &dashboardv1.GetBillingRequest{TeamId: teamID.String()})
	require.NoError(t, err)
	require.Equal(t, "pro", out.Billing.Plan)
	require.Equal(t, "active", out.Billing.Status)
	require.True(t, out.Billing.RazorpayConfigured)
}

func TestCreateCheckout_NotConfigured(t *testing.T) {
	t.Parallel()
	db, _, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	teamID := uuid.New()
	srv := NewServer(db, newTestRedis(t), testCfg(), plans.Default(), nil, nil, nil, noop.NewStack())
	client, cleanup := dialDashboardGRPC(t, srv)
	defer cleanup()

	ctx := grpcAuthCtx(t, teamID, uuid.New())
	_, err = client.CreateCheckout(ctx, &dashboardv1.CreateCheckoutRequest{TeamId: teamID.String(), Plan: "pro"})
	require.Error(t, err)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Contains(t, err.Error(), "billing_not_configured")
}

func TestCreateCheckout_InvalidPlan(t *testing.T) {
	t.Parallel()
	db, _, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	teamID := uuid.New()
	cfg := testCfg()
	cfg.RazorpayKeyID = "k"
	cfg.RazorpayKeySecret = "s"
	srv := NewServer(db, newTestRedis(t), cfg, plans.Default(), nil, nil, nil, noop.NewStack())
	client, cleanup := dialDashboardGRPC(t, srv)
	defer cleanup()

	ctx := grpcAuthCtx(t, teamID, uuid.New())
	_, err = client.CreateCheckout(ctx, &dashboardv1.CreateCheckoutRequest{TeamId: teamID.String(), Plan: "enterprise"})
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestGetResource_InvalidToken(t *testing.T) {
	t.Parallel()
	db, _, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	teamID := uuid.New()
	srv := NewServer(db, newTestRedis(t), testCfg(), plans.Default(), nil, nil, nil, noop.NewStack())
	client, cleanup := dialDashboardGRPC(t, srv)
	defer cleanup()

	ctx := grpcAuthCtx(t, teamID, uuid.New())
	_, err = client.GetResource(ctx, &dashboardv1.GetResourceRequest{Token: "not-uuid", TeamId: teamID.String()})
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestListResources_ScopedQueryUsesTeamArg(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	teamID := uuid.New()
	rid := uuid.New()
	created := time.Now()

	mock.ExpectQuery(`FROM resources`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "token", "resource_type", "tier", "status", "name", "storage_bytes",
			"cloud_vendor", "country_code", "expires_at", "created_at",
		}).AddRow(rid, uuid.New(), "redis", "hobby", "active", "r1", int64(0), nil, nil, nil, created))

	mock.ExpectQuery(`SELECT storage_bytes FROM resources WHERE id`).
		WithArgs(rid).
		WillReturnRows(sqlmock.NewRows([]string{"storage_bytes"}).AddRow(int64(0)))

	srv := NewServer(db, newTestRedis(t), testCfg(), plans.Default(), nil, nil, nil, noop.NewStack())
	client, cleanup := dialDashboardGRPC(t, srv)
	defer cleanup()

	ctx := grpcAuthCtx(t, teamID, uuid.New())
	_, err = client.ListResources(ctx, &dashboardv1.ListResourcesRequest{TeamId: teamID.String()})
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestGetTeam_NotFound(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	teamID := uuid.New()
	userID := uuid.New()

	mock.ExpectQuery(`FROM teams t`).
		WithArgs(teamID).
		WillReturnError(sql.ErrNoRows)

	srv := NewServer(db, newTestRedis(t), testCfg(), plans.Default(), nil, nil, nil, noop.NewStack())
	client, cleanup := dialDashboardGRPC(t, srv)
	defer cleanup()

	ctx := grpcAuthCtx(t, teamID, userID)
	_, err = client.GetTeam(ctx, &dashboardv1.GetTeamRequest{TeamId: teamID.String(), UserId: userID.String()})
	require.Error(t, err)
	require.Equal(t, codes.NotFound, status.Code(err))
}

func TestGetBilling_TeamNotFound(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	teamID := uuid.New()
	mock.ExpectQuery(`SELECT plan_tier`).
		WithArgs(teamID).
		WillReturnError(sql.ErrNoRows)

	srv := NewServer(db, newTestRedis(t), testCfg(), plans.Default(), nil, nil, nil, noop.NewStack())
	client, cleanup := dialDashboardGRPC(t, srv)
	defer cleanup()

	ctx := grpcAuthCtx(t, teamID, uuid.New())
	_, err = client.GetBilling(ctx, &dashboardv1.GetBillingRequest{TeamId: teamID.String()})
	require.Error(t, err)
	require.Equal(t, codes.NotFound, status.Code(err))
}
