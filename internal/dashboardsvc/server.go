package dashboardsvc

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	razorpay "github.com/razorpay/razorpay-go"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"instant.dev/internal/config"
	"instant.dev/internal/crypto"
	"instant.dev/internal/email"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	compute "instant.dev/internal/providers/compute"
	storageprovider "instant.dev/internal/providers/storage"
	"instant.dev/internal/provisioner"
	"instant.dev/internal/quota"
	"instant.dev/internal/razorpaybilling"
	commonv1 "instant.dev/proto/common/v1"
	dashboardv1 "instant.dev/proto/dashboard/v1"
)

// Server implements dashboardv1.DashboardServiceServer for dashboard-api.
type Server struct {
	dashboardv1.UnimplementedDashboardServiceServer
	db              *sql.DB
	rdb             *redis.Client
	cfg             *config.Config
	plans           *plans.Registry
	provisioner     *provisioner.Client
	storageProvider *storageprovider.Provider
	mail            *email.Client
	stackProv       compute.StackProvider
}

// NewServer constructs a Dashboard gRPC service implementation.
func NewServer(db *sql.DB, rdb *redis.Client, cfg *config.Config, reg *plans.Registry, prov *provisioner.Client, storageProv *storageprovider.Provider, mail *email.Client, stackProv compute.StackProvider) *Server {
	return &Server{
		db:              db,
		rdb:             rdb,
		cfg:             cfg,
		plans:           reg,
		provisioner:     prov,
		storageProvider: storageProv,
		mail:            mail,
		stackProv:       stackProv,
	}
}

func (s *Server) requireMatchingTeam(ctx context.Context, requestedTeam string) (uuid.UUID, error) {
	authTeam, err := authTeamID(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	if strings.TrimSpace(requestedTeam) == "" {
		return uuid.Nil, status.Error(codes.InvalidArgument, "team_id required")
	}
	reqTeam, err := uuid.Parse(requestedTeam)
	if err != nil {
		return uuid.Nil, status.Error(codes.InvalidArgument, "invalid team_id")
	}
	if authTeam != reqTeam {
		return uuid.Nil, status.Error(codes.PermissionDenied, "team_id does not match authenticated session")
	}
	return authTeam, nil
}

func (s *Server) requireMatchingUser(ctx context.Context, requestedUser string) error {
	if strings.TrimSpace(requestedUser) == "" {
		return nil
	}
	authUser, err := authUserID(ctx)
	if err != nil {
		return err
	}
	reqUser, err := uuid.Parse(requestedUser)
	if err != nil {
		return status.Error(codes.InvalidArgument, "invalid user_id")
	}
	if authUser != reqUser {
		return status.Error(codes.PermissionDenied, "user_id does not match authenticated session")
	}
	return nil
}

func slugify(name, teamID string) string {
	if name == "" {
		if len(teamID) >= 8 {
			return teamID[:8]
		}
		return teamID
	}
	slug := strings.ToLower(name)
	slug = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, slug)
	for strings.Contains(slug, "--") {
		slug = strings.ReplaceAll(slug, "--", "-")
	}
	slug = strings.Trim(slug, "-")
	if slug == "" {
		if len(teamID) >= 8 {
			return teamID[:8]
		}
		return teamID
	}
	return slug
}

// ListResources implements dashboard.v1.DashboardService/ListResources.
func (s *Server) ListResources(ctx context.Context, req *dashboardv1.ListResourcesRequest) (*dashboardv1.ListResourcesResponse, error) {
	if _, err := s.requireMatchingTeam(ctx, req.GetTeamId()); err != nil {
		return nil, err
	}
	teamID, _ := uuid.Parse(req.GetTeamId())

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, token, resource_type, tier, status, name, storage_bytes, cloud_vendor, country_code, expires_at, created_at
		FROM resources
		WHERE team_id = $1 AND status != 'deleted'
		ORDER BY created_at DESC
	`, teamID)
	if err != nil {
		slog.Error("dashboardsvc.ListResources.query_failed", "error", err, "team_id", teamID)
		return nil, status.Error(codes.Internal, "list resources failed")
	}
	defer rows.Close()

	var out []*dashboardv1.DashboardResource
	for rows.Next() {
		var (
			id            uuid.UUID
			token         uuid.UUID
			resType, tier string
			resStatus     string
			name          sql.NullString
			storageBytes  int64
			cloudVendor   sql.NullString
			countryCode   sql.NullString
			expiresAt     sql.NullTime
			createdAt     time.Time
		)
		if err := rows.Scan(&id, &token, &resType, &tier, &resStatus, &name, &storageBytes, &cloudVendor, &countryCode, &expiresAt, &createdAt); err != nil {
			slog.Error("dashboardsvc.ListResources.scan_failed", "error", err)
			return nil, status.Error(codes.Internal, "list resources failed")
		}

		limitMB := s.plans.StorageLimitMB(tier, resType)
		_, storageExceeded, _ := quota.CheckStorageQuota(ctx, s.db, id, limitMB)

		dr := &dashboardv1.DashboardResource{
			Id:              id.String(),
			Token:           token.String(),
			ResourceType:    resType,
			Tier:            tier,
			Status:          resStatus,
			StorageBytes:    storageBytes,
			StorageExceeded: storageExceeded,
			CreatedAt:       createdAt.UTC().Format(time.RFC3339Nano),
		}
		if name.Valid {
			dr.Name = name.String
		}
		if cloudVendor.Valid {
			dr.CloudVendor = cloudVendor.String
		}
		if countryCode.Valid {
			dr.CountryCode = countryCode.String
		}
		if expiresAt.Valid {
			s := expiresAt.Time.UTC().Format(time.RFC3339Nano)
			dr.ExpiresAt = &s
		}
		out = append(out, dr)
	}
	if err := rows.Err(); err != nil {
		slog.Error("dashboardsvc.ListResources.rows_failed", "error", err)
		return nil, status.Error(codes.Internal, "list resources failed")
	}

	return &dashboardv1.ListResourcesResponse{
		Resources:  out,
		TotalCount: int64(len(out)),
	}, nil
}

// GetResource implements dashboard.v1.DashboardService/GetResource.
func (s *Server) GetResource(ctx context.Context, req *dashboardv1.GetResourceRequest) (*dashboardv1.GetResourceResponse, error) {
	if _, err := s.requireMatchingTeam(ctx, req.GetTeamId()); err != nil {
		return nil, err
	}
	teamID, _ := uuid.Parse(req.GetTeamId())
	token, err := uuid.Parse(req.GetToken())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid token")
	}

	var (
		id            uuid.UUID
		tokenDB       uuid.UUID
		resType, tier string
		resStatus     string
		name          sql.NullString
		storageBytes  int64
		cloudVendor   sql.NullString
		countryCode   sql.NullString
		expiresAt     sql.NullTime
		createdAt     time.Time
		connEnc       sql.NullString
	)

	err = s.db.QueryRowContext(ctx, `
		SELECT id, token, resource_type, tier, status, name, storage_bytes, cloud_vendor, country_code, expires_at, created_at, connection_url
		FROM resources
		WHERE token = $1 AND team_id = $2
	`, token, teamID).Scan(
		&id, &tokenDB, &resType, &tier, &resStatus, &name, &storageBytes, &cloudVendor, &countryCode, &expiresAt, &createdAt, &connEnc,
	)
	if err == sql.ErrNoRows {
		return nil, status.Error(codes.NotFound, "resource not found")
	}
	if err != nil {
		slog.Error("dashboardsvc.GetResource.query_failed", "error", err)
		return nil, status.Error(codes.Internal, "get resource failed")
	}

	limitMB := s.plans.StorageLimitMB(tier, resType)
	_, storageExceeded, _ := quota.CheckStorageQuota(ctx, s.db, id, limitMB)

	dr := &dashboardv1.DashboardResource{
		Id:              id.String(),
		Token:           tokenDB.String(),
		ResourceType:    resType,
		Tier:            tier,
		Status:          resStatus,
		StorageBytes:    storageBytes,
		StorageExceeded: storageExceeded,
		CreatedAt:       createdAt.UTC().Format(time.RFC3339Nano),
	}
	if name.Valid {
		dr.Name = name.String
	}
	if cloudVendor.Valid {
		dr.CloudVendor = cloudVendor.String
	}
	if countryCode.Valid {
		dr.CountryCode = countryCode.String
	}
	if expiresAt.Valid {
		s := expiresAt.Time.UTC().Format(time.RFC3339Nano)
		dr.ExpiresAt = &s
	}

	if connEnc.Valid && connEnc.String != "" {
		aesKey, kerr := crypto.ParseAESKey(s.cfg.AESKey)
		if kerr != nil {
			slog.Error("dashboardsvc.GetResource.aes_key_invalid", "error", kerr)
			return nil, status.Error(codes.Internal, "encryption configuration error")
		}
		plain, derr := crypto.Decrypt(aesKey, connEnc.String)
		if derr != nil {
			slog.Error("dashboardsvc.GetResource.decrypt_failed", "error", derr)
			return nil, status.Error(codes.Internal, "decrypt connection_url failed")
		}
		dr.ConnectionUrl = plain
	}

	return &dashboardv1.GetResourceResponse{Resource: dr}, nil
}

// DeleteResource implements dashboard.v1.DashboardService/DeleteResource.
func (s *Server) DeleteResource(ctx context.Context, req *dashboardv1.DeleteResourceRequest) (*dashboardv1.DeleteResourceResponse, error) {
	if _, err := s.requireMatchingTeam(ctx, req.GetTeamId()); err != nil {
		return nil, err
	}
	teamID, _ := uuid.Parse(req.GetTeamId())
	token, err := uuid.Parse(req.GetToken())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid token")
	}

	resource, err := models.GetResourceByToken(ctx, s.db, token)
	if err != nil {
		var notFound *models.ErrResourceNotFound
		if errors.As(err, &notFound) {
			return nil, status.Error(codes.NotFound, "resource not found")
		}
		slog.Error("dashboardsvc.DeleteResource.lookup_failed", "error", err)
		return nil, status.Error(codes.Internal, "get resource failed")
	}
	if !resource.TeamID.Valid || resource.TeamID.UUID != teamID {
		return nil, status.Error(codes.NotFound, "resource not found")
	}

	if err := models.SoftDeleteResource(ctx, s.db, resource.ID); err != nil {
		slog.Error("dashboardsvc.DeleteResource.soft_delete_failed", "error", err, "resource_id", resource.ID)
		return nil, status.Error(codes.Internal, "delete resource failed")
	}

	switch resource.ResourceType {
	case "storage":
		if s.storageProvider != nil {
			if deprovErr := s.storageProvider.Deprovision(ctx, token.String()); deprovErr != nil {
				slog.Warn("dashboardsvc.DeleteResource.storage_deprovision_failed",
					"error", deprovErr, "resource_id", resource.ID, "token", token.String())
			}
		}
	default:
		if s.provisioner != nil {
			resType := resourceTypeToProto(resource.ResourceType)
			if resType != commonv1.ResourceType_RESOURCE_TYPE_UNSPECIFIED {
				providerID := resource.ProviderResourceID.String
				if deprovErr := s.provisioner.DeprovisionResource(ctx, token.String(), providerID, resType); deprovErr != nil {
					slog.Warn("dashboardsvc.DeleteResource.deprovision_failed",
						"error", deprovErr, "resource_id", resource.ID, "resource_type", resource.ResourceType)
				}
			}
		}
	}

	_ = s.rdb.Del(ctx, fmt.Sprintf("res:%s", token.String()))

	return &dashboardv1.DeleteResourceResponse{Ok: true}, nil
}

// RotateCredentials implements dashboard.v1.DashboardService/RotateCredentials.
func (s *Server) RotateCredentials(ctx context.Context, req *dashboardv1.RotateCredentialsRequest) (*dashboardv1.RotateCredentialsResponse, error) {
	if _, err := s.requireMatchingTeam(ctx, req.GetTeamId()); err != nil {
		return nil, err
	}
	teamID, _ := uuid.Parse(req.GetTeamId())
	token, err := uuid.Parse(req.GetToken())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid token")
	}

	resource, err := models.GetResourceByToken(ctx, s.db, token)
	if err != nil {
		var notFound *models.ErrResourceNotFound
		if errors.As(err, &notFound) {
			return nil, status.Error(codes.NotFound, "resource not found")
		}
		slog.Error("dashboardsvc.RotateCredentials.lookup_failed", "error", err)
		return nil, status.Error(codes.Internal, "get resource failed")
	}
	if !resource.TeamID.Valid || resource.TeamID.UUID != teamID {
		return nil, status.Error(codes.NotFound, "resource not found")
	}

	if !resource.ConnectionURL.Valid || resource.ConnectionURL.String == "" {
		return nil, status.Error(codes.FailedPrecondition, "resource has no connection_url")
	}

	aesKey, err := crypto.ParseAESKey(s.cfg.AESKey)
	if err != nil {
		slog.Error("dashboardsvc.RotateCredentials.aes_key_invalid", "error", err)
		return nil, status.Error(codes.Internal, "encryption configuration error")
	}

	plainURL, err := crypto.Decrypt(aesKey, resource.ConnectionURL.String)
	if err != nil {
		slog.Error("dashboardsvc.RotateCredentials.decrypt_failed", "error", err)
		return nil, status.Error(codes.Internal, "decrypt connection_url failed")
	}

	pwBytes := make([]byte, 16)
	if _, err := rand.Read(pwBytes); err != nil {
		return nil, status.Error(codes.Internal, "generate password failed")
	}
	newPassword := hex.EncodeToString(pwBytes)

	parsed, err := url.Parse(plainURL)
	if err != nil {
		slog.Error("dashboardsvc.RotateCredentials.url_parse_failed", "error", err)
		return nil, status.Error(codes.Internal, "parse connection_url failed")
	}
	username := parsed.User.Username()
	parsed.User = url.UserPassword(username, newPassword)
	newPlainURL := parsed.String()

	applyRotatedPassword(ctx, s.cfg, resource, username, newPassword, plainURL)

	newEncryptedURL, err := crypto.Encrypt(aesKey, newPlainURL)
	if err != nil {
		slog.Error("dashboardsvc.RotateCredentials.encrypt_failed", "error", err)
		return nil, status.Error(codes.Internal, "encrypt connection_url failed")
	}

	if err := models.UpdateConnectionURL(ctx, s.db, resource.ID, newEncryptedURL); err != nil {
		slog.Error("dashboardsvc.RotateCredentials.update_failed", "error", err)
		return nil, status.Error(codes.Internal, "persist rotated credentials failed")
	}

	limitMB := s.plans.StorageLimitMB(resource.Tier, resource.ResourceType)
	_, storageExceeded, _ := quota.CheckStorageQuota(ctx, s.db, resource.ID, limitMB)

	resProto := &dashboardv1.DashboardResource{
		Id:              resource.ID.String(),
		Token:           resource.Token.String(),
		ResourceType:    resource.ResourceType,
		Tier:            resource.Tier,
		Status:          resource.Status,
		StorageBytes:    resource.StorageBytes,
		StorageExceeded: storageExceeded,
		CreatedAt:       resource.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	if resource.Name.Valid {
		resProto.Name = resource.Name.String
	}
	if resource.CloudVendor.Valid {
		resProto.CloudVendor = resource.CloudVendor.String
	}
	if resource.CountryCode.Valid {
		resProto.CountryCode = resource.CountryCode.String
	}
	if resource.ExpiresAt.Valid {
		s := resource.ExpiresAt.Time.UTC().Format(time.RFC3339Nano)
		resProto.ExpiresAt = &s
	}

	return &dashboardv1.RotateCredentialsResponse{
		ConnectionUrl: newPlainURL,
		Resource:      resProto,
	}, nil
}

// GetTeam implements dashboard.v1.DashboardService/GetTeam.
func (s *Server) GetTeam(ctx context.Context, req *dashboardv1.GetTeamRequest) (*dashboardv1.GetTeamResponse, error) {
	if _, err := s.requireMatchingTeam(ctx, req.GetTeamId()); err != nil {
		return nil, err
	}
	if err := s.requireMatchingUser(ctx, req.GetUserId()); err != nil {
		return nil, err
	}
	teamID, _ := uuid.Parse(req.GetTeamId())

	team, err := s.loadDashboardTeam(ctx, teamID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "team not found")
		}
		slog.Error("dashboardsvc.GetTeam.query_failed", "error", err)
		return nil, status.Error(codes.Internal, "get team failed")
	}
	return &dashboardv1.GetTeamResponse{Team: team}, nil
}

func (s *Server) loadDashboardTeam(ctx context.Context, teamID uuid.UUID) (*dashboardv1.DashboardTeam, error) {
	var (
		id        uuid.UUID
		name      sql.NullString
		planTier  string
		createdAt time.Time
		memberCnt int64
		ownerID   sql.NullString
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT t.id, t.name, t.plan_tier, t.created_at,
		       (SELECT COUNT(*) FROM users WHERE team_id = t.id),
		       COALESCE(
		         (SELECT id::text FROM users WHERE team_id = t.id AND role = 'owner' ORDER BY created_at ASC LIMIT 1),
		         (SELECT id::text FROM users WHERE team_id = t.id ORDER BY created_at ASC LIMIT 1)
		       )
		FROM teams t
		WHERE t.id = $1
	`, teamID).Scan(&id, &name, &planTier, &createdAt, &memberCnt, &ownerID)
	if err != nil {
		return nil, err
	}
	nameStr := ""
	if name.Valid {
		nameStr = name.String
	}
	tidStr := id.String()
	ownerStr := ""
	if ownerID.Valid {
		ownerStr = ownerID.String
	}
	return &dashboardv1.DashboardTeam{
		Id:          tidStr,
		Name:        nameStr,
		Slug:        slugify(nameStr, tidStr),
		OwnerId:     ownerStr,
		MemberCount: int32(memberCnt),
		Tier:        planTier,
		CreatedAt:   createdAt.UTC().Format(time.RFC3339Nano),
	}, nil
}

// UpdateTeam implements dashboard.v1.DashboardService/UpdateTeam.
func (s *Server) UpdateTeam(ctx context.Context, req *dashboardv1.UpdateTeamRequest) (*dashboardv1.UpdateTeamResponse, error) {
	if _, err := s.requireMatchingTeam(ctx, req.GetTeamId()); err != nil {
		return nil, err
	}
	if err := s.requireMatchingUser(ctx, req.GetUserId()); err != nil {
		return nil, err
	}
	teamID, _ := uuid.Parse(req.GetTeamId())
	name := strings.TrimSpace(req.GetName())
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}

	_, err := s.db.ExecContext(ctx, `UPDATE teams SET name = $1 WHERE id = $2`, name, teamID)
	if err != nil {
		slog.Error("dashboardsvc.UpdateTeam.exec_failed", "error", err)
		return nil, status.Error(codes.Internal, "update team failed")
	}

	team, err := s.loadDashboardTeam(ctx, teamID)
	if err != nil {
		slog.Error("dashboardsvc.UpdateTeam.reload_failed", "error", err)
		return nil, status.Error(codes.Internal, "load team failed")
	}
	return &dashboardv1.UpdateTeamResponse{Team: team}, nil
}

// GetBilling implements dashboard.v1.DashboardService/GetBilling.
func (s *Server) GetBilling(ctx context.Context, req *dashboardv1.GetBillingRequest) (*dashboardv1.GetBillingResponse, error) {
	if _, err := s.requireMatchingTeam(ctx, req.GetTeamId()); err != nil {
		return nil, err
	}
	teamID, _ := uuid.Parse(req.GetTeamId())

	var planTier string
	var subID sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT plan_tier, stripe_customer_id FROM teams WHERE id = $1
	`, teamID).Scan(&planTier, &subID)
	if err == sql.ErrNoRows {
		return nil, status.Error(codes.NotFound, "team not found")
	}
	if err != nil {
		slog.Error("dashboardsvc.GetBilling.query_failed", "error", err)
		return nil, status.Error(codes.Internal, "get billing failed")
	}

	rzpOK := s.cfg.RazorpayKeyID != "" && s.cfg.RazorpayKeySecret != ""

	billingStatus := "none"
	sid := ""
	if subID.Valid {
		sid = strings.TrimSpace(subID.String)
	}
	if sid != "" {
		billingStatus = "active"
	}

	info := &dashboardv1.BillingInfo{
		Plan:               planTier,
		Status:             billingStatus,
		RazorpayConfigured: rzpOK,
	}

	if sid != "" && rzpOK {
		portal := &razorpaybilling.Portal{DB: s.db, Cfg: s.cfg}
		details, derr := portal.FetchSubscriptionDetails(sid)
		if derr != nil {
			slog.Warn("dashboardsvc.GetBilling.rzp_fetch_failed", "error", derr, "team_id", teamID)
		} else if details != nil {
			ss := details.Status
			info.SubscriptionStatus = &ss
			if !details.CurrentPeriodEnd.IsZero() {
				pe := details.CurrentPeriodEnd.UTC().Format(time.RFC3339Nano)
				info.CurrentPeriodEnd = &pe
			}
			if details.PaymentLast4 != "" {
				l4 := details.PaymentLast4
				info.PaymentLast4 = &l4
			}
			if details.PaymentNetwork != "" {
				net := details.PaymentNetwork
				info.PaymentNetwork = &net
			}
			if details.PaymentExpMonth > 0 {
				m := details.PaymentExpMonth
				info.PaymentExpMonth = &m
			}
			if details.PaymentExpYear > 0 {
				y := details.PaymentExpYear
				info.PaymentExpYear = &y
			}
			if details.CancelAtPeriodEnd {
				ce := true
				info.CancelAtPeriodEnd = &ce
			}
			switch strings.ToLower(details.Status) {
			case "cancelled", "completed", "expired":
				info.Status = details.Status
			case "halted":
				info.Status = "halted"
			case "pending", "authenticated":
				info.Status = "pending_payment"
			default:
				info.Status = "active"
			}
		}
	}

	return &dashboardv1.GetBillingResponse{Billing: info}, nil
}

func (s *Server) razorpayPlanIDs() map[string]string {
	m := make(map[string]string)
	if s.cfg.RazorpayPlanIDHobby != "" {
		m["hobby"] = s.cfg.RazorpayPlanIDHobby
	}
	if s.cfg.RazorpayPlanIDPro != "" {
		m["pro"] = s.cfg.RazorpayPlanIDPro
	}
	if s.cfg.RazorpayPlanIDTeam != "" {
		m["team"] = s.cfg.RazorpayPlanIDTeam
	}
	return m
}

// CreateCheckout implements dashboard.v1.DashboardService/CreateCheckout.
func (s *Server) CreateCheckout(ctx context.Context, req *dashboardv1.CreateCheckoutRequest) (*dashboardv1.CreateCheckoutResponse, error) {
	if _, err := s.requireMatchingTeam(ctx, req.GetTeamId()); err != nil {
		return nil, err
	}
	teamID, _ := uuid.Parse(req.GetTeamId())

	planKey := strings.ToLower(strings.TrimSpace(req.GetPlan()))
	planIDs := s.razorpayPlanIDs()
	planID, ok := planIDs[planKey]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "plan must be hobby, pro, or team")
	}

	if s.cfg.RazorpayKeyID == "" || s.cfg.RazorpayKeySecret == "" {
		return nil, status.Error(codes.FailedPrecondition, "billing_not_configured")
	}

	client := razorpay.NewClient(s.cfg.RazorpayKeyID, s.cfg.RazorpayKeySecret)
	subBody := map[string]interface{}{
		"plan_id":         planID,
		"total_count":     120,
		"quantity":        1,
		"customer_notify": 1,
		"notes": map[string]interface{}{
			"team_id": teamID.String(),
			"plan":    planKey,
		},
	}

	sub, err := client.Subscription.Create(subBody, nil)
	if err != nil {
		slog.Error("dashboardsvc.CreateCheckout.subscription_failed", "error", err, "team_id", teamID)
		return nil, status.Error(codes.Unavailable, "razorpay subscription create failed")
	}

	if subID, ok := sub["id"].(string); ok && subID != "" {
		if updateErr := models.UpdateRazorpaySubscriptionID(ctx, s.db, teamID, subID); updateErr != nil {
			slog.Error("dashboardsvc.CreateCheckout.persist_sub_id_failed", "error", updateErr, "team_id", teamID)
		}
	}

	shortURL, _ := sub["short_url"].(string)
	subscriptionID, _ := sub["id"].(string)

	return &dashboardv1.CreateCheckoutResponse{
		ShortUrl:       shortURL,
		SubscriptionId: subscriptionID,
	}, nil
}

// CancelSubscription implements dashboard.v1.DashboardService/CancelSubscription.
func (s *Server) CancelSubscription(ctx context.Context, req *dashboardv1.CancelSubscriptionRequest) (*dashboardv1.CancelSubscriptionResponse, error) {
	if _, err := s.requireMatchingTeam(ctx, req.GetTeamId()); err != nil {
		return nil, err
	}
	teamID, _ := uuid.Parse(req.GetTeamId())
	if s.cfg.RazorpayKeyID == "" || s.cfg.RazorpayKeySecret == "" {
		return nil, status.Error(codes.FailedPrecondition, "billing_not_configured")
	}
	portal := &razorpaybilling.Portal{DB: s.db, Cfg: s.cfg}
	subID, err := portal.SubscriptionID(ctx, teamID)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := portal.CancelAtCycleEnd(subID); err != nil {
		slog.Error("dashboardsvc.CancelSubscription.rzp_failed", "error", err, "team_id", teamID)
		return nil, status.Error(codes.Unavailable, "razorpay cancel failed")
	}
	return &dashboardv1.CancelSubscriptionResponse{Ok: true, CancelledAtCycleEnd: true}, nil
}

// ListInvoices implements dashboard.v1.DashboardService/ListInvoices.
func (s *Server) ListInvoices(ctx context.Context, req *dashboardv1.ListInvoicesRequest) (*dashboardv1.ListInvoicesResponse, error) {
	if _, err := s.requireMatchingTeam(ctx, req.GetTeamId()); err != nil {
		return nil, err
	}
	teamID, _ := uuid.Parse(req.GetTeamId())
	if s.cfg.RazorpayKeyID == "" || s.cfg.RazorpayKeySecret == "" {
		return nil, status.Error(codes.FailedPrecondition, "billing_not_configured")
	}
	portal := &razorpaybilling.Portal{DB: s.db, Cfg: s.cfg}
	subID, err := portal.SubscriptionID(ctx, teamID)
	if err != nil {
		return &dashboardv1.ListInvoicesResponse{}, nil
	}
	rows, err := portal.ListSubscriptionInvoices(subID)
	if err != nil {
		slog.Error("dashboardsvc.ListInvoices.rzp_failed", "error", err, "team_id", teamID)
		return nil, status.Error(codes.Unavailable, "razorpay invoice list failed")
	}
	out := make([]*dashboardv1.InvoiceRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, &dashboardv1.InvoiceRow{
			Id:       r.ID,
			Amount:   r.Amount,
			Currency: r.Currency,
			Status:   r.Status,
			Date:     r.Date.UTC().Format(time.RFC3339Nano),
			PdfUrl:   r.PDFURL,
		})
	}
	return &dashboardv1.ListInvoicesResponse{Invoices: out}, nil
}

// UpdatePaymentMethod implements dashboard.v1.DashboardService/UpdatePaymentMethod.
func (s *Server) UpdatePaymentMethod(ctx context.Context, req *dashboardv1.UpdatePaymentMethodRequest) (*dashboardv1.UpdatePaymentMethodResponse, error) {
	if _, err := s.requireMatchingTeam(ctx, req.GetTeamId()); err != nil {
		return nil, err
	}
	teamID, _ := uuid.Parse(req.GetTeamId())
	if s.cfg.RazorpayKeyID == "" || s.cfg.RazorpayKeySecret == "" {
		return nil, status.Error(codes.FailedPrecondition, "billing_not_configured")
	}
	portal := &razorpaybilling.Portal{DB: s.db, Cfg: s.cfg}
	subID, err := portal.SubscriptionID(ctx, teamID)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	shortURL, err := portal.PaymentUpdateURL(subID)
	if err != nil {
		slog.Warn("dashboardsvc.UpdatePaymentMethod.failed", "error", err, "team_id", teamID)
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &dashboardv1.UpdatePaymentMethodResponse{ShortUrl: shortURL}, nil
}

// ChangePlan implements dashboard.v1.DashboardService/ChangePlan.
func (s *Server) ChangePlan(ctx context.Context, req *dashboardv1.ChangePlanRequest) (*dashboardv1.ChangePlanResponse, error) {
	if _, err := s.requireMatchingTeam(ctx, req.GetTeamId()); err != nil {
		return nil, err
	}
	teamID, _ := uuid.Parse(req.GetTeamId())
	if s.cfg.RazorpayKeyID == "" || s.cfg.RazorpayKeySecret == "" {
		return nil, status.Error(codes.FailedPrecondition, "billing_not_configured")
	}
	target := strings.ToLower(strings.TrimSpace(req.GetTargetPlan()))
	var planTier string
	err := s.db.QueryRowContext(ctx, `SELECT plan_tier FROM teams WHERE id = $1`, teamID).Scan(&planTier)
	if err == sql.ErrNoRows {
		return nil, status.Error(codes.NotFound, "team not found")
	}
	if err != nil {
		return nil, status.Error(codes.Internal, "load team failed")
	}
	if strings.EqualFold(strings.TrimSpace(planTier), target) {
		return nil, status.Error(codes.InvalidArgument, "already on requested plan")
	}
	planIDs := s.razorpayPlanIDs()
	if _, ok := planIDs[target]; !ok {
		return nil, status.Error(codes.InvalidArgument, "plan must be hobby, pro, or team")
	}
	portal := &razorpaybilling.Portal{DB: s.db, Cfg: s.cfg}
	if _, err := portal.SubscriptionID(ctx, teamID); err != nil {
		return nil, status.Error(codes.InvalidArgument, "no active subscription to change")
	}
	res, err := portal.ChangePlan(ctx, teamID, target, planIDs)
	if err != nil {
		slog.Error("dashboardsvc.ChangePlan.failed", "error", err, "team_id", teamID)
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	return &dashboardv1.ChangePlanResponse{
		Ok:               true,
		NewPlan:          res.NewPlan,
		EffectiveDate:    res.EffectiveDate.UTC().Format(time.RFC3339Nano),
		CheckoutShortUrl: res.CheckoutShort,
	}, nil
}
