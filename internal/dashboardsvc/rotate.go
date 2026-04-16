package dashboardsvc

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	mongooptions "go.mongodb.org/mongo-driver/mongo/options"

	"instant.dev/internal/config"
	"instant.dev/internal/models"
	commonv1 "instant.dev/proto/common/v1"
)

// rotatePostgresPassword runs ALTER ROLE on postgres-customers (copied from handlers.ResourceHandler).
func rotatePostgresPassword(ctx context.Context, dsn, username, newPassword string) error {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("rotatePostgresPassword: open: %w", err)
	}
	defer db.Close()

	for _, ch := range username {
		if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-') {
			return fmt.Errorf("rotatePostgresPassword: unsafe username %q", username)
		}
	}

	_, err = db.ExecContext(ctx, fmt.Sprintf(`ALTER ROLE "%s" WITH PASSWORD '%s'`, username, newPassword))
	if err != nil {
		return fmt.Errorf("rotatePostgresPassword: ALTER ROLE: %w", err)
	}
	return nil
}

func rotateRedisPassword(ctx context.Context, originalURL, username, newPassword string) error {
	opts, err := redis.ParseURL(originalURL)
	if err != nil {
		return fmt.Errorf("rotateRedisPassword: parse url: %w", err)
	}
	client := redis.NewClient(opts)
	defer client.Close()

	if err := client.Do(ctx, "ACL", "SETUSER", username, "resetpass", ">"+newPassword).Err(); err != nil {
		return fmt.Errorf("rotateRedisPassword: ACL SETUSER: %w", err)
	}
	return nil
}

func rotateMongoPassword(ctx context.Context, adminURI, username, newPassword string) error {
	client, err := mongo.Connect(ctx, mongooptions.Client().ApplyURI(adminURI).
		SetServerSelectionTimeout(3*time.Second))
	if err != nil {
		return fmt.Errorf("rotateMongoPassword: connect: %w", err)
	}
	defer func() {
		if discErr := client.Disconnect(ctx); discErr != nil {
			slog.Warn("rotateMongoPassword: disconnect", "error", discErr)
		}
	}()

	result := client.Database("admin").RunCommand(ctx, bson.D{
		{Key: "updateUser", Value: username},
		{Key: "pwd", Value: newPassword},
	})
	if result.Err() != nil {
		return fmt.Errorf("rotateMongoPassword: updateUser: %w", result.Err())
	}
	return nil
}

func resourceTypeToProto(resourceType string) commonv1.ResourceType {
	switch resourceType {
	case "postgres":
		return commonv1.ResourceType_RESOURCE_TYPE_POSTGRES
	case "redis":
		return commonv1.ResourceType_RESOURCE_TYPE_REDIS
	case "mongodb":
		return commonv1.ResourceType_RESOURCE_TYPE_MONGODB
	default:
		return commonv1.ResourceType_RESOURCE_TYPE_UNSPECIFIED
	}
}

func applyRotatedPassword(ctx context.Context, cfg *config.Config, r *models.Resource, parsedUser, newPassword, plainURL string) {
	if r.ResourceType == "postgres" && cfg.CustomerDatabaseURL != "" {
		if rotErr := rotatePostgresPassword(ctx, cfg.CustomerDatabaseURL, parsedUser, newPassword); rotErr != nil {
			slog.Warn("dashboardsvc.rotate.postgres_alter_role_failed",
				"resource_id", r.ID, "error", rotErr)
		}
	}
	if r.ResourceType == "redis" {
		if rotErr := rotateRedisPassword(ctx, plainURL, parsedUser, newPassword); rotErr != nil {
			slog.Warn("dashboardsvc.rotate.redis_acl_setuser_failed",
				"resource_id", r.ID, "error", rotErr)
		}
	}
	if r.ResourceType == "mongodb" && cfg.MongoAdminURI != "" {
		if rotErr := rotateMongoPassword(ctx, cfg.MongoAdminURI, parsedUser, newPassword); rotErr != nil {
			slog.Warn("dashboardsvc.rotate.mongo_update_user_failed",
				"resource_id", r.ID, "error", rotErr)
		}
	}
}
