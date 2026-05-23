package nosql

// Package nosql handles MongoDB database provisioning.
// Supports local MongoDB instances running in the k8s cluster.
// Each provisioned token gets its own database (db_{token}) and
// a dedicated user (usr_{token}) with readWrite access scoped to that DB only.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// connectTimeout is the maximum time to wait for a MongoDB server to be found.
// Short to fail-fast in tests and when MongoDB is not reachable.
const connectTimeout = 3 * time.Second

// randRead is the entropy source for the user password. It defaults to
// crypto/rand.Read and is a package var only so a test can substitute a
// fault-injecting reader to exercise the (otherwise unreachable) RNG-failure
// branch in Provision. Production behaviour is identical to crypto/rand.Read.
var randRead = rand.Read

// mongoDisconnect is the seam through which every Provider method closes its
// client. It defaults to (*mongo.Client).Disconnect and is a package var only
// so a test can force it to error and exercise the disconnect defer-error log
// branches. Production behaviour is identical to calling client.Disconnect.
var mongoDisconnect = func(client *mongo.Client, ctx context.Context) error {
	return client.Disconnect(ctx)
}

// Credentials holds the MongoDB connection details returned after provisioning.
type Credentials struct {
	// URL is the mongodb:// connection string the caller can use immediately.
	// Format: mongodb://usr_{token}:{password}@{host}/db_{token}
	URL string

	// DatabaseName is the name of the provisioned database.
	DatabaseName string

	// ProviderResourceID is the backend-specific resource identifier.
	// For k8s-dedicated backend: the namespace name "instant-customer-<token>".
	// Empty for the shared local backend.
	ProviderResourceID string
}

// Provider manages MongoDB provisioning.
type Provider struct {
	adminURI  string // admin connection URI, e.g. mongodb://root:root@localhost:27017
	mongoHost string // host for building connection strings, e.g. localhost:27017
}

// New creates a Provider.
func New(adminURI, mongoHost string) *Provider {
	if adminURI == "" {
		adminURI = "mongodb://root:root@localhost:27017"
	}
	if mongoHost == "" {
		mongoHost = "localhost:27017"
	}
	return &Provider{adminURI: adminURI, mongoHost: mongoHost}
}

// Provision creates a MongoDB database and user for the given token.
// Database: db_{token}
// User: usr_{token} with readWrite role scoped to db_{token}
// Returns credentials the caller can use immediately.
func (p *Provider) Provision(ctx context.Context, token, tier string) (*Credentials, error) {
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(p.adminURI).
		SetServerSelectionTimeout(connectTimeout))
	if err != nil {
		return nil, fmt.Errorf("nosql.Provision: connect: %w", err)
	}
	defer func() {
		if discErr := mongoDisconnect(client, ctx); discErr != nil {
			slog.Error("nosql.Provision: disconnect", "error", discErr)
		}
	}()

	// Generate random 16-byte password.
	pwBytes := make([]byte, 16)
	if _, err := randRead(pwBytes); err != nil {
		return nil, fmt.Errorf("nosql.Provision: generate password: %w", err)
	}
	password := hex.EncodeToString(pwBytes)

	dbName := "db_" + token
	username := "usr_" + token

	// Create the user in the admin database with readWrite role scoped to the token DB.
	adminDB := client.Database("admin")
	result := adminDB.RunCommand(ctx, bson.D{
		{Key: "createUser", Value: username},
		{Key: "pwd", Value: password},
		{Key: "roles", Value: bson.A{
			bson.D{
				{Key: "role", Value: "readWrite"},
				{Key: "db", Value: dbName},
			},
		}},
	})
	if result.Err() != nil {
		return nil, fmt.Errorf("nosql.Provision: createUser: %w", result.Err())
	}

	// MongoDB creates the database implicitly on first insert. We insert and delete
	// a sentinel document to ensure the database exists and the user has access.
	tokenDB := client.Database(dbName)
	coll := tokenDB.Collection("_init")
	_, insertErr := coll.InsertOne(ctx, bson.D{{Key: "init", Value: true}})
	if insertErr != nil {
		slog.Error("nosql.Provision: init insert failed (non-fatal)", "token", token, "error", insertErr)
	} else {
		// Clean up the sentinel document — the DB will persist even when empty.
		_ = coll.Drop(ctx)
	}

	// User is created in the admin database; include authSource so clients authenticate correctly.
	url := fmt.Sprintf("mongodb://%s:%s@%s/%s?authSource=admin", username, password, p.mongoHost, dbName)
	slog.Info("nosql.Provision: provisioned",
		"token", token,
		"db", dbName,
		"user", username,
		"tier", tier,
	)

	return &Credentials{
		URL:          url,
		DatabaseName: dbName,
	}, nil
}

// StorageBytes returns the storage size in bytes used by db_{token}.
// Runs dbStats on the token database. Returns 0 on any error (fail-open).
func (p *Provider) StorageBytes(ctx context.Context, token string) (int64, error) {
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(p.adminURI).
		SetServerSelectionTimeout(connectTimeout))
	if err != nil {
		slog.Error("nosql.StorageBytes: connect", "token", token, "error", err)
		return 0, nil
	}
	defer func() {
		if discErr := mongoDisconnect(client, ctx); discErr != nil {
			slog.Error("nosql.StorageBytes: disconnect", "error", discErr)
		}
	}()

	dbName := "db_" + token
	var result bson.M
	err = client.Database(dbName).RunCommand(ctx, bson.D{{Key: "dbStats", Value: 1}}).Decode(&result)
	if err != nil {
		// Database may not exist yet — fail open.
		slog.Error("nosql.StorageBytes: dbStats failed", "token", token, "db", dbName, "error", err)
		return 0, nil
	}

	return storageSizeToInt64(result["storageSize"]), nil
}

// storageSizeToInt64 normalises the dbStats.storageSize field, which MongoDB
// returns as one of several numeric BSON types depending on magnitude and
// server version, into an int64. Unknown / nil types yield 0 (fail-open).
// Extracted as a free function so every type arm is unit-testable without
// depending on which numeric type a given mongod build happens to return.
func storageSizeToInt64(v any) int64 {
	switch n := v.(type) {
	case int32:
		return int64(n)
	case int64:
		return n
	case float64:
		return int64(n)
	default:
		return 0
	}
}

// Deprovision drops the user and database for the given token.
// Drops user first, then drops the database.
func (p *Provider) Deprovision(ctx context.Context, token string) error {
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(p.adminURI).
		SetServerSelectionTimeout(connectTimeout))
	if err != nil {
		return fmt.Errorf("nosql.Deprovision: connect: %w", err)
	}
	defer func() {
		if discErr := mongoDisconnect(client, ctx); discErr != nil {
			slog.Error("nosql.Deprovision: disconnect", "error", discErr)
		}
	}()

	dbName := "db_" + token
	username := "usr_" + token

	// Drop the user from the admin database.
	adminDB := client.Database("admin")
	dropUserResult := adminDB.RunCommand(ctx, bson.D{{Key: "dropUser", Value: username}})
	if dropUserResult.Err() != nil {
		slog.Error("nosql.Deprovision: dropUser failed (continuing)", "token", token, "error", dropUserResult.Err())
	}

	// Drop the database.
	if dropErr := client.Database(dbName).Drop(ctx); dropErr != nil {
		return fmt.Errorf("nosql.Deprovision: drop database %s: %w", dbName, dropErr)
	}

	slog.Info("nosql.Deprovision: deprovisioned", "token", token, "db", dbName, "user", username)
	return nil
}
