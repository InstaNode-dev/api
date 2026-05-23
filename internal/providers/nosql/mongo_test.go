package nosql_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	nosqlprovider "instant.dev/internal/providers/nosql"
)

// requireMongo skips the test if TEST_MONGO_URI is not set.
// Use this at the top of every test in this file.
func requireMongo(t *testing.T) string {
	t.Helper()
	uri := os.Getenv("TEST_MONGO_URI")
	if uri == "" {
		t.Skip("TEST_MONGO_URI not set — skipping MongoDB integration tests")
	}
	return uri
}

// mongoHost extracts host:port from a mongodb:// URI.
// For test purposes we just return "localhost:27017" by default.
func mongoHost(uri string) string {
	// Strip scheme and credentials to get host.
	// Simplified parser: mongodb://user:pass@host:port -> host:port
	after := strings.TrimPrefix(uri, "mongodb://")
	if idx := strings.Index(after, "@"); idx != -1 {
		after = after[idx+1:]
	}
	if idx := strings.Index(after, "/"); idx != -1 {
		after = after[:idx]
	}
	if after == "" {
		return "localhost:27017"
	}
	return after
}

// cleanupMongo removes the test user and database created during a test.
func cleanupMongo(t *testing.T, uri, token string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		t.Logf("cleanup: connect failed: %v", err)
		return
	}
	defer client.Disconnect(ctx)

	dbName := "db_" + token
	username := "usr_" + token

	// Drop user (ignore error — may not exist).
	client.Database("admin").RunCommand(ctx, bson.D{{Key: "dropUser", Value: username}})
	// Drop database (ignore error — may not exist).
	client.Database(dbName).Drop(ctx)
}

// TestMongoProvider_Provision_Success verifies that Provision connects, creates a
// user, and returns a non-empty connection URL.
func TestMongoProvider_Provision_Success(t *testing.T) {
	uri := requireMongo(t)
	host := mongoHost(uri)
	// Use a short safe token for MongoDB username limits.
	token := "provok123"
	defer cleanupMongo(t, uri, token)

	p := nosqlprovider.New(uri, host)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	creds, err := p.Provision(ctx, token, "anonymous")
	require.NoError(t, err)
	require.NotNil(t, creds)

	assert.NotEmpty(t, creds.URL, "URL must not be empty")
	assert.NotEmpty(t, creds.DatabaseName, "DatabaseName must not be empty")
	assert.True(t, strings.HasPrefix(creds.URL, "mongodb://"),
		"URL must start with mongodb://, got: %q", creds.URL)
}

// TestMongoProvider_Provision_URLFormat verifies that the provisioned URL contains
// the token in the username and database name fields.
func TestMongoProvider_Provision_URLFormat(t *testing.T) {
	uri := requireMongo(t)
	host := mongoHost(uri)
	token := "urlfmt456"
	defer cleanupMongo(t, uri, token)

	p := nosqlprovider.New(uri, host)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	creds, err := p.Provision(ctx, token, "anonymous")
	require.NoError(t, err)

	assert.Equal(t, "db_"+token, creds.DatabaseName,
		"DatabaseName must be db_{token}")
	assert.Contains(t, creds.URL, "usr_"+token,
		"URL must contain usr_{token} as the username")
	assert.Contains(t, creds.URL, "db_"+token,
		"URL must contain db_{token} as the database name")
	assert.Contains(t, creds.URL, host,
		"URL must contain the mongo host")
}

// TestMongoProvider_StorageBytes_ReturnsZeroOnMissingDB verifies that StorageBytes
// returns 0 (fail-open) when the database doesn't exist.
func TestMongoProvider_StorageBytes_ReturnsZeroOnMissingDB(t *testing.T) {
	uri := requireMongo(t)
	host := mongoHost(uri)

	p := nosqlprovider.New(uri, host)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Use a token that definitely doesn't have a provisioned DB.
	bytes, err := p.StorageBytes(ctx, "nonexistent-token-xyz789")
	// StorageBytes is fail-open: no error, returns 0.
	require.NoError(t, err)
	assert.Equal(t, int64(0), bytes,
		"StorageBytes must return 0 for a non-existent database (fail-open)")
}

// TestMongoProvider_Deprovision_DropsUserAndDB verifies that Deprovision removes
// both the user and the database.
func TestMongoProvider_Deprovision_DropsUserAndDB(t *testing.T) {
	uri := requireMongo(t)
	host := mongoHost(uri)
	token := "deprovtest789"

	p := nosqlprovider.New(uri, host)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Provision first.
	_, err := p.Provision(ctx, token, "anonymous")
	require.NoError(t, err, "Provision must succeed before Deprovision")

	// Deprovision.
	err = p.Deprovision(ctx, token)
	require.NoError(t, err, "Deprovision must not return an error")

	// Verify the database no longer lists in the admin DB.
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	require.NoError(t, err)
	defer client.Disconnect(ctx)

	databases, err := client.ListDatabaseNames(ctx, bson.D{})
	require.NoError(t, err)

	dbName := "db_" + token
	for _, db := range databases {
		assert.NotEqual(t, dbName, db, "database %q must not exist after Deprovision", dbName)
	}

	// Verify user no longer exists.
	var usersInfo bson.M
	result := client.Database("admin").RunCommand(ctx, bson.D{
		{Key: "usersInfo", Value: "usr_" + token},
	})
	require.NoError(t, result.Err())
	require.NoError(t, result.Decode(&usersInfo))

	users, _ := usersInfo["users"].(bson.A)
	assert.Len(t, users, 0, "user usr_%s must not exist after Deprovision", token)
}
