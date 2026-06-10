package nosql_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	nosqlprovider "instant.dev/internal/providers/nosql"
)

// requireMongoURI mirrors requireMongo but is named distinctly to avoid
// collisions with the black-box mongo_test.go in the same package.
func requireMongoURI(t *testing.T) string {
	t.Helper()
	uri := os.Getenv("TEST_MONGO_URI")
	if uri == "" {
		t.Skip("TEST_MONGO_URI not set — skipping MongoDB tests")
	}
	return uri
}

func hostFromURI(uri string) string {
	after := strings.TrimPrefix(uri, "mongodb://")
	if i := strings.Index(after, "@"); i != -1 {
		after = after[i+1:]
	}
	if i := strings.Index(after, "/"); i != -1 {
		after = after[:i]
	}
	if after == "" {
		return "localhost:27017"
	}
	return after
}

func dropMongo(t *testing.T, uri, token string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return
	}
	defer client.Disconnect(ctx)
	client.Database("admin").RunCommand(ctx, bson.D{{Key: "dropUser", Value: "usr_" + token}})
	client.Database("db_" + token).Drop(ctx)
}

// TestNew_Defaults covers the empty-arg default branches.
func TestNew_Defaults(t *testing.T) {
	p := nosqlprovider.New("", "", "")
	// We can't read unexported fields, but Provision against the default URI
	// (root:root@localhost:27017) is exercised elsewhere; here we simply assert
	// the constructor returns a usable, non-nil provider.
	if p == nil {
		t.Fatal("New must return a provider")
	}
	p2 := nosqlprovider.New("mongodb://x@h:1", "h:1", "")
	if p2 == nil {
		t.Fatal("New must return a provider for explicit args")
	}
}

// TestProvision_DuplicateUser covers the createUser error branch: provisioning
// the same token twice fails on the second createUser.
func TestProvision_DuplicateUser(t *testing.T) {
	uri := requireMongoURI(t)
	host := hostFromURI(uri)
	token := "dupuser01"
	defer dropMongo(t, uri, token)

	p := nosqlprovider.New(uri, host, "")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if _, err := p.Provision(ctx, token, "anonymous"); err != nil {
		t.Fatalf("first Provision: %v", err)
	}
	_, err := p.Provision(ctx, token, "anonymous")
	if err == nil || !strings.Contains(err.Error(), "createUser") {
		t.Fatalf("duplicate Provision must fail on createUser; got %v", err)
	}
}

// TestStorageBytes_PositiveAfterWrite covers the dbStats success path and the
// storageSize type-switch (the value comes back as a numeric BSON type).
func TestStorageBytes_PositiveAfterWrite(t *testing.T) {
	uri := requireMongoURI(t)
	host := hostFromURI(uri)
	token := "storagesz01"
	defer dropMongo(t, uri, token)

	p := nosqlprovider.New(uri, host, "")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if _, err := p.Provision(ctx, token, "anonymous"); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	// Write enough data that dbStats.storageSize is non-zero.
	client, _ := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	defer client.Disconnect(ctx)
	docs := make([]interface{}, 0, 500)
	for i := 0; i < 500; i++ {
		docs = append(docs, bson.D{{Key: "i", Value: i}, {Key: "pad", Value: strings.Repeat("x", 256)}})
	}
	if _, err := client.Database("db_"+token).Collection("data").InsertMany(ctx, docs); err != nil {
		t.Fatalf("seed data: %v", err)
	}

	bytes, err := p.StorageBytes(ctx, token)
	if err != nil {
		t.Fatalf("StorageBytes: %v", err)
	}
	if bytes <= 0 {
		t.Fatalf("storageSize must be > 0 after writes; got %d", bytes)
	}
}

// TestDeprovision_DropUserFailsNonFatal covers the dropUser non-fatal log
// branch: the user does not exist (only the database does) so dropUser errors
// but Deprovision still drops the database and returns nil.
func TestDeprovision_DropUserFailsNonFatal(t *testing.T) {
	uri := requireMongoURI(t)
	host := hostFromURI(uri)
	token := "nouser01"
	defer dropMongo(t, uri, token)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Create only the database (no user) by inserting a doc directly.
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := client.Database("db_"+token).Collection("c").InsertOne(ctx, bson.D{{Key: "x", Value: 1}}); err != nil {
		t.Fatalf("seed db: %v", err)
	}
	client.Disconnect(ctx)

	p := nosqlprovider.New(uri, host, "")
	if err := p.Deprovision(ctx, token); err != nil {
		t.Fatalf("Deprovision must succeed even when dropUser fails: %v", err)
	}
}

// TestDeprovision_DBSafetyRefusesProductionHost asserts the dbsafety guard
// fires BEFORE any mongo connection: a non-dev admin host (truehomie pattern —
// PROVISIONER_ADDR unset against a managed/public Mongo) makes Deprovision
// return a refusal, NOT a connect error, with no DROP attempted. Deterministic
// and needs no live mongod.
func TestDeprovision_DBSafetyRefusesProductionHost(t *testing.T) {
	p := nosqlprovider.New("mongodb://root:root@mongo.instanode.dev:27017", "mongo.instanode.dev:27017", "production")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := p.Deprovision(ctx, "tok")
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("Deprovision against a non-dev Mongo host must be refused; got %v", err)
	}
	// It must be a guard refusal, not a connect attempt.
	if strings.Contains(err.Error(), "connect") {
		t.Fatalf("guard must refuse before connecting; got connect error: %v", err)
	}
}

// TestDeprovision_DBSafetyRefusesBadName asserts the name guard fires for a
// malformed token even against a dev host (the token would yield a db name
// outside the per-tenant convention). Deterministic, no live mongod.
func TestDeprovision_DBSafetyRefusesBadName(t *testing.T) {
	p := nosqlprovider.New("mongodb://root:root@localhost:27017", "localhost:27017", "development")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// A token with a space makes db_<token> fail validTokenChars → refusal.
	err := p.Deprovision(ctx, "bad token")
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("malformed token must be refused; got %v", err)
	}
}

// TestConnectErrorBranches covers the mongo.Connect error returns in Provision,
// StorageBytes (fail-open → 0,nil) and Deprovision, using a syntactically
// invalid URI that fails at ApplyURI/Connect time.
func TestConnectErrorBranches(t *testing.T) {
	p := nosqlprovider.New("not-a-valid-uri", "h:1", "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := p.Provision(ctx, "tok", "anonymous"); err == nil || !strings.Contains(err.Error(), "connect") {
		t.Fatalf("Provision connect error expected; got %v", err)
	}
	// StorageBytes is fail-open: connect error returns (0, nil).
	if n, err := p.StorageBytes(ctx, "tok"); err != nil || n != 0 {
		t.Fatalf("StorageBytes connect error must fail open; got (%d,%v)", n, err)
	}
	if err := p.Deprovision(ctx, "tok"); err == nil || !strings.Contains(err.Error(), "connect") {
		t.Fatalf("Deprovision connect error expected; got %v", err)
	}
}

// TestProvision_InitInsertNonFatal covers the non-fatal init-insert log branch:
// the sentinel insert fails (here because the database name derived from the
// token is invalid for MongoDB) but createUser already succeeded so Provision
// still returns credentials.
func TestProvision_InitInsertNonFatal(t *testing.T) {
	uri := requireMongoURI(t)
	host := hostFromURI(uri)
	// A token with a '$' makes db_<token> an invalid MongoDB database name, so
	// the sentinel InsertOne fails — exercising the non-fatal branch. createUser
	// accepts the username (different validation), so it succeeds first.
	token := "init$bad"
	defer dropMongo(t, uri, token)

	p := nosqlprovider.New(uri, host, "")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	creds, err := p.Provision(ctx, token, "anonymous")
	if err != nil {
		// If createUser itself rejects the name, that's a different (also valid)
		// error path; only fail if neither path was exercised cleanly.
		if !strings.Contains(err.Error(), "createUser") {
			t.Fatalf("unexpected Provision error: %v", err)
		}
		return
	}
	if creds.DatabaseName != "db_"+token {
		t.Fatalf("DatabaseName = %q", creds.DatabaseName)
	}
}

// TestStorageBytes_MissingDB_FailOpen covers the dbStats fail-open path for a
// database that doesn't exist — returns (0, nil).
func TestStorageBytes_MissingDB_FailOpen(t *testing.T) {
	uri := requireMongoURI(t)
	host := hostFromURI(uri)
	p := nosqlprovider.New(uri, host, "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bytes, err := p.StorageBytes(ctx, "ghost-db-never-made")
	if err != nil || bytes != 0 {
		t.Fatalf("missing-db StorageBytes = (%d,%v); want (0,nil)", bytes, err)
	}
}

// TestStorageBytes_DBStatsError covers the dbStats RunCommand error branch
// (valid connection, but the derived database name is invalid for MongoDB so
// the dbStats command itself fails) — StorageBytes fails open with (0, nil).
func TestStorageBytes_DBStatsError(t *testing.T) {
	uri := requireMongoURI(t)
	host := hostFromURI(uri)
	p := nosqlprovider.New(uri, host, "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// '$' yields an invalid MongoDB database name; the connection succeeds but
	// the dbStats command errors.
	bytes, err := p.StorageBytes(ctx, "bad$name")
	if err != nil || bytes != 0 {
		t.Fatalf("dbStats error must fail open; got (%d,%v)", bytes, err)
	}
}
